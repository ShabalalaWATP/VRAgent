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
    """Generate AI analysis of traceroute results with network inference."""
    try:
        from google import genai
        
        if not settings.gemini_api_key:
            return {"error": "Gemini API key not configured"}
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build detailed context with hostname patterns for network inference
        hops_summary = []
        hostname_patterns = []
        ip_ranges = []
        
        for hop in result.hops:
            hop_info = f"Hop {hop.hop_number}: "
            if hop.is_timeout:
                hop_info += "* (timeout)"
            else:
                hop_info += f"{hop.ip_address or 'unknown'}"
                if hop.hostname:
                    hop_info += f" ({hop.hostname})"
                    hostname_patterns.append(hop.hostname)
                if hop.avg_rtt_ms:
                    hop_info += f" - {hop.avg_rtt_ms:.2f}ms"
                if hop.packet_loss > 0:
                    hop_info += f" [{hop.packet_loss:.0f}% loss]"
                if hop.ip_address:
                    ip_ranges.append(hop.ip_address)
            hops_summary.append(hop_info)
        
        # Calculate latency statistics
        rtts = [h.avg_rtt_ms for h in result.hops if h.avg_rtt_ms]
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0
        max_rtt = max(rtts) if rtts else 0
        timeout_count = sum(1 for h in result.hops if h.is_timeout)
        loss_count = sum(1 for h in result.hops if h.packet_loss > 0)
        
        prompt = f"""You are a network security analyst. Analyze this traceroute result and provide a comprehensive security and performance assessment.

## TRACEROUTE DATA
Target: {result.target} ({result.target_ip or 'IP not resolved'})
Total Hops: {result.total_hops}
Completed: {result.completed}
Duration: {result.duration_ms:.0f}ms

## STATISTICS
- Average RTT: {avg_rtt:.1f}ms
- Max RTT: {max_rtt:.1f}ms
- Timeout Hops: {timeout_count}
- Packet Loss Hops: {loss_count}

## NETWORK PATH
{chr(10).join(hops_summary)}

## HOSTNAME PATTERNS (for ISP/Network inference)
{chr(10).join(hostname_patterns) if hostname_patterns else 'No hostnames resolved'}

## ANALYSIS REQUIREMENTS

1. **Network Inference**: Analyze hostnames to identify:
   - ISP names (look for patterns like "comcast", "att", "level3", "cogent", "ntt", etc.)
   - Geographic locations (city codes like "nyc", "lax", "ams", "fra", etc.)
   - Network types (backbone, edge, CDN, cloud provider)
   - Autonomous System patterns from naming conventions

2. **Security Assessment**: Identify:
   - Filtering/firewall presence (consecutive timeouts)
   - Suspicious routing (unexpected geographic hops)
   - Network segmentation issues
   - ICMP rate limiting indicators
   - Potential MITM positions

3. **Performance Analysis**: Evaluate:
   - Latency spikes and bottlenecks
   - Packet loss patterns
   - Geographic latency (estimate based on typical intercontinental delays)
   - Congestion indicators

4. **Attack Surface**: Consider:
   - Exposed infrastructure (routers with hostnames)
   - Potential pivot points
   - Network boundaries crossed

Provide analysis in this JSON format:
{{
    "summary": "2-3 sentence overview of the network path and key findings",
    "network_inference": {{
        "identified_isps": ["ISP names inferred from hostnames"],
        "geographic_path": ["List of geographic locations traversed"],
        "network_types": ["backbone", "edge", "cdn", etc.],
        "estimated_asns": ["ASN patterns identified from naming"],
        "cloud_providers": ["Any cloud infrastructure detected"]
    }},
    "network_segments": [
        {{
            "segment": "Local/ISP/Transit/Backbone/Destination",
            "hops": "1-3",
            "description": "Description of this network segment",
            "inferred_owner": "Likely network owner based on hostnames",
            "geographic_region": "Estimated region"
        }}
    ],
    "performance_analysis": {{
        "overall_latency": "Assessment (excellent/good/acceptable/poor/critical)",
        "latency_grade": "A/B/C/D/F",
        "bottlenecks": [
            {{
                "hop": 5,
                "ip": "x.x.x.x",
                "issue": "High latency description",
                "likely_cause": "Congestion/distance/processing"
            }}
        ],
        "packet_loss_concerns": [
            {{
                "hop": 7,
                "loss_percent": 30,
                "impact": "Description of impact"
            }}
        ],
        "jitter_assessment": "Based on RTT variance"
    }},
    "security_observations": [
        {{
            "observation": "Security-relevant finding",
            "severity": "info/low/medium/high/critical",
            "details": "Detailed explanation",
            "attack_relevance": "How this could be exploited",
            "recommendation": "Mitigation if applicable"
        }}
    ],
    "attack_surface_analysis": {{
        "exposed_infrastructure": ["List of identified network devices"],
        "potential_pivot_points": ["Hops that could be targeted"],
        "filtering_detected": true/false,
        "filtering_locations": ["Hop numbers where filtering detected"],
        "network_boundaries": ["Points where network ownership changes"]
    }},
    "recommendations": [
        {{
            "priority": "high/medium/low",
            "recommendation": "Specific actionable recommendation",
            "rationale": "Why this matters"
        }}
    ],
    "risk_score": 0-100,
    "risk_justification": "Explanation of risk score"
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
                summary_data={
                    "total_findings": len(ai_analysis.get("security_observations", [])) if isinstance(ai_analysis, dict) else 0,
                    "summary": ai_analysis.get("summary", "") if isinstance(ai_analysis, dict) else ""
                },
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
                        summary_data={
                            "total_findings": len(ai_analysis.get("security_observations", [])) if isinstance(ai_analysis, dict) else 0,
                            "summary": ai_analysis.get("summary", "") if isinstance(ai_analysis, dict) else ""
                        },
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
                "total_findings": r.summary_data.get("total_findings", 0) if r.summary_data else 0,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "summary": r.summary_data.get("summary", "") if r.summary_data else ""
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
            "total_findings": report.summary_data.get("total_findings", 0) if report.summary_data else 0,
            "summary": report.summary_data.get("summary", "") if report.summary_data else "",
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


@router.get("/history/{target}")
async def get_traceroute_history(target: str, limit: int = 10):
    """Get historical traceroutes to a target for comparison."""
    try:
        from sqlalchemy import or_
        db = next(get_db())
        
        # Find all traceroutes to this target
        reports = db.query(NetworkAnalysisReport).filter(
            or_(
                NetworkAnalysisReport.analysis_type == "traceroute",
                NetworkAnalysisReport.report_type == "traceroute"
            ),
            NetworkAnalysisReport.filename == target
        ).order_by(NetworkAnalysisReport.created_at.desc()).limit(limit).all()
        
        history = []
        for r in reports:
            report_data = r.report_data or {}
            result = report_data.get("result", {})
            
            history.append({
                "id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "total_hops": result.get("total_hops", 0),
                "completed": result.get("completed", False),
                "duration_ms": result.get("duration_ms", 0),
                "path_ips": [h.get("ip_address") for h in result.get("hops", []) if h.get("ip_address")],
                "risk_score": r.risk_score,
            })
        
        return {"target": target, "history": history, "count": len(history)}
    except Exception as e:
        logger.error(f"Failed to get history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compare")
async def compare_traceroutes(request: dict):
    """Compare two or more traceroute reports and analyze differences."""
    try:
        from google import genai
        
        report_ids = request.get("report_ids", [])
        if len(report_ids) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 reports to compare")
        
        db = next(get_db())
        reports = []
        
        for rid in report_ids:
            report = db.query(NetworkAnalysisReport).filter(
                NetworkAnalysisReport.id == rid
            ).first()
            if report:
                reports.append(report)
        
        if len(reports) < 2:
            raise HTTPException(status_code=404, detail="Could not find enough reports")
        
        # Extract paths for comparison
        traces = []
        for r in reports:
            report_data = r.report_data or {}
            result = report_data.get("result", {})
            traces.append({
                "id": r.id,
                "timestamp": r.created_at.isoformat() if r.created_at else "Unknown",
                "target": result.get("target"),
                "hops": result.get("hops", []),
                "total_hops": result.get("total_hops", 0),
                "completed": result.get("completed", False),
            })
        
        # Compare paths
        comparison = {
            "traces_compared": len(traces),
            "path_changes": [],
            "latency_changes": [],
            "routing_stable": True,
        }
        
        # Compare hop paths
        base_path = [h.get("ip_address") for h in traces[0]["hops"]]
        for i, trace in enumerate(traces[1:], 2):
            trace_path = [h.get("ip_address") for h in trace["hops"]]
            
            if base_path != trace_path:
                comparison["routing_stable"] = False
                # Find differences
                differences = []
                for hop_num, (base_ip, trace_ip) in enumerate(zip(base_path, trace_path), 1):
                    if base_ip != trace_ip:
                        differences.append({
                            "hop": hop_num,
                            "trace_1": base_ip,
                            f"trace_{i}": trace_ip
                        })
                
                comparison["path_changes"].append({
                    "between": [1, i],
                    "differences": differences
                })
        
        # Use AI to analyze the comparison if available
        if settings.gemini_api_key:
            client = genai.Client(api_key=settings.gemini_api_key)
            
            traces_summary = ""
            for t in traces:
                hops_str = " -> ".join([h.get("ip_address", "*") for h in t["hops"][:15]])
                traces_summary += f"\nTrace {t['id']} ({t['timestamp']}): {hops_str}"
            
            prompt = f"""Compare these traceroute results and analyze routing changes:
{traces_summary}

Path differences detected: {json.dumps(comparison['path_changes'], indent=2)}
Routing stable: {comparison['routing_stable']}

Provide analysis in JSON format:
{{
    "summary": "Overview of routing comparison",
    "routing_stability": "stable/changed/fluctuating",
    "change_analysis": [
        {{
            "change": "Description of routing change",
            "significance": "high/medium/low",
            "possible_cause": "Why this might have changed",
            "security_implication": "Any security concerns"
        }}
    ],
    "recommendations": ["List of recommendations"],
    "risk_assessment": "Overall risk of routing changes"
}}"""
            
            response = client.models.generate_content(
                model=settings.gemini_model_id,
                contents=prompt
            )
            
            json_match = re.search(r'\{[\s\S]*\}', response.text)
            if json_match:
                comparison["ai_analysis"] = json.loads(json_match.group())
        
        return comparison
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Comparison error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/multi-trace")
async def run_multi_trace(request: dict, current_user: User = Depends(get_current_active_user)):
    """Run multiple traceroutes to detect routing variance."""
    target = request.get("target")
    count = min(request.get("count", 3), 5)  # Max 5 traces
    delay_seconds = request.get("delay_seconds", 2)
    
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Validate target
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Could not resolve target: {target}")
    
    results = []
    for i in range(count):
        req = TracerouteRequest(
            target=target,
            max_hops=30,
            timeout=5,
            queries=3,
            use_icmp=True,
            resolve_hostnames=True,
            save_report=False
        )
        
        result = await run_traceroute(req)
        results.append({
            "trace_number": i + 1,
            "hops": [h.model_dump() for h in result.hops],
            "total_hops": result.total_hops,
            "completed": result.completed,
            "duration_ms": result.duration_ms,
            "path_ips": [h.ip_address for h in result.hops if h.ip_address]
        })
        
        if i < count - 1:
            await asyncio.sleep(delay_seconds)
    
    # Analyze variance
    all_paths = [r["path_ips"] for r in results]
    unique_paths = len(set(tuple(p) for p in all_paths))
    
    # Calculate consistency
    path_lengths = [len(p) for p in all_paths]
    avg_length = sum(path_lengths) / len(path_lengths) if path_lengths else 0
    
    variance_analysis = {
        "target": target,
        "traces_run": count,
        "unique_paths": unique_paths,
        "load_balancing_detected": unique_paths > 1,
        "average_path_length": avg_length,
        "path_length_variance": max(path_lengths) - min(path_lengths) if path_lengths else 0,
    }
    
    # Use AI to analyze variance if available
    if settings.gemini_api_key and unique_paths > 1:
        try:
            from google import genai
            client = genai.Client(api_key=settings.gemini_api_key)
            
            paths_str = "\n".join([f"Path {i+1}: {' -> '.join(p[:15])}" for i, p in enumerate(all_paths)])
            
            prompt = f"""Analyze these multiple traceroute paths to the same target:

Target: {target}
{paths_str}

Unique paths detected: {unique_paths}

Analyze in JSON format:
{{
    "summary": "Overview of routing behavior",
    "load_balancing_type": "ECMP/Per-flow/None detected",
    "divergence_points": ["Hops where paths diverge"],
    "convergence_points": ["Hops where paths converge"],
    "stability_assessment": "stable/moderate variance/unstable",
    "security_implications": ["Any security concerns from routing variance"],
    "recommendations": ["Recommendations based on findings"]
}}"""
            
            response = client.models.generate_content(
                model=settings.gemini_model_id,
                contents=prompt
            )
            
            json_match = re.search(r'\{[\s\S]*\}', response.text)
            if json_match:
                variance_analysis["ai_analysis"] = json.loads(json_match.group())
        except Exception as e:
            logger.error(f"AI variance analysis error: {e}")
    
    return {
        "results": results,
        "analysis": variance_analysis
    }


# ============================================================================
# Batch Traceroute
# ============================================================================

class BatchTracerouteRequest(BaseModel):
    """Request to run traceroutes to multiple targets."""
    targets: List[str] = Field(..., description="List of target hostnames or IPs", min_length=1, max_length=10)
    max_hops: int = Field(default=30, ge=1, le=64)
    timeout: int = Field(default=5, ge=1, le=15)
    queries: int = Field(default=3, ge=1, le=5)
    use_icmp: bool = Field(default=True)
    resolve_hostnames: bool = Field(default=True)
    save_reports: bool = Field(default=True)
    project_id: Optional[int] = Field(default=None)


@router.post("/batch")
async def run_batch_traceroute(request: BatchTracerouteRequest, current_user: User = Depends(get_current_active_user)):
    """Run traceroutes to multiple targets in parallel."""
    # Validate all targets first
    valid_targets = []
    validation_errors = []
    
    for target in request.targets:
        target = target.strip()
        if not target:
            continue
        try:
            socket.gethostbyname(target)
            valid_targets.append(target)
        except socket.gaierror:
            validation_errors.append({"target": target, "error": "Could not resolve hostname"})
    
    if not valid_targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")
    
    # Check traceroute availability
    if not get_traceroute_command():
        raise HTTPException(status_code=503, detail="Traceroute is not installed on this system")
    
    # Run traceroutes in parallel (limit concurrency to 3)
    semaphore = asyncio.Semaphore(3)
    
    async def trace_with_semaphore(target: str):
        async with semaphore:
            try:
                req = TracerouteRequest(
                    target=target,
                    max_hops=request.max_hops,
                    timeout=request.timeout,
                    queries=request.queries,
                    use_icmp=request.use_icmp,
                    resolve_hostnames=request.resolve_hostnames,
                    save_report=False  # We'll save after collecting all results
                )
                
                result = await run_traceroute(req)
                ai_analysis = await generate_ai_analysis(result)
                
                return {
                    "target": target,
                    "success": True,
                    "result": result.model_dump(),
                    "ai_analysis": ai_analysis,
                }
            except Exception as e:
                logger.error(f"Batch traceroute error for {target}: {e}")
                return {
                    "target": target,
                    "success": False,
                    "error": str(e),
                }
    
    # Execute all traces in parallel (return_exceptions=True prevents single failure from crashing batch)
    tasks = [trace_with_semaphore(target) for target in valid_targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Handle any exceptions that were returned
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Batch traceroute exception for target {valid_targets[i]}: {result}")
            processed_results.append({
                "target": valid_targets[i],
                "success": False,
                "error": str(result),
            })
        else:
            processed_results.append(result)
    results = processed_results
    
    # Analyze results together
    successful_results = [r for r in results if r.get("success")]
    failed_results = [r for r in results if not r.get("success")]
    
    # Build combined topology data
    combined_topology = {"nodes": [], "links": []}
    all_ips = set()
    
    # Add source node
    combined_topology["nodes"].append({
        "id": "source",
        "ip": "Your Computer",
        "type": "host",
        "hostname": "localhost",
        "riskLevel": "none",
    })
    
    for trace_result in successful_results:
        target = trace_result["target"]
        hops = trace_result["result"].get("hops", [])
        
        for i, hop in enumerate(hops):
            node_id = hop.get("ip_address") or f"unknown-{target}-{hop.get('hop_number')}"
            
            # Avoid duplicate nodes
            if node_id not in all_ips:
                all_ips.add(node_id)
                
                # Determine risk level from latency/loss
                risk_level = "none"
                if hop.get("packet_loss", 0) > 50:
                    risk_level = "critical"
                elif hop.get("packet_loss", 0) > 20 or (hop.get("avg_rtt_ms") and hop["avg_rtt_ms"] > 300):
                    risk_level = "high"
                elif hop.get("packet_loss", 0) > 5 or (hop.get("avg_rtt_ms") and hop["avg_rtt_ms"] > 150):
                    risk_level = "medium"
                elif hop.get("avg_rtt_ms") and hop["avg_rtt_ms"] > 50:
                    risk_level = "low"
                
                combined_topology["nodes"].append({
                    "id": node_id,
                    "ip": hop.get("ip_address") or f"Hop {hop.get('hop_number')} (timeout)",
                    "type": "server" if hop.get("is_destination") else "router" if not hop.get("is_timeout") else "unknown",
                    "hostname": hop.get("hostname"),
                    "riskLevel": risk_level,
                    "targets": [target],  # Track which targets pass through this node
                })
            else:
                # Update existing node to track multiple targets
                for node in combined_topology["nodes"]:
                    if node["id"] == node_id and "targets" in node:
                        if target not in node["targets"]:
                            node["targets"].append(target)
            
            # Add link
            source_id = "source" if i == 0 else (hops[i-1].get("ip_address") or f"unknown-{target}-{hops[i-1].get('hop_number')}")
            link_id = f"{source_id}->{node_id}"
            
            combined_topology["links"].append({
                "source": source_id,
                "target": node_id,
                "protocol": "ICMP",
                "packets": 3,
                "targetHost": target,  # Track which trace this link belongs to
            })
    
    # Generate comparative AI analysis if multiple successful traces
    comparative_analysis = None
    if len(successful_results) > 1 and settings.gemini_api_key:
        try:
            from google import genai
            client = genai.Client(api_key=settings.gemini_api_key)
            
            traces_summary = []
            for r in successful_results:
                target = r["target"]
                hops = r["result"].get("hops", [])
                path_str = " -> ".join([h.get("ip_address", "*") for h in hops[:12]])
                total_hops = len(hops)
                completed = r["result"].get("completed", False)
                avg_rtt = sum(h.get("avg_rtt_ms", 0) for h in hops if h.get("avg_rtt_ms")) / max(1, len([h for h in hops if h.get("avg_rtt_ms")]))
                traces_summary.append(f"- {target}: {total_hops} hops, {'completed' if completed else 'incomplete'}, avg RTT {avg_rtt:.1f}ms\n  Path: {path_str}")
            
            prompt = f"""Analyze these traceroutes to multiple destinations and provide comparative insights:

## TRACES
{chr(10).join(traces_summary)}

## ANALYSIS REQUIREMENTS
Analyze the routing patterns across these destinations:
1. **Shared Infrastructure**: Identify common network segments (ISPs, transit providers)
2. **Geographic Distribution**: Infer geographic spread of destinations
3. **Performance Comparison**: Compare latency and hop counts
4. **Network Dependencies**: Identify critical shared hops
5. **Security Observations**: Any security-relevant patterns

Respond in JSON format:
{{
    "summary": "Overview of the batch traceroute analysis",
    "shared_infrastructure": {{
        "common_hops": ["IPs/hostnames that appear in multiple traces"],
        "shared_isps": ["ISPs identified across traces"],
        "convergence_analysis": "Where paths share infrastructure"
    }},
    "performance_comparison": {{
        "fastest_target": "Target with lowest latency",
        "slowest_target": "Target with highest latency",
        "hop_count_analysis": "Analysis of path lengths"
    }},
    "geographic_analysis": {{
        "regions_covered": ["Geographic regions inferred"],
        "routing_patterns": "Geographic routing observations"
    }},
    "security_observations": [
        {{
            "observation": "Security finding",
            "affected_targets": ["Which targets this affects"],
            "severity": "info/low/medium/high"
        }}
    ],
    "recommendations": ["Recommendations based on comparative analysis"]
}}"""
            
            response = client.models.generate_content(
                model=settings.gemini_model_id,
                contents=prompt
            )
            
            json_match = re.search(r'\{[\s\S]*\}', response.text)
            if json_match:
                comparative_analysis = json.loads(json_match.group())
        except Exception as e:
            logger.error(f"Batch AI analysis error: {e}")
    
    # Save reports if requested
    saved_report_ids = []
    if request.save_reports:
        try:
            db = next(get_db())
            for trace_result in successful_results:
                report = NetworkAnalysisReport(
                    title=f"Batch Traceroute to {trace_result['target']}",
                    analysis_type="traceroute",
                    report_type="traceroute",
                    filename=trace_result["target"],
                    risk_score=trace_result.get("ai_analysis", {}).get("risk_score", 0) if isinstance(trace_result.get("ai_analysis"), dict) else 0,
                    summary_data={
                        "total_findings": len(trace_result.get("ai_analysis", {}).get("security_observations", [])) if isinstance(trace_result.get("ai_analysis"), dict) else 0,
                        "summary": trace_result.get("ai_analysis", {}).get("summary", "") if isinstance(trace_result.get("ai_analysis"), dict) else ""
                    },
                    report_data={
                        "result": trace_result["result"],
                        "ai_analysis": trace_result.get("ai_analysis"),
                        "batch_mode": True,
                    },
                    ai_report=trace_result.get("ai_analysis"),
                    project_id=request.project_id,
                )
                db.add(report)
                db.commit()
                db.refresh(report)
                saved_report_ids.append({"target": trace_result["target"], "report_id": report.id})
        except Exception as e:
            logger.error(f"Failed to save batch reports: {e}")
    
    return {
        "targets_requested": len(request.targets),
        "targets_traced": len(valid_targets),
        "successful": len(successful_results),
        "failed": len(failed_results),
        "results": results,
        "validation_errors": validation_errors,
        "combined_topology": combined_topology,
        "comparative_analysis": comparative_analysis,
        "saved_reports": saved_report_ids if request.save_reports else None,
    }