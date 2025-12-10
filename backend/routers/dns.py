"""
DNS Reconnaissance API Router

Endpoints for DNS enumeration, subdomain discovery, and security analysis.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict
from datetime import datetime
import logging
import json
import asyncio
from sqlalchemy import or_

from ..services.dns_service import (
    run_dns_recon,
    get_scan_types,
    get_dns_status,
    validate_domain,
    DNSReconResult,
    run_whois_domain,
    run_whois_ip,
    is_whois_available,
)
from ..core.database import get_db
from ..models.models import NetworkAnalysisReport

logger = logging.getLogger("vragent.backend.routers.dns")
router = APIRouter(prefix="/dns", tags=["DNS Reconnaissance"])


# ============================================================================
# Request/Response Models
# ============================================================================

class DNSScanRequest(BaseModel):
    """Request to run DNS reconnaissance."""
    domain: str = Field(..., description="Target domain to scan")
    scan_type: str = Field(default="standard", description="Type of scan: quick, standard, thorough, subdomain_focus, security_focus")
    custom_subdomains: Optional[List[str]] = Field(default=None, description="Custom subdomains to check")
    save_report: bool = Field(default=True, description="Save report to database")
    report_title: Optional[str] = Field(default=None, description="Custom title for saved report")
    run_ai_analysis: bool = Field(default=True, description="Run AI analysis on results")


class DNSValidateRequest(BaseModel):
    """Request to validate a domain."""
    domain: str


class DNSValidateResponse(BaseModel):
    """Response for domain validation."""
    valid: bool
    domain: Optional[str] = None
    error: Optional[str] = None


class DNSStatusResponse(BaseModel):
    """Status of DNS service."""
    available: bool
    dnspython_installed: bool
    message: str
    features: Dict[str, bool]


class DNSScanTypeResponse(BaseModel):
    """Available DNS scan types."""
    id: str
    name: str
    description: str
    record_types: List[str]
    subdomain_count: int
    check_security: bool
    zone_transfer: bool
    timeout: int
    estimated_time: str


class DNSRecordResponse(BaseModel):
    """A DNS record."""
    record_type: str
    name: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None


class SubdomainResponse(BaseModel):
    """Subdomain enumeration result."""
    subdomain: str
    full_domain: str
    ip_addresses: List[str]
    cname: Optional[str] = None
    status: str


class SecurityAnalysisResponse(BaseModel):
    """DNS security analysis."""
    has_spf: bool
    spf_record: Optional[str] = None
    spf_issues: List[str]
    has_dmarc: bool
    dmarc_record: Optional[str] = None
    dmarc_issues: List[str]
    has_dkim: bool
    dkim_selectors_found: List[str]
    has_dnssec: bool
    dnssec_details: Optional[str] = None
    has_caa: bool
    caa_records: List[str]
    mail_security_score: int
    overall_issues: List[str]
    recommendations: List[str]


class DNSReconResponse(BaseModel):
    """Complete DNS reconnaissance result."""
    domain: str
    scan_timestamp: str
    scan_duration_seconds: float
    records: List[DNSRecordResponse]
    nameservers: List[str]
    mail_servers: List[Dict[str, Any]]
    subdomains: List[SubdomainResponse]
    zone_transfer_possible: bool
    zone_transfer_data: List[str]
    security: Optional[SecurityAnalysisResponse] = None
    reverse_dns: Dict[str, str]
    total_records: int
    total_subdomains: int
    unique_ips: List[str]
    ai_analysis: Optional[Any] = None
    report_id: Optional[int] = None


class DNSChatRequest(BaseModel):
    """Request for AI chat about DNS results."""
    message: str
    dns_context: Dict[str, Any]
    conversation_history: Optional[List[Dict[str, str]]] = None


class DNSChatResponse(BaseModel):
    """Response from AI chat."""
    response: str
    suggestions: List[str] = []


class SavedDNSReport(BaseModel):
    """Summary of a saved DNS report."""
    id: int
    domain: str
    scan_type: str
    title: Optional[str]
    total_records: int
    total_subdomains: int
    zone_transfer_possible: bool
    mail_security_score: Optional[int]
    created_at: str


class SavedDNSReportList(BaseModel):
    """List of saved DNS reports."""
    reports: List[SavedDNSReport]
    total: int


# WHOIS Models
class WhoisDomainRequest(BaseModel):
    """Request for domain WHOIS lookup."""
    domain: str = Field(..., description="Domain name to lookup")


class WhoisIPRequest(BaseModel):
    """Request for IP WHOIS lookup."""
    ip_address: str = Field(..., description="IP address to lookup")


class WhoisDomainResponse(BaseModel):
    """WHOIS lookup result for a domain."""
    domain: str
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = []
    status: List[str] = []
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_email: Optional[str] = None
    admin_email: Optional[str] = None
    tech_email: Optional[str] = None
    dnssec: Optional[str] = None
    raw_text: str = ""
    error: Optional[str] = None


class WhoisIPResponse(BaseModel):
    """WHOIS lookup result for an IP address."""
    ip_address: str
    network_name: Optional[str] = None
    network_range: Optional[str] = None
    cidr: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    registrar: Optional[str] = None  # RIR (ARIN, RIPE, etc.)
    registration_date: Optional[str] = None
    updated_date: Optional[str] = None
    abuse_contact: Optional[str] = None
    tech_contact: Optional[str] = None
    description: List[str] = []
    raw_text: str = ""
    error: Optional[str] = None


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/status", response_model=DNSStatusResponse)
async def dns_status():
    """Get DNS service status and capabilities."""
    return get_dns_status()


@router.get("/scan-types", response_model=List[DNSScanTypeResponse])
async def list_scan_types():
    """Get available DNS scan types."""
    return get_scan_types()


@router.post("/validate", response_model=DNSValidateResponse)
async def validate_domain_endpoint(request: DNSValidateRequest):
    """Validate a domain name."""
    is_valid, result = validate_domain(request.domain)
    if is_valid:
        return DNSValidateResponse(valid=True, domain=result)
    else:
        return DNSValidateResponse(valid=False, error=result)


@router.post("/scan", response_model=DNSReconResponse)
async def run_dns_scan(request: DNSScanRequest):
    """
    Run DNS reconnaissance on a domain.
    
    Performs DNS enumeration including:
    - DNS record lookups (A, AAAA, MX, NS, TXT, etc.)
    - Subdomain enumeration
    - Zone transfer attempts
    - Security analysis (SPF, DMARC, DKIM, DNSSEC)
    """
    # Validate domain
    is_valid, result = validate_domain(request.domain)
    if not is_valid:
        raise HTTPException(status_code=400, detail=result)
    
    domain = result
    
    try:
        # Run DNS reconnaissance
        recon_result = await run_dns_recon(
            domain=domain,
            scan_type=request.scan_type,
            custom_subdomains=request.custom_subdomains,
        )
        
        # Run AI analysis if requested
        if request.run_ai_analysis:
            try:
                ai_analysis = await _generate_dns_ai_analysis(recon_result)
                recon_result.ai_analysis = ai_analysis
            except Exception as e:
                logger.warning(f"AI analysis failed: {e}")
                recon_result.ai_analysis = {"error": str(e)}
        
        # Save report if requested
        report_id = None
        if request.save_report:
            try:
                report_id = await _save_dns_report(
                    recon_result,
                    request.scan_type,
                    request.report_title,
                )
            except Exception as e:
                logger.warning(f"Failed to save report: {e}")
        
        # Build response
        response_data = recon_result.to_dict()
        response_data["report_id"] = report_id
        
        return response_data
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"DNS scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"DNS scan failed: {str(e)}")


@router.post("/scan/stream")
async def run_dns_scan_stream(request: DNSScanRequest):
    """
    Run DNS reconnaissance with real-time progress streaming via Server-Sent Events.
    
    Returns a stream of progress events followed by the final result.
    """
    # Validate domain
    is_valid, result = validate_domain(request.domain)
    if not is_valid:
        raise HTTPException(status_code=400, detail=result)
    
    domain = result
    
    async def event_generator():
        progress_queue = asyncio.Queue()
        scan_complete = asyncio.Event()
        final_result = {"data": None, "error": None}
        
        def progress_callback(phase: str, progress: int, message: str):
            """Callback to queue progress updates."""
            try:
                asyncio.get_event_loop().call_soon_threadsafe(
                    progress_queue.put_nowait,
                    {"phase": phase, "progress": progress, "message": message}
                )
            except Exception:
                pass
        
        async def run_scan():
            """Run the scan in background."""
            try:
                recon_result = await run_dns_recon(
                    domain=domain,
                    scan_type=request.scan_type,
                    custom_subdomains=request.custom_subdomains,
                    progress_callback=progress_callback,
                )
                
                # Run AI analysis if requested
                if request.run_ai_analysis:
                    progress_callback("ai_analysis", 0, "Running AI analysis...")
                    try:
                        ai_analysis = await _generate_dns_ai_analysis(recon_result)
                        recon_result.ai_analysis = ai_analysis
                        progress_callback("ai_analysis", 100, "AI analysis complete")
                    except Exception as e:
                        logger.warning(f"AI analysis failed: {e}")
                        recon_result.ai_analysis = {"error": str(e)}
                
                # Save report if requested
                report_id = None
                if request.save_report:
                    try:
                        report_id = await _save_dns_report(
                            recon_result,
                            request.scan_type,
                            request.report_title,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to save report: {e}")
                
                response_data = recon_result.to_dict()
                response_data["report_id"] = report_id
                final_result["data"] = response_data
                
            except Exception as e:
                final_result["error"] = str(e)
            finally:
                scan_complete.set()
        
        # Start scan in background
        scan_task = asyncio.create_task(run_scan())
        
        # Stream progress updates
        while not scan_complete.is_set():
            try:
                # Wait for progress update with timeout
                progress = await asyncio.wait_for(progress_queue.get(), timeout=0.5)
                yield f"data: {json.dumps({'type': 'progress', **progress})}\n\n"
            except asyncio.TimeoutError:
                # Send heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        
        # Drain any remaining progress updates
        while not progress_queue.empty():
            progress = progress_queue.get_nowait()
            yield f"data: {json.dumps({'type': 'progress', **progress})}\n\n"
        
        # Send final result
        if final_result["error"]:
            yield f"data: {json.dumps({'type': 'error', 'error': final_result['error']})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'result', 'data': final_result['data']})}\n\n"
        
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/chat", response_model=DNSChatResponse)
async def chat_about_dns(request: DNSChatRequest):
    """Chat with AI about DNS reconnaissance results."""
    try:
        response = await _chat_about_dns_results(
            message=request.message,
            dns_context=request.dns_context,
            history=request.conversation_history,
        )
        return response
    except Exception as e:
        logger.error(f"DNS chat failed: {e}")
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")


@router.get("/reports", response_model=SavedDNSReportList)
async def list_dns_reports(skip: int = 0, limit: int = 20):
    """List saved DNS reconnaissance reports."""
    try:
        db = next(get_db())
        
        # Use analysis_type as primary filter (required column)
        dns_filter = or_(
            NetworkAnalysisReport.analysis_type == "dns",
            NetworkAnalysisReport.report_type == "dns"
        )
        
        reports = db.query(NetworkAnalysisReport).filter(
            dns_filter
        ).order_by(
            NetworkAnalysisReport.created_at.desc()
        ).offset(skip).limit(limit).all()
        
        total = db.query(NetworkAnalysisReport).filter(
            dns_filter
        ).count()
        
        summaries = []
        for report in reports:
            data = report.report_data or {}
            security = data.get("security", {})
            
            summaries.append(SavedDNSReport(
                id=report.id,
                domain=data.get("domain", "Unknown"),
                scan_type=data.get("scan_type", "standard"),
                title=report.title,
                total_records=data.get("total_records", 0),
                total_subdomains=data.get("total_subdomains", 0),
                zone_transfer_possible=data.get("zone_transfer_possible", False),
                mail_security_score=security.get("mail_security_score") if security else None,
                created_at=report.created_at.isoformat() if report.created_at else "",
            ))
        
        return SavedDNSReportList(reports=summaries, total=total)
        
    except Exception as e:
        logger.error(f"Failed to list DNS reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{report_id}")
async def get_dns_report(report_id: int):
    """Get a specific DNS report by ID."""
    try:
        db = next(get_db())
        
        dns_filter = or_(
            NetworkAnalysisReport.analysis_type == "dns",
            NetworkAnalysisReport.report_type == "dns"
        )
        
        report = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.id == report_id,
            dns_filter
        ).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        response_data = {
            "id": report.id,
            "title": report.title,
            "created_at": report.created_at.isoformat() if report.created_at else None,
        }
        
        # Merge report_data if available
        if report.report_data:
            response_data.update(report.report_data)
        
        # Add AI analysis if available
        if report.ai_report:
            response_data["ai_analysis"] = report.ai_report
        
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get DNS report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/reports/{report_id}")
async def delete_dns_report(report_id: int):
    """Delete a DNS report."""
    try:
        db = next(get_db())
        
        dns_filter = or_(
            NetworkAnalysisReport.analysis_type == "dns",
            NetworkAnalysisReport.report_type == "dns"
        )
        
        report = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.id == report_id,
            dns_filter
        ).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        db.delete(report)
        db.commit()
        
        return {"message": "Report deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete DNS report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WHOIS Endpoints
# ============================================================================

@router.get("/whois/status")
async def whois_status():
    """Check if WHOIS lookup is available."""
    available = is_whois_available()
    return {
        "available": available,
        "message": "WHOIS lookup ready" if available else "WHOIS command not installed"
    }


@router.post("/whois/domain", response_model=WhoisDomainResponse)
async def lookup_domain_whois(request: WhoisDomainRequest):
    """
    Perform WHOIS lookup for a domain name.
    
    Returns domain registration information including:
    - Registrar and registration dates
    - Name servers
    - Domain status
    - Registrant information (if available)
    """
    if not is_whois_available():
        raise HTTPException(status_code=503, detail="WHOIS command not available on server")
    
    # Basic domain validation
    domain = request.domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    
    # Remove protocol if present
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]
    # Remove path if present
    domain = domain.split("/")[0]
    # Remove port if present
    domain = domain.split(":")[0]
    
    try:
        result = run_whois_domain(domain)
        return result.to_dict()
    except Exception as e:
        logger.error(f"WHOIS domain lookup failed: {e}")
        raise HTTPException(status_code=500, detail=f"WHOIS lookup failed: {str(e)}")


@router.post("/whois/ip", response_model=WhoisIPResponse)
async def lookup_ip_whois(request: WhoisIPRequest):
    """
    Perform WHOIS lookup for an IP address.
    
    Returns IP ownership information including:
    - Network name and range
    - ASN and organization
    - Regional Internet Registry (RIR)
    - Abuse contact information
    """
    if not is_whois_available():
        raise HTTPException(status_code=503, detail="WHOIS command not available on server")
    
    ip_address = request.ip_address.strip()
    
    try:
        result = run_whois_ip(ip_address)
        return result.to_dict()
    except Exception as e:
        logger.error(f"WHOIS IP lookup failed: {e}")
        raise HTTPException(status_code=500, detail=f"WHOIS lookup failed: {str(e)}")


# ============================================================================
# Helper Functions
# ============================================================================

async def _save_dns_report(
    result: DNSReconResult,
    scan_type: str,
    title: Optional[str],
) -> int:
    """Save DNS report to database."""
    db = next(get_db())
    
    report_data = result.to_dict()
    report_data["scan_type"] = scan_type
    
    # Extract risk level from AI analysis if available
    risk_level = None
    if result.ai_analysis and isinstance(result.ai_analysis, dict):
        risk_level = result.ai_analysis.get("risk_level", "").capitalize() or None
    
    report = NetworkAnalysisReport(
        analysis_type="dns",  # Required column
        report_type="dns",    # Optional categorization
        title=title or f"DNS Scan: {result.domain}",
        report_data=report_data,
        risk_level=risk_level,
        ai_report=result.ai_analysis if isinstance(result.ai_analysis, dict) else None,
        created_at=datetime.utcnow(),
    )
    
    db.add(report)
    db.commit()
    db.refresh(report)
    
    logger.info(f"Saved DNS report with ID {report.id} for domain {result.domain}")
    return report.id


async def _generate_dns_ai_analysis(result: DNSReconResult) -> Dict[str, Any]:
    """Generate AI analysis of DNS reconnaissance results."""
    try:
        from ..core.config import settings
        from google import genai
        from google.genai import types
        
        if not settings.gemini_api_key:
            return {"error": "Gemini API key not configured"}
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build context
        security_summary = ""
        if result.security:
            security_summary = f"""
## Email Security Analysis
- SPF: {'✅ Present' if result.security.has_spf else '❌ Missing'}
  {f'Record: {result.security.spf_record}' if result.security.spf_record else ''}
  {f'Issues: {", ".join(result.security.spf_issues)}' if result.security.spf_issues else ''}
- DMARC: {'✅ Present' if result.security.has_dmarc else '❌ Missing'}
  {f'Record: {result.security.dmarc_record}' if result.security.dmarc_record else ''}
- DKIM: {'✅ Found' if result.security.has_dkim else '❌ Not found'} (selectors: {', '.join(result.security.dkim_selectors_found) if result.security.dkim_selectors_found else 'none'})
- DNSSEC: {'✅ Enabled' if result.security.has_dnssec else '❌ Not enabled'}
- CAA: {'✅ Present' if result.security.has_caa else '❌ Missing'}
- Mail Security Score: {result.security.mail_security_score}/100
"""
        
        subdomains_text = ""
        if result.subdomains:
            subdomains_text = "\n## Subdomains Found\n"
            for sub in result.subdomains[:30]:
                subdomains_text += f"- {sub.full_domain}: {', '.join(sub.ip_addresses) if sub.ip_addresses else 'No A record'}\n"
            if len(result.subdomains) > 30:
                subdomains_text += f"... and {len(result.subdomains) - 30} more\n"
        
        records_text = "\n## DNS Records\n"
        for record in result.records[:50]:
            records_text += f"- {record.record_type}: {record.value}\n"
        
        prompt = f"""Analyze this DNS reconnaissance data for security implications and attack surface.

# DNS Reconnaissance: {result.domain}

## Summary
- Total DNS Records: {result.total_records}
- Subdomains Found: {result.total_subdomains}
- Unique IPs: {len(result.unique_ips)}
- Nameservers: {', '.join(result.nameservers)}
- Mail Servers: {', '.join([m['server'] for m in result.mail_servers])}
- Zone Transfer Possible: {'⚠️ YES - CRITICAL!' if result.zone_transfer_possible else 'No'}

{security_summary}

{records_text}

{subdomains_text}

Provide analysis in this JSON structure:
{{
  "executive_summary": "<2-3 paragraph overview of the domain's DNS configuration, security posture, and attack surface>",
  "risk_level": "<critical/high/medium/low>",
  "key_findings": [
    {{"finding": "<title>", "severity": "<critical/high/medium/low>", "description": "<details>", "recommendation": "<action>"}}
  ],
  "attack_surface": {{
    "exposed_services": ["<service descriptions based on DNS>"],
    "potential_targets": ["<interesting subdomains or IPs>"],
    "reconnaissance_value": "<what an attacker learned>"
  }},
  "email_security": {{
    "assessment": "<overall email security assessment>",
    "spoofing_risk": "<high/medium/low>",
    "recommendations": ["<email security improvements>"]
  }},
  "infrastructure_insights": "<what we can infer about their infrastructure>",
  "next_steps": ["<recommended follow-up actions>"]
}}

Focus on actionable security insights. Be specific about risks and recommendations."""

        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
            )
        )
        response_text = response.text.strip()
        
        # Parse JSON
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]
        
        return json.loads(response_text)
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": str(e)}


async def _chat_about_dns_results(
    message: str,
    dns_context: Dict[str, Any],
    history: Optional[List[Dict[str, str]]] = None,
) -> DNSChatResponse:
    """Chat with AI about DNS results."""
    try:
        from ..core.config import settings
        from google import genai
        
        if not settings.gemini_api_key:
            return DNSChatResponse(
                response="AI chat requires a Gemini API key to be configured.",
                suggestions=[]
            )
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build conversation context
        context = f"""You are a DNS security expert helping analyze DNS reconnaissance results.

## DNS Data for {dns_context.get('domain', 'Unknown')}
- Records: {dns_context.get('total_records', 0)}
- Subdomains: {dns_context.get('total_subdomains', 0)}
- Nameservers: {', '.join(dns_context.get('nameservers', []))}
- Zone Transfer Possible: {dns_context.get('zone_transfer_possible', False)}

Security Analysis:
{json.dumps(dns_context.get('security', {}), indent=2) if dns_context.get('security') else 'Not available'}

Sample subdomains: {', '.join([s.get('full_domain', '') for s in dns_context.get('subdomains', [])[:10]])}
"""
        
        # Add conversation history
        conversation = ""
        if history:
            for msg in history[-6:]:  # Last 6 messages
                role = msg.get("role", "user")
                content = msg.get("content", "")
                conversation += f"\n{role.upper()}: {content}"
        
        prompt = f"""{context}

{conversation}

USER: {message}

Provide a helpful, security-focused response. If suggesting commands or techniques, explain what they do.
At the end, suggest 2-3 relevant follow-up questions the user might ask."""

        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt
        )
        response_text = response.text.strip()
        
        # Extract suggestions (look for bullet points at the end)
        suggestions = []
        lines = response_text.split('\n')
        for i, line in enumerate(lines):
            if 'follow-up' in line.lower() or 'you might ask' in line.lower():
                for j in range(i+1, min(i+5, len(lines))):
                    if lines[j].strip().startswith(('-', '•', '*', '1', '2', '3')):
                        suggestion = lines[j].strip().lstrip('-•*123456789. ')
                        if suggestion and len(suggestion) > 10:
                            suggestions.append(suggestion)
        
        return DNSChatResponse(
            response=response_text,
            suggestions=suggestions[:3]
        )
        
    except Exception as e:
        logger.error(f"DNS chat failed: {e}")
        return DNSChatResponse(
            response=f"I encountered an error: {str(e)}",
            suggestions=["Try rephrasing your question", "Ask about specific DNS records"]
        )
