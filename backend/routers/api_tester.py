"""
API Tester Router

Endpoints for API security testing functionality.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
import logging
import asyncio

from backend.services.api_tester_service import (
    test_api_endpoints,
    quick_scan,
    test_websocket,
    get_owasp_api_reference,
    APITestResult,
    OWASP_API_TOP_10,
    discover_http_services,
    get_all_presets,
    get_preset,
    save_preset,
    delete_preset,
    batch_test_targets,
    TargetPreset,
    BatchTestTarget,
    # OpenAPI Import
    parse_openapi_spec,
    fetch_openapi_spec,
    OpenAPIParseResult,
    # JWT Analyzer
    analyze_jwt,
    JWTAnalysisResult,
    # Export functions
    export_test_result_json,
    export_test_result_markdown,
    export_batch_result_markdown,
    export_jwt_analysis_markdown,
    # AI Auto-Test
    ai_auto_test,
    AIAutoTestResult,
)
from backend.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api-tester", tags=["API Tester"])


class EndpointConfig(BaseModel):
    """Configuration for a single endpoint to test."""
    url: str = Field(..., description="Endpoint URL (relative or absolute)")
    method: str = Field(default="GET", description="HTTP method")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Custom headers")
    params: Optional[Dict[str, str]] = Field(default=None, description="Query parameters")
    body: Optional[Any] = Field(default=None, description="Request body (for POST/PUT/PATCH)")


class APITestRequest(BaseModel):
    """Request model for API testing."""
    base_url: str = Field(..., description="Base URL of the API")
    endpoints: List[EndpointConfig] = Field(
        default_factory=list,
        description="List of endpoints to test"
    )
    auth_type: Optional[str] = Field(
        default=None,
        description="Authentication type: none, basic, bearer, api_key"
    )
    auth_value: Optional[str] = Field(
        default=None,
        description="Authentication value (token, API key, or base64 credentials)"
    )
    
    # Test options
    test_auth: bool = Field(default=True, description="Test authentication")
    test_cors: bool = Field(default=True, description="Test CORS configuration")
    test_rate_limit: bool = Field(default=True, description="Test rate limiting")
    test_input_validation: bool = Field(default=True, description="Test input validation")
    test_methods: bool = Field(default=True, description="Test HTTP methods")
    test_graphql: bool = Field(default=False, description="Run GraphQL-specific tests")
    
    # Proxy configuration
    proxy_url: Optional[str] = Field(default=None, description="HTTP/HTTPS proxy URL (e.g., http://proxy:8080)")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")


class QuickScanRequest(BaseModel):
    """Request model for quick API scan."""
    url: str = Field(..., description="URL to scan")
    auth_header: Optional[str] = Field(default=None, description="Optional Authorization header")
    proxy_url: Optional[str] = Field(default=None, description="Optional HTTP/HTTPS proxy URL")


class WebSocketTestRequest(BaseModel):
    """Request model for WebSocket security testing."""
    url: str = Field(..., description="WebSocket URL (ws:// or wss://)")
    auth_token: Optional[str] = Field(default=None, description="Optional authentication token")
    test_messages: Optional[List[str]] = Field(default=None, description="Custom messages to test")
    timeout: float = Field(default=10.0, description="Connection timeout in seconds")
    proxy_url: Optional[str] = Field(default=None, description="Optional proxy URL")


class AIAnalysisRequest(BaseModel):
    """Request model for AI analysis of API test results."""
    test_result: Dict[str, Any] = Field(..., description="API test result to analyze")


@router.post("/test", response_model=Dict[str, Any])
async def test_api(request: APITestRequest) -> Dict[str, Any]:
    """
    Test API endpoints for security vulnerabilities.
    
    Performs comprehensive security testing including:
    - Security header analysis
    - CORS configuration testing
    - Authentication testing
    - Rate limiting detection
    - Input validation testing (SQLi, XSS)
    - HTTP method enumeration
    - Sensitive data exposure detection
    - Error handling analysis
    - GraphQL-specific tests (optional)
    """
    try:
        # Build auth header if provided
        auth_header = None
        if request.auth_type and request.auth_value:
            if request.auth_type == "bearer":
                auth_header = f"Bearer {request.auth_value}"
            elif request.auth_type == "basic":
                auth_header = f"Basic {request.auth_value}"
            elif request.auth_type == "api_key":
                auth_header = request.auth_value
        
        # Convert endpoint configs to dicts
        endpoints = []
        if request.endpoints:
            for ep in request.endpoints:
                endpoints.append({
                    "url": ep.url,
                    "method": ep.method,
                    "headers": ep.headers,
                    "params": ep.params,
                    "body": ep.body,
                })
        else:
            # If no endpoints specified, test the base URL
            endpoints = [{"url": request.base_url, "method": "GET"}]
        
        result = await test_api_endpoints(
            base_url=request.base_url,
            endpoints=endpoints,
            auth_header=auth_header,
            test_auth=request.test_auth,
            test_cors=request.test_cors,
            test_rate_limit=request.test_rate_limit,
            test_input_validation=request.test_input_validation,
            test_methods=request.test_methods,
            test_graphql=request.test_graphql,
            proxy_url=request.proxy_url,
            timeout=request.timeout,
        )
        
        return result.to_dict()
        
    except Exception as e:
        logger.error(f"API testing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/quick-scan", response_model=Dict[str, Any])
async def quick_api_scan(request: QuickScanRequest) -> Dict[str, Any]:
    """
    Quick security scan of a single API endpoint.
    
    Performs a rapid assessment with essential security checks:
    - Security headers
    - CORS configuration
    - Authentication requirements
    - Input validation
    - HTTP methods
    - Sensitive data exposure
    """
    try:
        result = await quick_scan(request.url, proxy_url=request.proxy_url)
        return result.to_dict()
    except Exception as e:
        logger.error(f"Quick scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_api_results(request: AIAnalysisRequest) -> Dict[str, Any]:
    """
    Get AI-powered analysis of API test results.
    
    Provides:
    - Executive summary of findings
    - Risk assessment
    - Prioritized remediation steps
    - Best practices recommendations
    """
    try:
        # Build prompt for AI analysis
        findings_summary = []
        for finding in request.test_result.get("all_findings", []):
            findings_summary.append(
                f"- [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}: "
                f"{finding.get('description', '')} (CWE: {finding.get('cwe', 'N/A')})"
            )
        
        prompt = f"""Analyze the following API security test results and provide actionable recommendations:

Base URL: {request.test_result.get('base_url', 'Unknown')}
Security Score: {request.test_result.get('security_score', 'N/A')}/100
Endpoints Tested: {request.test_result.get('endpoints_tested', 0)}
Total Findings: {request.test_result.get('total_findings', 0)}

Severity Breakdown:
- Critical: {request.test_result.get('critical_count', 0)}
- High: {request.test_result.get('high_count', 0)}
- Medium: {request.test_result.get('medium_count', 0)}
- Low: {request.test_result.get('low_count', 0)}
- Info: {request.test_result.get('info_count', 0)}

Findings:
{chr(10).join(findings_summary) if findings_summary else 'No findings'}

Provide:
1. Executive summary (2-3 sentences)
2. Top 3 priority actions to address
3. Risk assessment (Critical/High/Medium/Low overall risk)
4. Recommended security improvements
5. Any compliance concerns (OWASP API Security Top 10, etc.)
"""
        
        # Call Gemini API directly
        from google import genai
        
        if not settings.gemini_api_key:
            raise HTTPException(status_code=500, detail="Gemini API key not configured")
        
        client = genai.Client(api_key=settings.gemini_api_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        
        analysis_text = response.text if response.text else "Unable to generate analysis"
        
        # Extract recommendations (lines starting with numbers)
        import re
        recommendations = re.findall(r'^\d+\.\s*(.+)$', analysis_text, re.MULTILINE)
        
        return {
            "analysis": analysis_text,
            "recommendations": recommendations[:5],  # Top 5 recommendations
            "test_result_summary": {
                "security_score": request.test_result.get("security_score"),
                "total_findings": request.test_result.get("total_findings"),
                "critical_count": request.test_result.get("critical_count"),
                "high_count": request.test_result.get("high_count"),
            }
        }
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Common API security payloads for reference
COMMON_PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' OR '1'='1",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
    ],
    "command_injection": [
        "; ls -la",
        "| cat /etc/passwd",
        "& whoami",
        "`id`",
    ],
    "nosql_injection": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
    ],
}


@router.get("/payloads", response_model=Dict[str, List[str]])
async def get_test_payloads() -> Dict[str, List[str]]:
    """
    Get common security test payloads.
    
    Returns categorized payloads for:
    - SQL Injection
    - XSS
    - Path Traversal
    - Command Injection
    - NoSQL Injection
    """
    return COMMON_PAYLOADS


@router.get("/security-headers", response_model=Dict[str, Dict[str, str]])
async def get_security_headers_info() -> Dict[str, Dict[str, str]]:
    """
    Get information about security headers to check.
    
    Returns recommended security headers with descriptions
    and recommended values.
    """
    return {
        "Strict-Transport-Security": {
            "description": "Forces HTTPS connections",
            "recommended": "max-age=31536000; includeSubDomains",
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing",
            "recommended": "nosniff",
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking",
            "recommended": "DENY or SAMEORIGIN",
        },
        "Content-Security-Policy": {
            "description": "Controls resources browser can load",
            "recommended": "default-src 'self'; script-src 'self'",
        },
        "X-XSS-Protection": {
            "description": "Legacy XSS filter",
            "recommended": "0 (if CSP is set) or 1; mode=block",
        },
        "Referrer-Policy": {
            "description": "Controls referrer information",
            "recommended": "strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "description": "Controls browser features",
            "recommended": "geolocation=(), microphone=(), camera=()",
        },
        "Cache-Control": {
            "description": "Controls caching",
            "recommended": "no-store, private (for sensitive APIs)",
        },
    }


@router.post("/websocket-test", response_model=Dict[str, Any])
async def test_websocket_endpoint(request: WebSocketTestRequest) -> Dict[str, Any]:
    """
    Test WebSocket endpoint for security vulnerabilities.
    
    Performs security testing including:
    - Connection without authentication
    - Origin header validation (CSWSH)
    - Message injection (XSS, prototype pollution)
    - Rate limiting detection
    - Error handling analysis
    - Transport security (ws vs wss)
    """
    try:
        result = await test_websocket(
            url=request.url,
            auth_token=request.auth_token,
            test_messages=request.test_messages,
            timeout=request.timeout,
            proxy_url=request.proxy_url,
        )
        return result.to_dict()
    except Exception as e:
        logger.error(f"WebSocket test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/owasp-api-top10", response_model=Dict[str, Any])
async def get_owasp_api_top10() -> Dict[str, Any]:
    """
    Get OWASP API Security Top 10 (2023) reference.
    
    Returns detailed information about each category including:
    - Name and description
    - Reference URL
    """
    return {
        "version": "2023",
        "categories": OWASP_API_TOP_10,
    }


# WebSocket test payloads for reference
WS_PAYLOADS = {
    "xss": [
        '{"type": "message", "content": "<script>alert(1)</script>"}',
        '{"data": "<img src=x onerror=alert(1)>"}',
    ],
    "prototype_pollution": [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
    ],
    "injection": [
        '{"type": "subscribe", "channel": "../../../etc/passwd"}',
        '{"query": "\' OR 1=1 --"}',
    ],
    "dos": [
        '{"type": "subscribe", "channel": "*"}',  # Wildcard subscription
        '{"data": "' + 'A' * 100000 + '"}',  # Large payload
    ],
}


@router.get("/websocket-payloads", response_model=Dict[str, List[str]])
async def get_websocket_payloads() -> Dict[str, List[str]]:
    """
    Get WebSocket security test payloads.
    
    Returns categorized payloads for:
    - XSS
    - Prototype Pollution
    - Injection
    - DoS
    """
    return WS_PAYLOADS


# =============================================================================
# Network Discovery Endpoints
# =============================================================================

class NetworkDiscoveryRequest(BaseModel):
    """Request model for network discovery."""
    subnet: str = Field(..., description="Subnet in CIDR notation (e.g., 192.168.1.0/24) or IP range")
    ports: Optional[List[int]] = Field(
        default=None,
        description="Ports to scan (default: 80, 443, 8080, 8443, 3000, 5000, 8000)"
    )
    timeout: float = Field(default=1.5, description="Connection timeout per host in seconds")
    max_concurrent: int = Field(default=100, description="Maximum concurrent connections")
    max_hosts: int = Field(default=256, description="Maximum number of hosts to scan")
    overall_timeout: float = Field(default=120.0, description="Maximum total scan time in seconds")


@router.post("/discover", response_model=Dict[str, Any])
async def discover_services(request: NetworkDiscoveryRequest) -> Dict[str, Any]:
    """
    Discover HTTP/API services on a network subnet.
    
    Scans the specified subnet for HTTP services and identifies potential APIs.
    Useful for air-gapped environments to find targets on VM networks.
    
    **Example subnets:**
    - 192.168.1.0/24 (256 hosts)
    - 10.0.0.1-10.0.0.50 (50 hosts)
    - 172.16.0.100 (single host)
    
    **Timeouts:**
    - Per-host timeout: 1.5s default (lower = faster but may miss slow hosts)
    - Overall timeout: 120s default (prevents runaway scans)
    - Max hosts: 256 default (prevents scanning huge networks)
    """
    try:
        result = await discover_http_services(
            subnet=request.subnet,
            ports=request.ports,
            timeout=request.timeout,
            max_concurrent=request.max_concurrent,
            max_hosts=request.max_hosts,
            overall_timeout=request.overall_timeout,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Network discovery timed out for {request.subnet}")
        return {
            "subnet": request.subnet,
            "total_hosts_scanned": 0,
            "services_found": [],
            "scan_duration_seconds": request.overall_timeout,
            "errors": [f"Scan timed out after {request.overall_timeout}s"]
        }
    except Exception as e:
        logger.error(f"Network discovery failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Target Presets Endpoints
# =============================================================================

class PresetCreateRequest(BaseModel):
    """Request model for creating a target preset."""
    name: str = Field(..., description="Preset name")
    description: str = Field(default="", description="Preset description")
    base_url: str = Field(..., description="Base URL for the target")
    endpoints: List[Dict[str, str]] = Field(
        default_factory=list,
        description="List of endpoints to test"
    )
    auth_type: Optional[str] = Field(default=None, description="Auth type (bearer, basic, api_key)")
    auth_value: Optional[str] = Field(default=None, description="Auth value/token")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")


@router.get("/presets", response_model=List[Dict[str, Any]])
async def list_presets() -> List[Dict[str, Any]]:
    """
    Get all saved target presets.
    
    Returns default presets and any user-created presets.
    """
    presets = get_all_presets()
    return [p.to_dict() for p in presets]


@router.get("/presets/{preset_id}", response_model=Dict[str, Any])
async def get_preset_by_id(preset_id: str) -> Dict[str, Any]:
    """Get a specific target preset by ID."""
    preset = get_preset(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Preset not found")
    return preset.to_dict()


@router.post("/presets", response_model=Dict[str, Any])
async def create_preset(request: PresetCreateRequest) -> Dict[str, Any]:
    """
    Create a new target preset.
    
    Save commonly used targets for quick access.
    """
    preset = TargetPreset(
        id="",
        name=request.name,
        description=request.description,
        base_url=request.base_url,
        endpoints=request.endpoints,
        auth_type=request.auth_type,
        auth_value=request.auth_value,
        headers=request.headers,
        tags=request.tags,
    )
    saved = save_preset(preset)
    return saved.to_dict()


@router.delete("/presets/{preset_id}")
async def remove_preset(preset_id: str) -> Dict[str, str]:
    """Delete a target preset (default presets cannot be deleted)."""
    if delete_preset(preset_id):
        return {"status": "deleted", "id": preset_id}
    raise HTTPException(status_code=400, detail="Cannot delete default presets")


# =============================================================================
# Batch Testing Endpoints
# =============================================================================

class BatchTargetConfig(BaseModel):
    """Configuration for a single target in batch testing."""
    url: str = Field(..., description="Target URL")
    name: Optional[str] = Field(default=None, description="Friendly name for the target")
    auth_type: Optional[str] = Field(default=None, description="Auth type")
    auth_value: Optional[str] = Field(default=None, description="Auth value")


class BatchTestRequest(BaseModel):
    """Request model for batch testing multiple targets."""
    targets: List[BatchTargetConfig] = Field(..., description="List of targets to test")
    test_options: Optional[Dict[str, bool]] = Field(
        default=None,
        description="Test options (test_auth, test_cors, test_input_validation, etc.)"
    )
    proxy_url: Optional[str] = Field(default=None, description="Proxy URL for all requests")
    max_concurrent: int = Field(default=5, description="Maximum concurrent tests")


@router.post("/batch-test", response_model=Dict[str, Any])
async def run_batch_test(request: BatchTestRequest) -> Dict[str, Any]:
    """
    Test multiple API targets in batch.
    
    Runs quick security scans on multiple targets simultaneously.
    Useful for testing multiple VMs or services at once.
    
    **Example use cases:**
    - Test all VMs in a lab environment
    - Compare security across multiple API versions
    - Audit multiple microservices
    """
    try:
        targets = [
            BatchTestTarget(
                url=t.url,
                name=t.name,
                auth_type=t.auth_type,
                auth_value=t.auth_value,
            )
            for t in request.targets
        ]
        
        result = await batch_test_targets(
            targets=targets,
            test_options=request.test_options,
            proxy_url=request.proxy_url,
            max_concurrent=request.max_concurrent,
        )
        
        return result.to_dict()
    except Exception as e:
        logger.error(f"Batch testing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# OpenAPI/Swagger Import Endpoints
# =============================================================================

class OpenAPIImportRequest(BaseModel):
    """Request model for importing OpenAPI specs."""
    spec_content: Optional[str] = Field(default=None, description="OpenAPI/Swagger spec content (JSON or YAML)")
    spec_url: Optional[str] = Field(default=None, description="URL to fetch OpenAPI spec from")


@router.post("/import-openapi", response_model=Dict[str, Any])
async def import_openapi(request: OpenAPIImportRequest) -> Dict[str, Any]:
    """
    Import and parse an OpenAPI/Swagger specification.
    
    Supports:
    - OpenAPI 3.0.x (JSON/YAML)
    - Swagger 2.0 (JSON/YAML)
    - Remote URL fetching
    - Direct content upload
    
    Returns discovered endpoints with:
    - Path and HTTP method
    - Parameters and request body schema
    - Security requirements
    - Tags and descriptions
    """
    try:
        spec_content = request.spec_content
        
        # Fetch from URL if provided
        if request.spec_url and not spec_content:
            spec_content = await fetch_openapi_spec(request.spec_url)
        
        if not spec_content:
            raise HTTPException(
                status_code=400,
                detail="Either spec_content or spec_url must be provided"
            )
        
        result = parse_openapi_spec(spec_content, request.spec_url)
        return result.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OpenAPI import failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# JWT Token Analyzer Endpoints
# =============================================================================

class JWTAnalyzeRequest(BaseModel):
    """Request model for JWT analysis."""
    token: str = Field(..., description="JWT token to analyze")
    test_weak_secrets: bool = Field(default=True, description="Test for common weak secrets")


@router.post("/analyze-jwt", response_model=Dict[str, Any])
async def analyze_jwt_token(request: JWTAnalyzeRequest) -> Dict[str, Any]:
    """
    Analyze a JWT token for security issues.
    
    Checks for:
    - Algorithm vulnerabilities ('none', weak symmetric keys)
    - Common weak secrets (HS256/HS384/HS512)
    - Token expiration status
    - Missing security claims (exp, iat, jti)
    - Sensitive data in payload
    
    Works completely offline - no external services needed.
    """
    try:
        result = analyze_jwt(request.token, request.test_weak_secrets)
        return result.to_dict()
    except Exception as e:
        logger.error(f"JWT analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Export Report Endpoints
# =============================================================================

class ExportTestResultRequest(BaseModel):
    """Request model for exporting test results."""
    test_result: Dict[str, Any] = Field(..., description="Test result to export")
    format: str = Field(default="markdown", description="Export format: json, markdown, pdf, docx")
    title: str = Field(default="API Security Test Report", description="Report title")


class ExportBatchResultRequest(BaseModel):
    """Request model for exporting batch test results."""
    batch_result: Dict[str, Any] = Field(..., description="Batch test result to export")
    format: str = Field(default="markdown", description="Export format: json, markdown, pdf, docx")
    title: str = Field(default="Batch API Test Report", description="Report title")


class ExportJWTResultRequest(BaseModel):
    """Request model for exporting JWT analysis results."""
    jwt_result: Dict[str, Any] = Field(..., description="JWT analysis result to export")
    format: str = Field(default="markdown", description="Export format: json, markdown, pdf, docx")


class ExportAutoTestResultRequest(BaseModel):
    """Request model for exporting AI Auto-Test results."""
    auto_test_result: Dict[str, Any] = Field(..., description="Auto-test result to export")
    format: str = Field(default="markdown", description="Export format: json, markdown, pdf, docx")
    title: str = Field(default="AI Auto-Test Security Report", description="Report title")


from fastapi.responses import PlainTextResponse, Response


@router.post("/export/test-result")
async def export_test_result(request: ExportTestResultRequest):
    """
    Export API test result as JSON, Markdown, PDF, or Word document.
    
    Formats:
    - json: Raw JSON data
    - markdown: Formatted markdown report
    - pdf: Professional PDF document
    - docx: Microsoft Word document
    """
    try:
        from backend.services.api_tester_service import (
            APITestResult, Finding,
            export_test_result_json, export_test_result_markdown,
            export_test_result_pdf, export_test_result_docx
        )
        
        result_dict = request.test_result
        
        # Convert findings
        all_findings = []
        for f in result_dict.get("all_findings", []):
            all_findings.append(Finding(
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=f.get("severity", "info"),
                category=f.get("category", ""),
                cwe=f.get("cwe"),
                owasp_api=f.get("owasp_api"),
                endpoint=f.get("endpoint"),
                evidence=f.get("evidence"),
                remediation=f.get("remediation", ""),
            ))
        
        result = APITestResult(
            base_url=result_dict.get("base_url", ""),
            endpoints_tested=result_dict.get("endpoints_tested", 0),
            total_findings=result_dict.get("total_findings", 0),
            critical_count=result_dict.get("critical_count", 0),
            high_count=result_dict.get("high_count", 0),
            medium_count=result_dict.get("medium_count", 0),
            low_count=result_dict.get("low_count", 0),
            info_count=result_dict.get("info_count", 0),
            security_score=result_dict.get("security_score", 0),
            test_duration_seconds=result_dict.get("test_duration_seconds", 0),
            owasp_api_breakdown=result_dict.get("owasp_api_breakdown", {}),
            all_findings=all_findings,
        )
        
        fmt = request.format.lower()
        
        if fmt == "json":
            content = export_test_result_json(result)
            return PlainTextResponse(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="api-security-report.json"'}
            )
        elif fmt == "pdf":
            content = export_test_result_pdf(result, request.title)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": 'attachment; filename="api-security-report.pdf"'}
            )
        elif fmt == "docx":
            content = export_test_result_docx(result, request.title)
            return Response(
                content=content,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": 'attachment; filename="api-security-report.docx"'}
            )
        else:  # markdown
            content = export_test_result_markdown(result, request.title)
            return PlainTextResponse(
                content=content,
                media_type="text/markdown",
                headers={"Content-Disposition": 'attachment; filename="api-security-report.md"'}
            )
    except Exception as e:
        logger.error(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export/batch-result")
async def export_batch_result(request: ExportBatchResultRequest):
    """
    Export batch test result as JSON, Markdown, PDF, or Word document.
    """
    try:
        from backend.services.api_tester_service import (
            BatchTestResult,
            export_batch_result_markdown, export_batch_result_pdf, export_batch_result_docx
        )
        import json
        
        result_dict = request.batch_result
        
        result = BatchTestResult(
            total_targets=result_dict.get("total_targets", 0),
            successful=result_dict.get("successful", 0),
            failed=result_dict.get("failed", 0),
            total_findings=result_dict.get("total_findings", 0),
            critical_findings=result_dict.get("critical_findings", 0),
            high_findings=result_dict.get("high_findings", 0),
            results=result_dict.get("results", []),
            scan_duration_seconds=result_dict.get("scan_duration_seconds", 0),
        )
        
        fmt = request.format.lower()
        
        if fmt == "json":
            content = json.dumps(result.to_dict(), indent=2)
            return PlainTextResponse(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="batch-report.json"'}
            )
        elif fmt == "pdf":
            content = export_batch_result_pdf(result, request.title)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": 'attachment; filename="batch-report.pdf"'}
            )
        elif fmt == "docx":
            content = export_batch_result_docx(result, request.title)
            return Response(
                content=content,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": 'attachment; filename="batch-report.docx"'}
            )
        else:  # markdown
            content = export_batch_result_markdown(result, request.title)
            return PlainTextResponse(
                content=content,
                media_type="text/markdown",
                headers={"Content-Disposition": 'attachment; filename="batch-report.md"'}
            )
    except Exception as e:
        logger.error(f"Batch export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export/jwt-result")
async def export_jwt_result(request: ExportJWTResultRequest):
    """
    Export JWT analysis result as JSON, Markdown, PDF, or Word document.
    """
    try:
        from backend.services.api_tester_service import (
            JWTAnalysisResult,
            export_jwt_analysis_markdown, export_jwt_analysis_pdf, export_jwt_analysis_docx
        )
        import json
        
        result_dict = request.jwt_result
        
        result = JWTAnalysisResult(
            valid_structure=result_dict.get("valid_structure", False),
            header=result_dict.get("header", {}),
            payload=result_dict.get("payload", {}),
            signature=result_dict.get("signature", ""),
            algorithm=result_dict.get("algorithm", ""),
            findings=result_dict.get("findings", []),
            is_expired=result_dict.get("is_expired", False),
            expiry_time=result_dict.get("expiry_time"),
            issued_at=result_dict.get("issued_at"),
            issuer=result_dict.get("issuer"),
            audience=result_dict.get("audience"),
            subject=result_dict.get("subject"),
            raw_parts=result_dict.get("raw_parts", []),
        )
        
        fmt = request.format.lower()
        
        if fmt == "json":
            content = json.dumps(result.to_dict(), indent=2)
            return PlainTextResponse(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="jwt-analysis.json"'}
            )
        elif fmt == "pdf":
            content = export_jwt_analysis_pdf(result)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": 'attachment; filename="jwt-analysis.pdf"'}
            )
        elif fmt == "docx":
            content = export_jwt_analysis_docx(result)
            return Response(
                content=content,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": 'attachment; filename="jwt-analysis.docx"'}
            )
        else:  # markdown
            content = export_jwt_analysis_markdown(result)
            return PlainTextResponse(
                content=content,
                media_type="text/markdown",
                headers={"Content-Disposition": 'attachment; filename="jwt-analysis.md"'}
            )
    except Exception as e:
        logger.error(f"JWT export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export/auto-test")
async def export_auto_test_result(request: ExportAutoTestResultRequest):
    """
    Export AI Auto-Test result as JSON, Markdown, PDF, or Word document.
    """
    try:
        from backend.services.api_tester_service import (
            AIAutoTestResult,
            export_auto_test_pdf, export_auto_test_docx
        )
        import json
        
        result_dict = request.auto_test_result
        
        result = AIAutoTestResult(
            target=result_dict.get("target", ""),
            target_type=result_dict.get("target_type", "url"),
            discovered_services=result_dict.get("discovered_services", []),
            discovered_endpoints=result_dict.get("discovered_endpoints", []),
            test_results=result_dict.get("test_results", []),
            all_findings=result_dict.get("all_findings", []),
            total_findings=result_dict.get("total_findings", 0),
            critical_count=result_dict.get("critical_count", 0),
            high_count=result_dict.get("high_count", 0),
            medium_count=result_dict.get("medium_count", 0),
            low_count=result_dict.get("low_count", 0),
            info_count=result_dict.get("info_count", 0),
            security_score=result_dict.get("security_score", 100),
            ai_summary=result_dict.get("ai_summary", ""),
            scan_duration_seconds=result_dict.get("scan_duration_seconds", 0),
            error=result_dict.get("error"),
        )
        
        fmt = request.format.lower()
        
        if fmt == "json":
            content = json.dumps(result.to_dict(), indent=2)
            return PlainTextResponse(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="auto-test-report.json"'}
            )
        elif fmt == "pdf":
            content = export_auto_test_pdf(result, request.title)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": 'attachment; filename="auto-test-report.pdf"'}
            )
        elif fmt == "docx":
            content = export_auto_test_docx(result, request.title)
            return Response(
                content=content,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": 'attachment; filename="auto-test-report.docx"'}
            )
        else:  # markdown
            # Return the AI summary as markdown since it's already well-formatted
            content = result.ai_summary or "No results to export"
            return PlainTextResponse(
                content=content,
                media_type="text/markdown",
                headers={"Content-Disposition": 'attachment; filename="auto-test-report.md"'}
            )
    except Exception as e:
        logger.error(f"Auto-test export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class ExportWebSocketResultRequest(BaseModel):
    """Request to export WebSocket test result."""
    websocket_result: Dict[str, Any] = Field(..., description="WebSocket test result data")
    format: str = Field(default="json", description="Export format: json, markdown, pdf, docx")
    title: Optional[str] = Field(default="WebSocket Security Test Report")


@router.post("/export/websocket")
async def export_websocket_result(request: ExportWebSocketResultRequest):
    """
    Export WebSocket test result as JSON, Markdown, PDF, or Word document.
    """
    try:
        from backend.services.api_tester_service import (
            WebSocketTestResult,
            export_websocket_pdf, export_websocket_docx, export_websocket_markdown
        )
        import json
        
        result_dict = request.websocket_result
        
        result = WebSocketTestResult(
            url=result_dict.get("url", ""),
            connected=result_dict.get("connected", False),
            connection_time_ms=result_dict.get("connection_time_ms", 0),
            protocol=result_dict.get("protocol"),
            subprotocol=result_dict.get("subprotocol"),
            findings=result_dict.get("findings", []),
            messages_sent=result_dict.get("messages_sent", 0),
            messages_received=result_dict.get("messages_received", 0),
            error=result_dict.get("error"),
            test_duration_seconds=result_dict.get("test_duration_seconds", 0),
            security_score=result_dict.get("security_score", 100),
            owasp_api_breakdown=result_dict.get("owasp_api_breakdown", {}),
        )
        
        fmt = request.format.lower()
        
        if fmt == "json":
            content = json.dumps(result.to_dict(), indent=2)
            return PlainTextResponse(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="websocket-test-report.json"'}
            )
        elif fmt == "pdf":
            content = export_websocket_pdf(result, request.title)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": 'attachment; filename="websocket-test-report.pdf"'}
            )
        elif fmt == "docx":
            content = export_websocket_docx(result, request.title)
            return Response(
                content=content,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": 'attachment; filename="websocket-test-report.docx"'}
            )
        else:  # markdown
            content = export_websocket_markdown(result, request.title)
            return PlainTextResponse(
                content=content,
                media_type="text/markdown",
                headers={"Content-Disposition": 'attachment; filename="websocket-test-report.md"'}
            )
    except Exception as e:
        logger.error(f"WebSocket export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# AI Chat Endpoint
# =============================================================================

class ChatMessage(BaseModel):
    """A message in the chat conversation."""
    role: str = Field(..., description="Role: 'user' or 'assistant'")
    content: str = Field(..., description="Message content")


class APITesterChatRequest(BaseModel):
    """Request model for chat about API test results."""
    message: str = Field(..., description="User's message/question")
    conversation_history: List[ChatMessage] = Field(
        default_factory=list,
        description="Previous messages in the conversation"
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="API test context (results, JWT analysis, OpenAPI, etc.)"
    )


class APITesterChatResponse(BaseModel):
    """Response from API tester chat."""
    response: str
    error: Optional[str] = None


@router.post("/chat", response_model=APITesterChatResponse)
async def chat_about_api_test(request: APITesterChatRequest) -> APITesterChatResponse:
    """
    Chat with AI about API security test results.
    
    Allows users to ask follow-up questions about:
    - Test results and findings
    - JWT token analysis
    - OpenAPI specifications
    - Security recommendations
    - Remediation guidance
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        return APITesterChatResponse(
            response="",
            error="Chat unavailable: GEMINI_API_KEY not configured"
        )
    
    try:
        from google import genai
        from google.genai import types
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Extract context
        ctx = request.context
        test_result = ctx.get("test_result", {})
        batch_result = ctx.get("batch_result", {})
        jwt_result = ctx.get("jwt_result", {})
        openapi_result = ctx.get("openapi_result", {})
        
        # Build system context
        context_parts = []
        
        context_parts.append("""You are a helpful API security expert assistant. You help users understand API security test results, JWT tokens, and provide guidance on fixing vulnerabilities.

Be concise but thorough. Use technical terms appropriately. Reference specific findings when relevant. Suggest concrete remediation steps.""")
        
        # Add test result context
        if test_result:
            context_parts.append(f"""
## API Security Test Results
- **Base URL:** {test_result.get('base_url', 'N/A')}
- **Security Score:** {test_result.get('security_score', 'N/A')}/100
- **Endpoints Tested:** {test_result.get('endpoints_tested', 0)}
- **Total Findings:** {test_result.get('total_findings', 0)}
- **Critical:** {test_result.get('critical_count', 0)} | **High:** {test_result.get('high_count', 0)} | **Medium:** {test_result.get('medium_count', 0)} | **Low:** {test_result.get('low_count', 0)}

### Findings:
{json.dumps(test_result.get('all_findings', [])[:15], indent=2)}

### OWASP API Top 10 Breakdown:
{json.dumps(test_result.get('owasp_api_breakdown', {}), indent=2)}
""")
        
        # Add batch result context
        if batch_result:
            context_parts.append(f"""
## Batch Test Results
- **Total Targets:** {batch_result.get('total_targets', 0)}
- **Successful:** {batch_result.get('successful', 0)}
- **Failed:** {batch_result.get('failed', 0)}
- **Total Findings:** {batch_result.get('total_findings', 0)}
- **Critical/High:** {batch_result.get('critical_findings', 0) + batch_result.get('high_findings', 0)}

### Target Results:
{json.dumps(batch_result.get('results', [])[:10], indent=2)}
""")
        
        # Add JWT analysis context
        if jwt_result:
            context_parts.append(f"""
## JWT Token Analysis
- **Valid Structure:** {jwt_result.get('valid_structure', False)}
- **Algorithm:** {jwt_result.get('algorithm', 'N/A')}
- **Expired:** {jwt_result.get('is_expired', False)}
- **Issuer:** {jwt_result.get('issuer', 'N/A')}
- **Subject:** {jwt_result.get('subject', 'N/A')}

### Header:
{json.dumps(jwt_result.get('header', {}), indent=2)}

### Payload:
{json.dumps(jwt_result.get('payload', {}), indent=2)}

### Security Findings:
{json.dumps(jwt_result.get('findings', []), indent=2)}
""")
        
        # Add OpenAPI context
        if openapi_result:
            context_parts.append(f"""
## OpenAPI Specification
- **Title:** {openapi_result.get('title', 'N/A')}
- **Version:** {openapi_result.get('version', 'N/A')}
- **Base URL:** {openapi_result.get('base_url', 'N/A')}
- **Total Endpoints:** {openapi_result.get('total_endpoints', 0)}

### Methods Breakdown:
{json.dumps(openapi_result.get('methods_breakdown', {}), indent=2)}

### Security Schemes:
{json.dumps(openapi_result.get('security_schemes', {}), indent=2)}

### Endpoints (first 10):
{json.dumps(openapi_result.get('endpoints', [])[:10], indent=2)}
""")
        
        full_context = "\n".join(context_parts)
        
        # Build conversation for multi-turn chat
        contents = []
        contents.append(types.Content(
            role="user",
            parts=[types.Part(text=full_context + "\n\n---\nAnswer the user's question below based on the above context.")]
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
        
        return APITesterChatResponse(response=response.text)
        
    except Exception as e:
        logger.error(f"API Tester chat error: {e}")
        return APITesterChatResponse(
            response="",
            error=f"Failed to generate response: {str(e)}"
        )


# =============================================================================
# AI Auto-Test - Automated Security Testing
# =============================================================================

class AIAutoTestRequest(BaseModel):
    """Request for AI-driven automated security testing."""
    target: str = Field(
        ...,
        description="Target to test - can be IP (192.168.1.1), IP:port (192.168.1.1:8080), URL (http://api.example.com), domain (api.example.com), CIDR network (192.168.1.0/24), or IP range (192.168.1.1-192.168.1.254)"
    )
    ports: Optional[List[int]] = Field(
        default=None,
        description="Specific ports to scan (default: common web ports 80, 443, 8080, etc.)"
    )
    probe_endpoints: bool = Field(
        default=True,
        description="Whether to probe for common API endpoints"
    )
    run_security_tests: bool = Field(
        default=True,
        description="Whether to run security tests on discovered endpoints"
    )
    max_endpoints: int = Field(
        default=20,
        description="Maximum number of endpoints to test"
    )
    timeout: float = Field(
        default=10.0,
        description="Request timeout in seconds for endpoint testing"
    )
    network_timeout: float = Field(
        default=1.0,
        description="Connection timeout for network scans (lower = faster but may miss slow hosts)"
    )
    max_concurrent: int = Field(
        default=200,
        description="Maximum concurrent connections for network scans (higher = faster)"
    )
    proxy_url: Optional[str] = Field(
        default=None,
        description="Optional proxy URL for requests"
    )


@router.post("/auto-test")
async def run_ai_auto_test(request: AIAutoTestRequest) -> Dict[str, Any]:
    """
    AI-driven automated security testing.
    
    Automatically:
    1. Detects target type (IP, URL, domain, CIDR network, IP range)
    2. Discovers running web services and ports (fast parallel scan for networks)
    3. Probes for common API endpoints
    4. Runs comprehensive security tests
    5. Aggregates findings and generates AI summary
    
    Perfect for quickly assessing security posture of:
    - IP addresses (e.g., 192.168.1.1, 10.0.0.50:8080)
    - URLs (e.g., http://api.example.com/v1)
    - Domains (e.g., api.example.com)
    - CIDR networks (e.g., 192.168.1.0/24) - scans up to 256 hosts in parallel
    - IP ranges (e.g., 192.168.1.1-192.168.1.254)
    
    Network scans use aggressive parallelism (200 concurrent connections by default)
    with short timeouts (1s) for speed. A /24 network typically completes in under 30 seconds.
    """
    try:
        result = await ai_auto_test(
            target=request.target,
            ports=request.ports,
            probe_common_paths=request.probe_endpoints,
            run_security_tests=request.run_security_tests,
            max_endpoints=request.max_endpoints,
            timeout=request.timeout,
            proxy_url=request.proxy_url,
            network_timeout=request.network_timeout,
            max_concurrent=request.max_concurrent,
        )
        return result.to_dict()
    except Exception as e:
        logger.error(f"AI Auto-Test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
