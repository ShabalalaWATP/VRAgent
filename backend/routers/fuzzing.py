"""
Fuzzing Router

Endpoints for web application fuzzing and security testing.
"""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime
import logging
import json
import asyncio

from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models.models import FuzzingSession

from backend.services.fuzzing_service import (
    FuzzConfig,
    FuzzResult,
    run_fuzzing_session,
    stream_fuzzing_session,
    export_fuzz_results_json,
    export_fuzz_results_markdown,
)

from backend.services.smart_detection_service import (
    detect_vulnerabilities,
    detect_anomalies,
    differential_analysis,
    categorize_responses,
    create_session_summary,
    SmartFinding,
    AnomalyResult,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/fuzzer", tags=["Security Fuzzer"])


class FuzzRequest(BaseModel):
    """Request model for starting a fuzzing session."""
    target_url: str = Field(..., description="Target URL with position markers (§0§, §1§, etc.)")
    method: str = Field(default="GET", description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    body: str = Field(default="", description="Request body (for POST/PUT/PATCH)")
    positions: List[str] = Field(default_factory=list, description="Position markers")
    payloads: List[List[str]] = Field(default_factory=list, description="Payload sets for each position")
    attack_mode: str = Field(default="sniper", description="Attack mode: sniper, batteringram, pitchfork, clusterbomb")
    threads: int = Field(default=10, ge=1, le=50, description="Number of concurrent threads")
    delay: int = Field(default=0, ge=0, description="Delay between requests in milliseconds")
    timeout: int = Field(default=10000, ge=1000, le=60000, description="Request timeout in milliseconds")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    match_codes: List[int] = Field(default_factory=lambda: [200, 301, 302, 401, 403], description="Status codes to highlight")
    filter_codes: List[int] = Field(default_factory=list, description="Status codes to filter out")
    match_regex: str = Field(default="", description="Regex pattern to match in responses")
    proxy_url: Optional[str] = Field(default=None, description="HTTP proxy URL")


class ExportRequest(BaseModel):
    """Request model for exporting fuzzing results."""
    result: Dict[str, Any] = Field(..., description="Fuzzing result data")
    format: str = Field(default="json", description="Export format: json, markdown")


@router.post("/run", response_model=Dict[str, Any])
async def run_fuzzer(request: FuzzRequest):
    """
    Run a complete fuzzing session.
    
    This endpoint executes all payload combinations and returns the complete results
    when finished. For real-time progress updates, use the /stream endpoint or WebSocket.
    """
    try:
        config = FuzzConfig(
            target_url=request.target_url,
            method=request.method,
            headers=request.headers,
            body=request.body,
            positions=request.positions,
            payloads=request.payloads,
            attack_mode=request.attack_mode,
            threads=request.threads,
            delay=request.delay,
            timeout=request.timeout,
            follow_redirects=request.follow_redirects,
            match_codes=request.match_codes,
            filter_codes=request.filter_codes,
            match_regex=request.match_regex,
            proxy_url=request.proxy_url,
        )
        
        result = await run_fuzzing_session(config)
        return result.to_dict()
        
    except Exception as e:
        logger.exception(f"Fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stream")
async def stream_fuzzer(request: FuzzRequest):
    """
    Stream fuzzing results as Server-Sent Events.
    
    Each result is sent as it completes, allowing real-time progress monitoring.
    """
    config = FuzzConfig(
        target_url=request.target_url,
        method=request.method,
        headers=request.headers,
        body=request.body,
        positions=request.positions,
        payloads=request.payloads,
        attack_mode=request.attack_mode,
        threads=request.threads,
        delay=request.delay,
        timeout=request.timeout,
        follow_redirects=request.follow_redirects,
        match_codes=request.match_codes,
        filter_codes=request.filter_codes,
        match_regex=request.match_regex,
        proxy_url=request.proxy_url,
    )
    
    async def event_generator():
        try:
            async for event in stream_fuzzing_session(config):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception(f"Streaming error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/ws")
async def websocket_fuzzer(websocket: WebSocket):
    """
    WebSocket endpoint for real-time fuzzing with bidirectional communication.
    
    Supports:
    - Starting fuzzing sessions
    - Receiving real-time results
    - Stopping/pausing sessions
    """
    await websocket.accept()
    
    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")
            
            if action == "start":
                config_data = data.get("config", {})
                config = FuzzConfig(
                    target_url=config_data.get("target_url", ""),
                    method=config_data.get("method", "GET"),
                    headers=config_data.get("headers", {}),
                    body=config_data.get("body", ""),
                    positions=config_data.get("positions", []),
                    payloads=config_data.get("payloads", []),
                    attack_mode=config_data.get("attack_mode", "sniper"),
                    threads=config_data.get("threads", 10),
                    delay=config_data.get("delay", 0),
                    timeout=config_data.get("timeout", 10000),
                    follow_redirects=config_data.get("follow_redirects", True),
                    match_codes=config_data.get("match_codes", [200, 301, 302, 401, 403]),
                    filter_codes=config_data.get("filter_codes", []),
                    match_regex=config_data.get("match_regex", ""),
                    proxy_url=config_data.get("proxy_url"),
                )
                
                async for event in stream_fuzzing_session(config):
                    await websocket.send_json(event)
                    
            elif action == "ping":
                await websocket.send_json({"type": "pong"})
                
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.exception(f"WebSocket error: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass


@router.post("/export")
async def export_results(request: ExportRequest):
    """
    Export fuzzing results in various formats.
    """
    try:
        # Reconstruct FuzzResult from dict
        from backend.services.fuzzing_service import (
            FuzzConfig, FuzzResult, FuzzResponse, FuzzFinding, FuzzStats
        )
        
        result_data = request.result
        
        config = FuzzConfig(**result_data.get("config", {}))
        stats = FuzzStats(**result_data.get("stats", {}))
        
        responses = []
        for r in result_data.get("responses", []):
            responses.append(FuzzResponse(**r))
        
        findings = []
        for f in result_data.get("findings", []):
            findings.append(FuzzFinding(**f))
        
        result = FuzzResult(
            config=config,
            responses=responses,
            findings=findings,
            stats=stats,
        )
        
        if request.format == "json":
            content = export_fuzz_results_json(result)
            return {"content": content, "filename": "fuzzing-report.json", "mime_type": "application/json"}
        elif request.format == "markdown":
            content = export_fuzz_results_markdown(result)
            return {"content": content, "filename": "fuzzing-report.md", "mime_type": "text/markdown"}
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")
            
    except Exception as e:
        logger.exception(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Built-in wordlists endpoint
BUILTIN_WORDLISTS = {
    "sqli": {
        "name": "SQL Injection",
        "description": "Common SQL injection payloads",
        "payloads": [
            "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
            "' OR 1=1#", "admin'--", "') OR ('1'='1", "1' ORDER BY 1--",
            "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
            "'; DROP TABLE users--", "' AND 1=1--", "' AND 1=2--",
            "' WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--", "1' AND SLEEP(5)--", "' OR SLEEP(5)--",
        ],
    },
    "xss": {
        "name": "XSS Payloads",
        "description": "Cross-site scripting test payloads",
        "payloads": [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>", "javascript:alert('XSS')",
            "<body onload=alert('XSS')>", "<iframe src=\"javascript:alert('XSS')\">",
            "<input onfocus=alert('XSS') autofocus>", "\"><script>alert('XSS')</script>",
            "'-alert('XSS')-'", "';alert('XSS')//",
            "</title><script>alert('XSS')</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<svg/onload=alert('XSS')>",
        ],
    },
    "lfi": {
        "name": "Path Traversal",
        "description": "Directory traversal payloads",
        "payloads": [
            "../", "..\\", "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd", "/etc/passwd", "/etc/shadow",
            "/proc/self/environ", "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input", "file:///etc/passwd",
        ],
    },
    "cmdi": {
        "name": "Command Injection",
        "description": "OS command injection payloads",
        "payloads": [
            "; ls -la", "| ls -la", "& ls -la", "&& ls -la", "|| ls -la",
            "`ls -la`", "$(ls -la)", "; cat /etc/passwd", "| cat /etc/passwd",
            "; id", "| id", "| whoami", "; whoami", "; sleep 5", "| sleep 5",
        ],
    },
    "ssti": {
        "name": "SSTI Payloads",
        "description": "Server-side template injection payloads",
        "payloads": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "{{config}}", "{{config.items()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
        ],
    },
    "directories": {
        "name": "Common Directories",
        "description": "Common web directories for enumeration",
        "payloads": [
            "admin", "api", "backup", "config", "dashboard", "db", "debug",
            "dev", "docs", "files", "images", "include", "js", "lib", "log",
            "login", "media", "old", "php", "private", "public", "scripts",
            "static", "system", "temp", "test", "tmp", "upload", "user",
            "vendor", "wp-admin", "wp-content", ".git", ".svn", ".env",
        ],
    },
    "params": {
        "name": "API Parameters",
        "description": "Common API parameter names",
        "payloads": [
            "id", "user_id", "userId", "user", "username", "name", "email",
            "password", "token", "api_key", "apiKey", "key", "secret",
            "auth", "session", "access_token", "page", "limit", "offset",
            "sort", "order", "filter", "query", "q", "search", "type",
            "category", "status", "action", "format", "callback", "url",
        ],
    },
}


@router.get("/wordlists")
async def get_wordlists():
    """Get available built-in wordlists."""
    result = {}
    for key, wordlist in BUILTIN_WORDLISTS.items():
        result[key] = {
            "name": wordlist["name"],
            "description": wordlist["description"],
            "count": len(wordlist["payloads"]),
        }
    return result


@router.get("/wordlists/{wordlist_id}")
async def get_wordlist(wordlist_id: str):
    """Get a specific wordlist's payloads."""
    if wordlist_id not in BUILTIN_WORDLISTS:
        raise HTTPException(status_code=404, detail=f"Wordlist not found: {wordlist_id}")
    
    return BUILTIN_WORDLISTS[wordlist_id]


# ============================================================================
# ADVANCED FUZZING ENDPOINTS
# ============================================================================

from backend.services.fuzzing_advanced import (
    EncodingType,
    TransformationType,
    encode_payload,
    apply_multiple_encodings,
    generate_encoded_variants,
    transform_payload,
    GeneratorConfig,
    generate_from_config,
    generate_number_range,
    generate_date_range,
    generate_pattern_payloads,
    GrepRule,
    ExtractRule,
    apply_grep_rules,
    apply_extract_rules,
    COMMON_EXTRACT_RULES,
    cluster_responses,
    find_anomalous_responses,
    detect_waf,
    detect_rate_limiting,
    discover_parameters,
    discover_endpoints,
    mutate_payload,
    generate_all_mutations,
    prioritize_payloads,
    export_advanced_analysis,
)


class EncodeRequest(BaseModel):
    """Request for encoding payloads."""
    payloads: List[str] = Field(..., description="Payloads to encode")
    encodings: List[str] = Field(default=["url"], description="Encoding types to apply")
    chain: bool = Field(default=False, description="Chain encodings sequentially")


class GenerateRequest(BaseModel):
    """Request for generating payloads."""
    generator_type: str = Field(..., description="Generator type: number_range, char_range, date_range, uuid, pattern")
    params: Dict[str, Any] = Field(default_factory=dict, description="Generator parameters")


class MutateRequest(BaseModel):
    """Request for mutating payloads."""
    payloads: List[str] = Field(..., description="Payloads to mutate")
    mutation_types: List[str] = Field(default=["case", "encoding"], description="Mutation types to apply")


class GrepRequest(BaseModel):
    """Request for grep matching."""
    content: str = Field(..., description="Content to search")
    rules: List[Dict[str, Any]] = Field(default_factory=list, description="Custom grep rules")
    use_common_rules: bool = Field(default=True, description="Include common extraction rules")


class ClusterRequest(BaseModel):
    """Request for response clustering."""
    responses: List[Dict[str, Any]] = Field(..., description="Responses to cluster")
    similarity_threshold: float = Field(default=0.85, ge=0.5, le=1.0, description="Similarity threshold")


class AnalyzeRequest(BaseModel):
    """Request for comprehensive analysis."""
    responses: List[Dict[str, Any]] = Field(..., description="Responses to analyze")
    detect_waf: bool = Field(default=True, description="Detect WAF presence")
    detect_rate_limit: bool = Field(default=True, description="Detect rate limiting")
    discover_params: bool = Field(default=True, description="Discover parameters from responses")
    cluster_responses: bool = Field(default=True, description="Cluster similar responses")
    extract_data: bool = Field(default=True, description="Extract common data patterns")


@router.post("/encode")
async def encode_payloads(request: EncodeRequest):
    """
    Encode payloads using various encoding schemes.
    
    Supported encodings: none, url, double_url, base64, html_entities, 
    html_decimal, html_hex, unicode, hex, octal, binary
    """
    try:
        results = {}
        
        for payload in request.payloads:
            if request.chain:
                # Apply encodings sequentially
                encodings = [EncodingType(e) for e in request.encodings if e in [et.value for et in EncodingType]]
                results[payload] = apply_multiple_encodings(payload, encodings)
            else:
                # Generate each encoding variant
                encodings = [EncodingType(e) for e in request.encodings if e in [et.value for et in EncodingType]]
                results[payload] = generate_encoded_variants(payload, encodings)
        
        return {
            "encoded": results,
            "available_encodings": [e.value for e in EncodingType],
        }
    except Exception as e:
        logger.exception(f"Encoding failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate")
async def generate_payloads(request: GenerateRequest):
    """
    Generate payloads using various generators.
    
    Generator types:
    - number_range: {start, end, step, padding}
    - char_range: {start, end}
    - date_range: {start, end, format}
    - uuid: {count}
    - pattern: {pattern, count}
    """
    try:
        config = GeneratorConfig(type=request.generator_type, params=request.params)
        payloads = generate_from_config(config)
        
        return {
            "payloads": payloads,
            "count": len(payloads),
            "generator_type": request.generator_type,
        }
    except Exception as e:
        logger.exception(f"Generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mutate")
async def mutate_payloads(request: MutateRequest):
    """
    Generate mutations of payloads.
    
    Mutation types: case, encoding, whitespace, null_byte, comment, concatenation
    """
    try:
        results = {}
        
        for payload in request.payloads:
            mutations = set([payload])
            for mutation_type in request.mutation_types:
                for mutated in mutate_payload(payload, mutation_type):
                    mutations.add(mutated)
            results[payload] = list(mutations)
        
        return {
            "mutations": results,
            "total_variants": sum(len(v) for v in results.values()),
            "available_mutation_types": ["case", "encoding", "whitespace", "null_byte", "comment", "concatenation"],
        }
    except Exception as e:
        logger.exception(f"Mutation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/grep")
async def grep_responses(request: GrepRequest):
    """
    Search content using grep rules and extract data.
    
    Returns matched patterns and extracted values.
    """
    try:
        rules = []
        
        # Add custom rules
        for rule_data in request.rules:
            rules.append(GrepRule(
                name=rule_data.get("name", "custom"),
                pattern=rule_data.get("pattern", ""),
                is_regex=rule_data.get("is_regex", True),
                case_sensitive=rule_data.get("case_sensitive", False),
                extract_group=rule_data.get("extract_group"),
            ))
        
        # Apply grep rules
        matches = apply_grep_rules(request.content, rules)
        
        # Apply common extract rules if requested
        extracted = {}
        if request.use_common_rules:
            extracted = apply_extract_rules(request.content, COMMON_EXTRACT_RULES)
        
        return {
            "matches": [m.to_dict() for m in matches],
            "match_count": len(matches),
            "extracted": extracted,
        }
    except Exception as e:
        logger.exception(f"Grep failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cluster")
async def cluster_fuzz_responses(request: ClusterRequest):
    """
    Cluster similar responses together.
    
    Helps identify unique responses and potential anomalies.
    """
    try:
        clusters = cluster_responses(request.responses, request.similarity_threshold)
        anomalies = find_anomalous_responses(request.responses, clusters)
        
        return {
            "clusters": [c.to_dict() for c in clusters],
            "total_clusters": len(clusters),
            "anomalous_responses": anomalies,
            "similarity_threshold": request.similarity_threshold,
        }
    except Exception as e:
        logger.exception(f"Clustering failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_responses(request: AnalyzeRequest):
    """
    Perform comprehensive analysis of fuzzing responses.
    
    Includes WAF detection, rate limiting, parameter discovery, 
    response clustering, and data extraction.
    """
    try:
        results = {
            "response_count": len(request.responses),
        }
        
        # WAF Detection
        if request.detect_waf and request.responses:
            # Use first 403/503 response for WAF detection
            waf_response = next(
                (r for r in request.responses if r.get('status_code') in [403, 503]),
                request.responses[0]
            )
            waf_result = detect_waf(
                waf_response.get('headers', {}),
                waf_response.get('body', ''),
                waf_response.get('status_code', 200)
            )
            results["waf_detection"] = waf_result.to_dict()
        
        # Rate Limit Detection
        if request.detect_rate_limit:
            rate_result = detect_rate_limiting(request.responses)
            results["rate_limiting"] = rate_result.to_dict()
        
        # Parameter Discovery
        if request.discover_params:
            all_params = []
            all_endpoints = set()
            
            for r in request.responses[:10]:  # Limit to first 10 for performance
                body = r.get('body', '')
                if body:
                    params = discover_parameters(body)
                    all_params.extend([p.to_dict() for p in params])
                    endpoints = discover_endpoints(body)
                    all_endpoints.update(endpoints)
            
            # Deduplicate parameters by name
            seen_params = set()
            unique_params = []
            for p in all_params:
                if p['name'] not in seen_params:
                    seen_params.add(p['name'])
                    unique_params.append(p)
            
            results["discovered_parameters"] = unique_params
            results["discovered_endpoints"] = list(all_endpoints)[:50]  # Limit output
        
        # Response Clustering
        if request.cluster_responses:
            clusters = cluster_responses(request.responses)
            anomalies = find_anomalous_responses(request.responses, clusters)
            results["clustering"] = {
                "clusters": [c.to_dict() for c in clusters],
                "total_clusters": len(clusters),
                "anomalous_responses": anomalies,
            }
        
        # Data Extraction
        if request.extract_data:
            all_extracted = {}
            for r in request.responses[:10]:
                body = r.get('body', '')
                if body:
                    extracted = apply_extract_rules(body, COMMON_EXTRACT_RULES)
                    for key, values in extracted.items():
                        if key not in all_extracted:
                            all_extracted[key] = []
                        all_extracted[key].extend(values)
            
            # Deduplicate extracted values
            for key in all_extracted:
                all_extracted[key] = list(set(all_extracted[key]))[:20]  # Limit per category
            
            results["extracted_data"] = all_extracted
        
        # Statistics
        results["statistics"] = {
            "unique_status_codes": list(set(r.get('status_code') for r in request.responses)),
            "avg_response_time": sum(r.get('response_time', 0) for r in request.responses) / len(request.responses) if request.responses else 0,
            "avg_response_length": sum(r.get('response_length', 0) for r in request.responses) / len(request.responses) if request.responses else 0,
            "error_count": sum(1 for r in request.responses if r.get('error')),
            "interesting_count": sum(1 for r in request.responses if r.get('interesting')),
        }
        
        return results
        
    except Exception as e:
        logger.exception(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/encodings")
async def get_available_encodings():
    """Get list of available encoding types."""
    return {
        "encodings": [
            {"value": e.value, "name": e.name.replace("_", " ").title()}
            for e in EncodingType
        ]
    }


@router.get("/transformations")
async def get_available_transformations():
    """Get list of available transformation types."""
    return {
        "transformations": [
            {"value": t.value, "name": t.name.replace("_", " ").title()}
            for t in TransformationType
        ]
    }


@router.get("/generators")
async def get_available_generators():
    """Get information about available payload generators."""
    return {
        "generators": [
            {
                "type": "number_range",
                "description": "Generate a range of numbers",
                "params": {"start": "int", "end": "int", "step": "int (optional)", "padding": "int (optional)"},
                "example": {"start": 1, "end": 100, "step": 1, "padding": 4}
            },
            {
                "type": "char_range",
                "description": "Generate a range of characters",
                "params": {"start": "char", "end": "char"},
                "example": {"start": "a", "end": "z"}
            },
            {
                "type": "date_range",
                "description": "Generate a range of dates",
                "params": {"start": "YYYY-MM-DD", "end": "YYYY-MM-DD", "format": "strftime format"},
                "example": {"start": "2024-01-01", "end": "2024-12-31", "format": "%Y-%m-%d"}
            },
            {
                "type": "uuid",
                "description": "Generate random UUIDs",
                "params": {"count": "int"},
                "example": {"count": 10}
            },
            {
                "type": "pattern",
                "description": "Generate payloads from a pattern",
                "params": {"pattern": "string with [a-z], [0-9], etc.", "count": "int"},
                "example": {"pattern": "user[0-9]{4}", "count": 10}
            }
        ]
    }


# =============================================================================
# Session Management Endpoints
# =============================================================================

class SessionCreateRequest(BaseModel):
    """Request to create a new fuzzing session."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target_url: str
    method: str = "GET"
    config: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class SessionUpdateRequest(BaseModel):
    """Request to update a fuzzing session."""
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None
    findings: Optional[List[Dict[str, Any]]] = None
    analysis: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    total_requests: Optional[int] = None
    success_count: Optional[int] = None
    error_count: Optional[int] = None
    interesting_count: Optional[int] = None
    avg_response_time: Optional[float] = None


class SessionListResponse(BaseModel):
    """Response for listing sessions."""
    sessions: List[Dict[str, Any]]
    total: int
    page: int
    page_size: int


@router.post("/sessions", response_model=Dict[str, Any])
async def create_session(request: SessionCreateRequest, db: Session = Depends(get_db)):
    """Create a new fuzzing session."""
    try:
        session = FuzzingSession(
            name=request.name,
            description=request.description,
            target_url=request.target_url,
            method=request.method,
            config=request.config,
            tags=request.tags,
            status="created",
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        
        return {
            "id": session.id,
            "name": session.name,
            "target_url": session.target_url,
            "status": session.status,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "message": "Session created successfully",
        }
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to create session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all fuzzing sessions with pagination and filtering."""
    try:
        query = db.query(FuzzingSession)
        
        # Apply filters
        if status:
            query = query.filter(FuzzingSession.status == status)
        if search:
            query = query.filter(
                FuzzingSession.name.ilike(f"%{search}%") |
                FuzzingSession.target_url.ilike(f"%{search}%")
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        offset = (page - 1) * page_size
        sessions = query.order_by(FuzzingSession.created_at.desc()).offset(offset).limit(page_size).all()
        
        return SessionListResponse(
            sessions=[
                {
                    "id": s.id,
                    "name": s.name,
                    "description": s.description,
                    "target_url": s.target_url,
                    "method": s.method,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                    "total_requests": s.total_requests,
                    "success_count": s.success_count,
                    "error_count": s.error_count,
                    "interesting_count": s.interesting_count,
                    "avg_response_time": s.avg_response_time,
                    "tags": s.tags or [],
                    "findings_count": len(s.findings) if s.findings else 0,
                }
                for s in sessions
            ],
            total=total,
            page=page,
            page_size=page_size,
        )
    except Exception as e:
        logger.exception(f"Failed to list sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}", response_model=Dict[str, Any])
async def get_session(session_id: int, db: Session = Depends(get_db)):
    """Get a specific fuzzing session with all details."""
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {
            "id": session.id,
            "name": session.name,
            "description": session.description,
            "target_url": session.target_url,
            "method": session.method,
            "status": session.status,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "updated_at": session.updated_at.isoformat() if session.updated_at else None,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "finished_at": session.finished_at.isoformat() if session.finished_at else None,
            "config": session.config,
            "total_requests": session.total_requests,
            "success_count": session.success_count,
            "error_count": session.error_count,
            "interesting_count": session.interesting_count,
            "avg_response_time": session.avg_response_time,
            "results": session.results,
            "findings": session.findings,
            "analysis": session.analysis,
            "tags": session.tags or [],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to get session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/sessions/{session_id}", response_model=Dict[str, Any])
async def update_session(
    session_id: int,
    request: SessionUpdateRequest,
    db: Session = Depends(get_db),
):
    """Update a fuzzing session."""
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Update fields if provided
        if request.name is not None:
            session.name = request.name
        if request.description is not None:
            session.description = request.description
        if request.status is not None:
            session.status = request.status
            if request.status == "running" and not session.started_at:
                session.started_at = datetime.utcnow()
            elif request.status in ["completed", "failed"]:
                session.finished_at = datetime.utcnow()
        if request.results is not None:
            session.results = request.results
        if request.findings is not None:
            session.findings = request.findings
        if request.analysis is not None:
            session.analysis = request.analysis
        if request.tags is not None:
            session.tags = request.tags
        if request.total_requests is not None:
            session.total_requests = request.total_requests
        if request.success_count is not None:
            session.success_count = request.success_count
        if request.error_count is not None:
            session.error_count = request.error_count
        if request.interesting_count is not None:
            session.interesting_count = request.interesting_count
        if request.avg_response_time is not None:
            session.avg_response_time = request.avg_response_time
        
        db.commit()
        db.refresh(session)
        
        return {
            "id": session.id,
            "name": session.name,
            "status": session.status,
            "message": "Session updated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to update session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: int, db: Session = Depends(get_db)):
    """Delete a fuzzing session."""
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        db.delete(session)
        db.commit()
        
        return {"message": "Session deleted successfully", "id": session_id}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to delete session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sessions/{session_id}/duplicate", response_model=Dict[str, Any])
async def duplicate_session(session_id: int, db: Session = Depends(get_db)):
    """Duplicate a fuzzing session (config only, not results)."""
    try:
        original = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not original:
            raise HTTPException(status_code=404, detail="Session not found")
        
        new_session = FuzzingSession(
            name=f"{original.name} (Copy)",
            description=original.description,
            target_url=original.target_url,
            method=original.method,
            config=original.config,
            tags=original.tags,
            status="created",
        )
        db.add(new_session)
        db.commit()
        db.refresh(new_session)
        
        return {
            "id": new_session.id,
            "name": new_session.name,
            "message": "Session duplicated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to duplicate session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Smart Detection Endpoints
# =============================================================================

class SmartDetectRequest(BaseModel):
    """Request for smart vulnerability detection."""
    responses: List[Dict[str, Any]] = Field(..., description="Fuzzing responses to analyze")
    baseline_response: Optional[Dict[str, Any]] = Field(None, description="Optional baseline for comparison")


class AnomalyDetectRequest(BaseModel):
    """Request for anomaly detection."""
    responses: List[Dict[str, Any]] = Field(..., description="Fuzzing responses to analyze")
    sensitivity: float = Field(default=2.0, ge=1.0, le=5.0, description="Anomaly sensitivity (z-score threshold)")


class DifferentialRequest(BaseModel):
    """Request for differential analysis."""
    baseline_response: Dict[str, Any] = Field(..., description="Baseline response for comparison")
    test_responses: List[Dict[str, Any]] = Field(..., description="Responses to compare against baseline")


class AutoAnalyzeRequest(BaseModel):
    """Request for automatic comprehensive analysis."""
    responses: List[Dict[str, Any]] = Field(..., description="Fuzzing responses to analyze")
    detect_vulnerabilities: bool = Field(default=True)
    detect_anomalies: bool = Field(default=True)
    categorize: bool = Field(default=True)
    differential: bool = Field(default=False)
    baseline_index: int = Field(default=0, description="Index of response to use as baseline for differential")


@router.post("/smart-detect/vulnerabilities")
async def smart_detect_vulnerabilities(request: SmartDetectRequest):
    """
    Detect potential vulnerabilities in fuzzing responses using signature-based detection.
    
    Analyzes responses for:
    - SQL injection error messages
    - XSS reflection
    - Command injection output
    - Path traversal file content
    - SSTI template evaluation
    - Information disclosure
    - And more...
    """
    try:
        # Normalize response format for detection engine
        normalized_responses = []
        for resp in request.responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
            }
            normalized_responses.append(normalized)
        
        # Normalize baseline if provided
        baseline = None
        if request.baseline_response:
            baseline = {
                "id": request.baseline_response.get("id"),
                "body": request.baseline_response.get("body") or request.baseline_response.get("response_body", ""),
                "headers": request.baseline_response.get("headers") or request.baseline_response.get("response_headers", {}),
                "status_code": request.baseline_response.get("status_code", 0),
            }
        
        findings = detect_vulnerabilities(normalized_responses, baseline)
        
        return {
            "findings": [f.to_dict() for f in findings],
            "total": len(findings),
            "by_severity": {
                "critical": sum(1 for f in findings if f.severity.value == "critical"),
                "high": sum(1 for f in findings if f.severity.value == "high"),
                "medium": sum(1 for f in findings if f.severity.value == "medium"),
                "low": sum(1 for f in findings if f.severity.value == "low"),
                "info": sum(1 for f in findings if f.severity.value == "info"),
            },
            "by_type": _count_by_field(findings, lambda f: f.vuln_type.value),
        }
    except Exception as e:
        logger.exception(f"Vulnerability detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-detect/anomalies")
async def smart_detect_anomalies(request: AnomalyDetectRequest):
    """
    Detect anomalous responses using statistical analysis.
    
    Detects:
    - Response time anomalies
    - Response length anomalies
    - Status code anomalies
    - Content anomalies
    """
    try:
        # Normalize response format for detection engine
        normalized_responses = []
        for resp in request.responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
                "content_length": resp.get("content_length") or len(resp.get("body") or resp.get("response_body", "")),
            }
            normalized_responses.append(normalized)
        
        anomalies = detect_anomalies(normalized_responses)
        
        return {
            "anomalies": [a.to_dict() for a in anomalies],
            "total": len(anomalies),
            "by_type": _count_by_field(anomalies, lambda a: a.anomaly_type),
            "most_anomalous": [a.response_id for a in anomalies[:10]],
        }
    except Exception as e:
        logger.exception(f"Anomaly detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-detect/differential")
async def smart_differential_analysis(request: DifferentialRequest):
    """
    Perform differential analysis comparing responses to a baseline.
    
    Useful for:
    - Boolean-based SQL injection detection
    - Authentication bypass detection
    - Access control testing
    """
    try:
        # Normalize baseline
        baseline = {
            "id": request.baseline_response.get("id"),
            "body": request.baseline_response.get("body") or request.baseline_response.get("response_body", ""),
            "headers": request.baseline_response.get("headers") or request.baseline_response.get("response_headers", {}),
            "status_code": request.baseline_response.get("status_code", 0),
            "response_time": request.baseline_response.get("response_time", 0),
            "content_length": request.baseline_response.get("content_length") or len(request.baseline_response.get("body") or request.baseline_response.get("response_body", "")),
        }
        
        # Normalize test responses
        test_responses = []
        for resp in request.test_responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
                "content_length": resp.get("content_length") or len(resp.get("body") or resp.get("response_body", "")),
            }
            test_responses.append(normalized)
        
        results = differential_analysis(baseline, test_responses)
        
        interesting = [r for r in results if r.get("potentially_interesting")]
        
        return {
            "results": results,
            "total": len(results),
            "interesting_count": len(interesting),
            "most_different": [r["response_id"] for r in interesting[:10]],
        }
    except Exception as e:
        logger.exception(f"Differential analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-detect/categorize")
async def smart_categorize_responses(request: SmartDetectRequest):
    """
    Automatically categorize responses into groups.
    
    Categories include:
    - success (2xx)
    - redirect (3xx)
    - client_error (4xx)
    - server_error (5xx)
    - rate_limited (429)
    - blocked (WAF)
    - interesting
    - timeout
    """
    try:
        # Normalize responses
        normalized_responses = []
        for resp in request.responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
                "error": resp.get("error", ""),
                "flags": resp.get("flags", []),
                "interesting": resp.get("interesting", False),
            }
            normalized_responses.append(normalized)
        
        categories = categorize_responses(normalized_responses)
        
        return {
            "categories": categories,
            "summary": {
                category: len(ids) for category, ids in categories.items()
            },
        }
    except Exception as e:
        logger.exception(f"Categorization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _normalize_responses(responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize response format for detection engine."""
    normalized = []
    for resp in responses:
        norm = {
            "id": resp.get("id"),
            "payload": resp.get("payload", ""),
            "body": resp.get("body") or resp.get("response_body", ""),
            "headers": resp.get("headers") or resp.get("response_headers", {}),
            "status_code": resp.get("status_code", 0),
            "response_time": resp.get("response_time", 0),
            "content_length": resp.get("content_length") or len(resp.get("body") or resp.get("response_body", "")),
            "error": resp.get("error", ""),
            "flags": resp.get("flags", []),
            "interesting": resp.get("interesting", False),
        }
        normalized.append(norm)
    return normalized


@router.post("/smart-detect/auto-analyze")
async def smart_auto_analyze(request: AutoAnalyzeRequest):
    """
    Perform comprehensive automatic analysis on fuzzing responses.
    
    Combines vulnerability detection, anomaly detection, categorization,
    and optionally differential analysis into a single request.
    """
    try:
        # Normalize all responses once
        normalized = _normalize_responses(request.responses)
        
        result = {
            "responses_analyzed": len(normalized),
        }
        
        # Vulnerability detection
        if request.detect_vulnerabilities:
            findings = detect_vulnerabilities(normalized)
            result["vulnerabilities"] = {
                "findings": [f.to_dict() for f in findings],
                "total": len(findings),
                "by_severity": {
                    "critical": sum(1 for f in findings if f.severity.value == "critical"),
                    "high": sum(1 for f in findings if f.severity.value == "high"),
                    "medium": sum(1 for f in findings if f.severity.value == "medium"),
                    "low": sum(1 for f in findings if f.severity.value == "low"),
                    "info": sum(1 for f in findings if f.severity.value == "info"),
                },
            }
        
        # Anomaly detection
        if request.detect_anomalies:
            anomalies = detect_anomalies(normalized)
            result["anomalies"] = {
                "items": [a.to_dict() for a in anomalies],
                "total": len(anomalies),
                "by_type": _count_by_field(anomalies, lambda a: a.anomaly_type),
            }
        
        # Categorization
        if request.categorize:
            categories = categorize_responses(normalized)
            result["categories"] = {
                "groups": categories,
                "summary": {cat: len(ids) for cat, ids in categories.items()},
            }
        
        # Differential analysis
        if request.differential and len(normalized) > request.baseline_index:
            baseline = normalized[request.baseline_index]
            test_responses = [r for i, r in enumerate(normalized) if i != request.baseline_index]
            diff_results = differential_analysis(baseline, test_responses)
            interesting = [r for r in diff_results if r.get("potentially_interesting")]
            result["differential"] = {
                "results": diff_results[:50],  # Limit output
                "interesting_count": len(interesting),
            }
        
        # Create summary
        findings = result.get("vulnerabilities", {}).get("findings", [])
        anomaly_list = result.get("anomalies", {}).get("items", [])
        
        # Calculate risk score
        severity_weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}
        risk_score = sum(
            severity_weights.get(f.get("severity", "info"), 0)
            for f in findings
        )
        risk_score = min(100, risk_score)
        
        result["summary"] = {
            "risk_score": risk_score,
            "risk_level": (
                "critical" if risk_score >= 70 else
                "high" if risk_score >= 40 else
                "medium" if risk_score >= 20 else
                "low" if risk_score >= 5 else
                "info"
            ),
            "findings_count": len(findings),
            "anomalies_count": len(anomaly_list),
            "interesting_count": len(result.get("categories", {}).get("groups", {}).get("interesting", [])),
        }
        
        return result
    except Exception as e:
        logger.exception(f"Auto analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sessions/{session_id}/auto-analyze")
async def analyze_session(session_id: int, db: Session = Depends(get_db)):
    """
    Run automatic analysis on a saved session's results and update the session.
    """
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        if not session.results:
            raise HTTPException(status_code=400, detail="Session has no results to analyze")
        
        responses = session.results
        
        # Run all detections
        findings = detect_vulnerabilities(responses)
        anomalies = detect_anomalies(responses)
        categories = categorize_responses(responses)
        
        # Create analysis results
        analysis = {
            "vulnerabilities": {
                "findings": [f.to_dict() for f in findings],
                "total": len(findings),
                "by_severity": {
                    "critical": sum(1 for f in findings if f.severity.value == "critical"),
                    "high": sum(1 for f in findings if f.severity.value == "high"),
                    "medium": sum(1 for f in findings if f.severity.value == "medium"),
                    "low": sum(1 for f in findings if f.severity.value == "low"),
                    "info": sum(1 for f in findings if f.severity.value == "info"),
                },
            },
            "anomalies": {
                "items": [a.to_dict() for a in anomalies],
                "total": len(anomalies),
            },
            "categories": {
                "groups": categories,
                "summary": {cat: len(ids) for cat, ids in categories.items()},
            },
            "analyzed_at": datetime.utcnow().isoformat(),
        }
        
        # Calculate risk
        severity_weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}
        risk_score = min(100, sum(
            severity_weights.get(f.severity.value, 0) for f in findings
        ))
        
        analysis["summary"] = {
            "risk_score": risk_score,
            "risk_level": (
                "critical" if risk_score >= 70 else
                "high" if risk_score >= 40 else
                "medium" if risk_score >= 20 else
                "low" if risk_score >= 5 else
                "info"
            ),
        }
        
        # Update session
        session.findings = [f.to_dict() for f in findings]
        session.analysis = analysis
        db.commit()
        
        return {
            "session_id": session_id,
            "analysis": analysis,
            "message": "Session analyzed successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Session analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _count_by_field(items, field_getter):
    """Helper to count items by a field value."""
    counts = {}
    for item in items:
        value = field_getter(item)
        counts[value] = counts.get(value, 0) + 1
    return counts