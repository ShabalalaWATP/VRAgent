"""
OpenAPI Import and OOB Callback Router

Provides API endpoints for:
- OpenAPI/Swagger specification import and parsing
- Out-of-band callback handling for blind vulnerability detection
- Fuzzing target generation from API specs
"""

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, Response, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from backend.services.openapi_parser_service import (
    OpenAPIParser,
    ParsedAPISpec,
    parse_openapi_content,
    parse_openapi_url,
    discover_openapi_spec,
    COMMON_SPEC_PATHS,
)
from backend.services.oob_callback_service import (
    OOBCallbackManager,
    OOBPayloadGenerator,
    OOBCallbackStore,
    CallbackEvent,
    CallbackToken,
    VulnerabilityType,
    get_callback_store,
    create_callback_manager,
    create_payload_generator,
)
from backend.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api-tools", tags=["api-tools"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ParseURLRequest(BaseModel):
    """Request to parse OpenAPI spec from URL."""
    url: str = Field(..., description="URL to the OpenAPI/Swagger specification")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Optional headers for the request")
    base_url: Optional[str] = Field(default=None, description="Override base URL for endpoints")


class ParseContentRequest(BaseModel):
    """Request to parse OpenAPI spec from raw content."""
    content: str = Field(..., description="OpenAPI/Swagger specification content (JSON or YAML)")
    base_url: str = Field(default="", description="Base URL for endpoints")


class DiscoverSpecRequest(BaseModel):
    """Request to discover OpenAPI spec at a target."""
    base_url: str = Field(..., description="Base URL to probe for OpenAPI specs")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Optional headers")


class GenerateFuzzTargetsRequest(BaseModel):
    """Request to generate fuzzing targets from spec."""
    spec_id: str = Field(..., description="ID of the parsed spec")
    tags: Optional[List[str]] = Field(default=None, description="Filter by tags")
    methods: Optional[List[str]] = Field(default=None, description="Filter by HTTP methods")
    exclude_deprecated: bool = Field(default=True, description="Exclude deprecated endpoints")


class OOBConfigRequest(BaseModel):
    """Request to configure OOB callback settings."""
    callback_domain: str = Field(..., description="Domain for callbacks")
    callback_port: int = Field(default=8080, description="Port for callbacks")
    callback_protocol: str = Field(default="http", description="Protocol (http/https)")
    token_expiry_hours: int = Field(default=24, description="Token expiry in hours")


class GenerateOOBPayloadsRequest(BaseModel):
    """Request to generate OOB payloads."""
    scan_id: str = Field(..., description="Scan identifier")
    endpoint: str = Field(..., description="Target endpoint")
    parameter: str = Field(..., description="Target parameter")
    vulnerability_types: Optional[List[str]] = Field(
        default=None,
        description="Types of vulnerabilities to generate payloads for"
    )


class CheckCallbacksRequest(BaseModel):
    """Request to check for callbacks."""
    scan_id: Optional[str] = Field(default=None, description="Filter by scan ID")
    token: Optional[str] = Field(default=None, description="Filter by token")
    limit: int = Field(default=100, description="Maximum events to return")


# =============================================================================
# IN-MEMORY SPEC STORAGE
# =============================================================================

# Store parsed specs in memory (use database in production)
_parsed_specs: Dict[str, ParsedAPISpec] = {}


def _store_spec(spec: ParsedAPISpec) -> str:
    """Store a parsed spec and return its ID."""
    _parsed_specs[spec.id] = spec
    return spec.id


def _get_spec(spec_id: str) -> Optional[ParsedAPISpec]:
    """Retrieve a stored spec by ID."""
    return _parsed_specs.get(spec_id)


def _list_specs() -> List[Dict[str, Any]]:
    """List all stored specs (summary only)."""
    return [
        {
            "id": spec.id,
            "title": spec.title,
            "version": spec.version,
            "spec_version": spec.spec_version.value,
            "endpoints_count": len(spec.endpoints),
            "parsed_at": spec.parsed_at,
        }
        for spec in _parsed_specs.values()
    ]


# =============================================================================
# OPENAPI IMPORT ENDPOINTS
# =============================================================================

@router.post("/openapi/parse-url")
async def parse_openapi_from_url(request: ParseURLRequest) -> Dict[str, Any]:
    """
    Parse an OpenAPI/Swagger specification from a URL.
    
    Supports:
    - OpenAPI 3.0.x and 3.1.x
    - Swagger 2.0
    - JSON and YAML formats
    """
    try:
        parser = OpenAPIParser()
        spec = await parser.parse_url(request.url, request.headers)
        
        if request.base_url:
            spec.base_url = request.base_url
        
        if spec.errors and not spec.endpoints:
            raise HTTPException(status_code=400, detail=spec.errors)
        
        _store_spec(spec)
        
        return {
            "success": True,
            "spec_id": spec.id,
            "title": spec.title,
            "version": spec.version,
            "spec_version": spec.spec_version.value,
            "base_url": spec.base_url,
            "endpoints_count": len(spec.endpoints),
            "security_schemes_count": len(spec.security_schemes),
            "warnings": spec.warnings,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to parse OpenAPI spec from URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/openapi/parse-content")
async def parse_openapi_from_content(request: ParseContentRequest) -> Dict[str, Any]:
    """
    Parse an OpenAPI/Swagger specification from raw content.
    
    Accepts JSON or YAML content.
    """
    try:
        spec = parse_openapi_content(request.content, request.base_url)
        
        if spec.errors and not spec.endpoints:
            raise HTTPException(status_code=400, detail=spec.errors)
        
        _store_spec(spec)
        
        return {
            "success": True,
            "spec_id": spec.id,
            "title": spec.title,
            "version": spec.version,
            "spec_version": spec.spec_version.value,
            "base_url": spec.base_url,
            "endpoints_count": len(spec.endpoints),
            "security_schemes_count": len(spec.security_schemes),
            "warnings": spec.warnings,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to parse OpenAPI content: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/openapi/upload")
async def upload_openapi_spec(
    file: UploadFile = File(...),
    base_url: str = Form(default=""),
) -> Dict[str, Any]:
    """
    Upload and parse an OpenAPI/Swagger specification file.
    
    Accepts .json, .yaml, or .yml files.
    """
    try:
        content = (await file.read()).decode("utf-8")
        spec = parse_openapi_content(content, base_url)
        
        if spec.errors and not spec.endpoints:
            raise HTTPException(status_code=400, detail=spec.errors)
        
        _store_spec(spec)
        
        return {
            "success": True,
            "spec_id": spec.id,
            "filename": file.filename,
            "title": spec.title,
            "version": spec.version,
            "spec_version": spec.spec_version.value,
            "base_url": spec.base_url,
            "endpoints_count": len(spec.endpoints),
            "security_schemes_count": len(spec.security_schemes),
            "warnings": spec.warnings,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to parse uploaded OpenAPI spec: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/openapi/discover")
async def discover_openapi_at_target(request: DiscoverSpecRequest) -> Dict[str, Any]:
    """
    Attempt to discover an OpenAPI specification at common paths.
    
    Probes paths like /openapi.json, /swagger.json, /api-docs, etc.
    """
    try:
        spec_url = await discover_openapi_spec(request.base_url, request.headers)
        
        if not spec_url:
            return {
                "success": False,
                "message": "No OpenAPI specification found at common paths",
                "paths_checked": COMMON_SPEC_PATHS,
            }
        
        # Parse the discovered spec
        parser = OpenAPIParser()
        spec = await parser.parse_url(spec_url, request.headers)
        
        _store_spec(spec)
        
        return {
            "success": True,
            "discovered_url": spec_url,
            "spec_id": spec.id,
            "title": spec.title,
            "version": spec.version,
            "spec_version": spec.spec_version.value,
            "base_url": spec.base_url,
            "endpoints_count": len(spec.endpoints),
        }
        
    except Exception as e:
        logger.error(f"Failed to discover OpenAPI spec: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/openapi/specs")
async def list_parsed_specs() -> Dict[str, Any]:
    """List all parsed OpenAPI specifications."""
    return {
        "specs": _list_specs(),
        "count": len(_parsed_specs),
    }


@router.get("/openapi/specs/{spec_id}")
async def get_parsed_spec(spec_id: str) -> Dict[str, Any]:
    """Get full details of a parsed specification."""
    spec = _get_spec(spec_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Specification not found")
    
    return spec.to_dict()


@router.get("/openapi/specs/{spec_id}/endpoints")
async def get_spec_endpoints(
    spec_id: str,
    tag: Optional[str] = Query(default=None),
    method: Optional[str] = Query(default=None),
    include_deprecated: bool = Query(default=False),
) -> Dict[str, Any]:
    """Get endpoints from a parsed specification with filtering."""
    spec = _get_spec(spec_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Specification not found")
    
    endpoints = spec.endpoints
    
    if tag:
        endpoints = [e for e in endpoints if tag in e.tags]
    
    if method:
        endpoints = [e for e in endpoints if e.method.upper() == method.upper()]
    
    if not include_deprecated:
        endpoints = [e for e in endpoints if not e.deprecated]
    
    return {
        "spec_id": spec_id,
        "count": len(endpoints),
        "endpoints": [e.to_dict() for e in endpoints],
    }


@router.post("/openapi/specs/{spec_id}/generate-targets")
async def generate_fuzz_targets(spec_id: str) -> Dict[str, Any]:
    """
    Generate fuzzing targets from a parsed specification.
    
    Creates structured targets suitable for the agentic fuzzer.
    """
    spec = _get_spec(spec_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Specification not found")
    
    targets = spec.generate_fuzzing_targets()
    
    return {
        "spec_id": spec_id,
        "spec_title": spec.title,
        "base_url": spec.base_url,
        "targets_count": len(targets),
        "targets": targets,
    }


@router.delete("/openapi/specs/{spec_id}")
async def delete_parsed_spec(spec_id: str) -> Dict[str, Any]:
    """Delete a parsed specification."""
    if spec_id not in _parsed_specs:
        raise HTTPException(status_code=404, detail="Specification not found")
    
    del _parsed_specs[spec_id]
    
    return {"success": True, "deleted_id": spec_id}


# =============================================================================
# OOB CALLBACK ENDPOINTS
# =============================================================================

# Default callback manager configuration
_callback_config = {
    "domain": "localhost",
    "port": 8080,
    "protocol": "http",
    "expiry_hours": 24,
}


def _get_callback_manager() -> OOBCallbackManager:
    """Get configured callback manager."""
    return create_callback_manager(
        domain=_callback_config["domain"],
        port=_callback_config["port"],
        protocol=_callback_config["protocol"],
    )


@router.post("/oob/configure")
async def configure_oob_callbacks(request: OOBConfigRequest) -> Dict[str, Any]:
    """
    Configure OOB callback server settings.
    
    Set the domain, port, and protocol used for callback URLs.
    """
    _callback_config["domain"] = request.callback_domain
    _callback_config["port"] = request.callback_port
    _callback_config["protocol"] = request.callback_protocol
    _callback_config["expiry_hours"] = request.token_expiry_hours
    
    return {
        "success": True,
        "config": _callback_config,
        "sample_callback_url": f"{request.callback_protocol}://{request.callback_domain}:{request.callback_port}/callback/{{token}}",
    }


@router.get("/oob/config")
async def get_oob_config() -> Dict[str, Any]:
    """Get current OOB callback configuration."""
    return {
        "config": _callback_config,
        "sample_callback_url": f"{_callback_config['protocol']}://{_callback_config['domain']}:{_callback_config['port']}/callback/{{token}}",
    }


@router.post("/oob/generate-payloads")
async def generate_oob_payloads(request: GenerateOOBPayloadsRequest) -> Dict[str, Any]:
    """
    Generate OOB payloads for blind vulnerability detection.
    
    Creates payloads with embedded callback URLs/domains for:
    - SSRF
    - XXE
    - RCE
    - Blind SQLi
    - SSTI
    - LFI
    """
    manager = _get_callback_manager()
    generator = create_payload_generator(manager)
    
    # Determine which vulnerability types to generate
    vuln_types = []
    if request.vulnerability_types:
        for vt in request.vulnerability_types:
            try:
                vuln_types.append(VulnerabilityType(vt.lower()))
            except ValueError:
                pass
    else:
        # Generate all types
        vuln_types = [
            VulnerabilityType.SSRF,
            VulnerabilityType.XXE,
            VulnerabilityType.RCE,
            VulnerabilityType.BLIND_SQLI,
            VulnerabilityType.SSTI,
            VulnerabilityType.LFI,
        ]
    
    result = {}
    
    for vt in vuln_types:
        method_map = {
            VulnerabilityType.SSRF: generator.get_ssrf_payloads,
            VulnerabilityType.XXE: generator.get_xxe_payloads,
            VulnerabilityType.RCE: generator.get_rce_payloads,
            VulnerabilityType.BLIND_SQLI: generator.get_blind_sqli_payloads,
            VulnerabilityType.SSTI: generator.get_ssti_payloads,
            VulnerabilityType.LFI: generator.get_lfi_payloads,
        }
        
        if vt in method_map:
            payloads = method_map[vt](
                request.scan_id,
                request.endpoint,
                request.parameter,
            )
            result[vt.value] = [
                {
                    "payload": payload,
                    "token": token.token,
                    "callback_url": manager.get_callback_url(token),
                }
                for payload, token in payloads
            ]
    
    return {
        "scan_id": request.scan_id,
        "endpoint": request.endpoint,
        "parameter": request.parameter,
        "payloads": result,
        "total_payloads": sum(len(p) for p in result.values()),
    }


@router.get("/oob/events")
async def get_callback_events(
    scan_id: Optional[str] = Query(default=None),
    token: Optional[str] = Query(default=None),
    limit: int = Query(default=100, le=1000),
) -> Dict[str, Any]:
    """
    Get received callback events.
    
    Filter by scan_id or specific token.
    """
    store = get_callback_store()
    
    if token:
        events = store.get_events_by_token(token)
    elif scan_id:
        events = store.get_events_by_scan(scan_id)
    else:
        events = store.get_recent_events(limit)
    
    return {
        "count": len(events),
        "events": [e.to_dict() for e in events[:limit]],
    }


@router.get("/oob/check/{scan_id}")
async def check_scan_callbacks(scan_id: str) -> Dict[str, Any]:
    """
    Check if any callbacks were received for a specific scan.
    
    Returns a summary of findings by vulnerability type.
    """
    store = get_callback_store()
    events = store.get_events_by_scan(scan_id)
    
    # Group by vulnerability type
    findings_by_type: Dict[str, List[Dict]] = {}
    for event in events:
        vt = event.correlated_payload_type.value if event.correlated_payload_type else "unknown"
        if vt not in findings_by_type:
            findings_by_type[vt] = []
        findings_by_type[vt].append({
            "token": event.token,
            "endpoint": event.correlated_endpoint,
            "parameter": event.correlated_parameter,
            "callback_type": event.callback_type.value,
            "source_ip": event.source_ip,
            "timestamp": event.timestamp.isoformat(),
        })
    
    return {
        "scan_id": scan_id,
        "has_callbacks": len(events) > 0,
        "total_callbacks": len(events),
        "findings_by_type": findings_by_type,
        "vulnerability_types_detected": list(findings_by_type.keys()),
    }


@router.get("/oob/stats")
async def get_oob_stats() -> Dict[str, Any]:
    """Get OOB callback server statistics."""
    store = get_callback_store()
    return store.get_stats()


# =============================================================================
# CALLBACK RECEIVER ENDPOINTS
# These endpoints receive the actual callbacks from targets
# =============================================================================

@router.api_route(
    "/callback/{token}",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
async def receive_callback(token: str, request: Request) -> Response:
    """
    Receive HTTP callbacks from targets.
    
    This endpoint captures callbacks triggered by OOB payloads.
    Supports all HTTP methods.
    """
    manager = _get_callback_manager()
    
    try:
        event = await manager.process_http_callback(request, token)
        
        logger.info(
            f"OOB callback received: token={token}, "
            f"type={event.callback_type.value}, "
            f"source={event.source_ip}, "
            f"scan={event.correlated_scan_id}"
        )
        
        # Return a minimal response
        return Response(
            content="OK",
            status_code=200,
            headers={
                "X-Callback-Received": "true",
                "X-Callback-Token": token,
            }
        )
        
    except Exception as e:
        logger.error(f"Error processing callback: {e}")
        return Response(content="OK", status_code=200)


@router.api_route(
    "/callback",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
async def receive_callback_query(request: Request) -> Response:
    """
    Receive HTTP callbacks with token in query string.
    
    Alternative callback endpoint for payloads that use query params.
    """
    manager = _get_callback_manager()
    token = request.query_params.get("token", "")
    
    try:
        event = await manager.process_http_callback(request, token)
        
        logger.info(
            f"OOB callback received (query): token={token}, "
            f"type={event.callback_type.value}, "
            f"source={event.source_ip}"
        )
        
        return Response(
            content="OK",
            status_code=200,
            headers={"X-Callback-Received": "true"}
        )
        
    except Exception as e:
        logger.error(f"Error processing callback: {e}")
        return Response(content="OK", status_code=200)


# =============================================================================
# COMBINED IMPORT + FUZZ WORKFLOW
# =============================================================================

@router.post("/openapi/import-and-scan")
async def import_and_generate_scan(request: ParseURLRequest) -> Dict[str, Any]:
    """
    Import an OpenAPI spec and generate a complete scan configuration.
    
    One-step workflow that:
    1. Parses the OpenAPI specification
    2. Generates fuzzing targets
    3. Creates OOB tokens for blind vulnerability detection
    """
    try:
        # Parse the spec
        parser = OpenAPIParser()
        spec = await parser.parse_url(request.url, request.headers)
        
        if request.base_url:
            spec.base_url = request.base_url
        
        if spec.errors and not spec.endpoints:
            raise HTTPException(status_code=400, detail=spec.errors)
        
        _store_spec(spec)
        
        # Generate fuzzing targets
        targets = spec.generate_fuzzing_targets()
        
        # Generate OOB tokens for each target
        manager = _get_callback_manager()
        scan_id = spec.id  # Use spec ID as scan ID
        
        targets_with_oob = []
        for target in targets:
            target_oob = dict(target)
            target_oob["oob_tokens"] = []
            
            # Generate SSRF token for URL parameters
            for param in target.get("parameters", []):
                token = manager.generate_token(
                    scan_id=scan_id,
                    endpoint=target["url"],
                    parameter=param,
                    payload_type=VulnerabilityType.SSRF,
                    payload="auto-generated",
                )
                target_oob["oob_tokens"].append({
                    "parameter": param,
                    "token": token.token,
                    "callback_url": manager.get_callback_url(token),
                })
            
            targets_with_oob.append(target_oob)
        
        return {
            "success": True,
            "spec_id": spec.id,
            "spec_title": spec.title,
            "base_url": spec.base_url,
            "endpoints_count": len(spec.endpoints),
            "targets_count": len(targets_with_oob),
            "scan_id": scan_id,
            "targets": targets_with_oob,
            "security_schemes": [s.to_dict() for s in spec.security_schemes],
            "oob_callback_base": f"{_callback_config['protocol']}://{_callback_config['domain']}:{_callback_config['port']}/callback",
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to import and generate scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))
