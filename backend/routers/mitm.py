"""
Man-in-the-Middle Workbench Router
API endpoints for MITM proxy management.
"""

import json

import asyncio
from fastapi import APIRouter, HTTPException, Query, Path, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional, Dict, List, Any

from ..core.auth import get_current_active_user
from ..models.models import User
from ..services.mitm_service import (
    mitm_service, 
    analyze_mitm_traffic,
    generate_mitm_markdown_report,
    generate_mitm_pdf_report,
    generate_mitm_docx_report,
    generate_mitm_pcap,
    create_rule_from_natural_language,
    get_ai_traffic_suggestions,
    network_throttler,
    macro_recorder,
    har_exporter,
    protocol_decoder_manager,
    session_sharing_manager,
    ThrottleProfile,
    Macro,
    MacroStep,
    # AI-powered analysis
    analyze_traffic_sensitive_data,
    analyze_traffic_injection_points,
    query_traffic_natural_language,
    generate_security_test_cases,
    generate_vulnerability_finding
)
from ..core.mitm_ws_manager import mitm_stream_manager

router = APIRouter(prefix="/mitm", tags=["MITM Workbench"])


class ProxyConfig(BaseModel):
    proxy_id: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    target_host: str = "localhost"
    target_port: int = 80
    mode: str = "passthrough"  # passthrough, intercept, auto_modify
    tls_enabled: bool = False


class RuleConfig(BaseModel):
    name: str
    enabled: bool = True
    priority: int = 100
    group: Optional[str] = None
    match_host: Optional[str] = None
    match_path: Optional[str] = None
    match_method: Optional[str] = None
    match_content_type: Optional[str] = None
    match_body: Optional[str] = None
    match_header: Optional[Dict[str, str]] = None
    match_status_code: Optional[int] = None
    match_direction: str = "both"  # request, response, both
    match_query: Optional[Dict[str, str]] = None
    action: str = "modify"  # modify, drop, delay
    modify_headers: Optional[Dict[str, str]] = None
    remove_headers: Optional[List[str]] = None
    modify_body: Optional[str] = None
    body_find_replace: Optional[Dict[str, str]] = None
    body_find_replace_regex: bool = False
    json_path_edits: Optional[List[Dict[str, Any]]] = None
    modify_status_code: Optional[int] = None
    modify_path: Optional[str] = None
    delay_ms: int = 0


class TrafficUpdate(BaseModel):
    """Update notes or tags for a traffic entry."""
    notes: Optional[str] = None
    tags: Optional[List[str]] = None


class SessionCreateRequest(BaseModel):
    """Create a named traffic session snapshot."""
    name: Optional[str] = None


class ReplayRequest(BaseModel):
    """Replay request overrides."""
    method: Optional[str] = None
    path: Optional[str] = None
    body: Optional[Any] = None
    add_headers: Optional[Dict[str, str]] = None
    remove_headers: Optional[List[str]] = None
    base_url: Optional[str] = None
    timeout: Optional[int] = 20
    verify_tls: Optional[bool] = False


@router.post("/proxies")
async def create_proxy(config: ProxyConfig, current_user: User = Depends(get_current_active_user)):
    """Create a new MITM proxy instance"""
    try:
        result = mitm_service.create_proxy(
            proxy_id=config.proxy_id,
            listen_host=config.listen_host,
            listen_port=config.listen_port,
            target_host=config.target_host,
            target_port=config.target_port,
            mode=config.mode,
            tls_enabled=config.tls_enabled
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/proxies")
async def list_proxies():
    """List all MITM proxy instances"""
    return mitm_service.list_proxies()


@router.get("/proxies/{proxy_id}")
async def get_proxy_status(proxy_id: str):
    """Get status and stats for a proxy"""
    try:
        return mitm_service.get_proxy_status(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/proxies/{proxy_id}/start")
async def start_proxy(proxy_id: str):
    """Start a proxy"""
    try:
        return mitm_service.start_proxy(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/proxies/{proxy_id}/stop")
async def stop_proxy(proxy_id: str):
    """Stop a proxy"""
    try:
        return mitm_service.stop_proxy(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/proxies/{proxy_id}")
async def delete_proxy(proxy_id: str):
    """Delete a proxy"""
    try:
        return mitm_service.delete_proxy(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/proxies/{proxy_id}/mode")
async def set_proxy_mode(proxy_id: str, mode: str = Query(...)):
    """Set proxy interception mode"""
    try:
        return mitm_service.set_mode(proxy_id, mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/proxies/{proxy_id}/traffic")
async def get_traffic(
    proxy_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    start: Optional[int] = Query(None, ge=0),
    end: Optional[int] = Query(None, ge=0)
):
    """Get intercepted traffic for a proxy"""
    try:
        if start is not None:
            return mitm_service.get_traffic_range(proxy_id, start, end)
        return mitm_service.get_traffic(proxy_id, limit, offset)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/proxies/{proxy_id}/traffic")
async def clear_traffic(proxy_id: str):
    """Clear traffic log for a proxy"""
    try:
        return mitm_service.clear_traffic(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/proxies/{proxy_id}/traffic/export")
async def export_traffic(
    proxy_id: str,
    format: str = Query("json", regex="^(json|pcap)$"),
    limit: int = Query(1000, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    start: Optional[int] = Query(None, ge=0),
    end: Optional[int] = Query(None, ge=0)
):
    """Export traffic in JSON or PCAP format."""
    try:
        if start is not None:
            result = mitm_service.get_traffic_range(proxy_id, start, end)
        else:
            result = mitm_service.get_traffic(proxy_id, limit, offset)
        entries = result.get("entries", [])

        if format == "json":
            content = json.dumps(entries, ensure_ascii=True, indent=2)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=mitm-traffic-{proxy_id}.json"}
            )

        pcap_content = generate_mitm_pcap(entries)
        return Response(
            content=pcap_content,
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f"attachment; filename=mitm-traffic-{proxy_id}.pcap"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/ws/{proxy_id}")
async def mitm_stream(websocket: WebSocket, proxy_id: str):
    """WebSocket stream for real-time MITM traffic updates."""
    mitm_stream_manager.set_loop(asyncio.get_running_loop())
    await mitm_stream_manager.connect(websocket, proxy_id)
    try:
        status = mitm_service.get_proxy_status(proxy_id)
        traffic = mitm_service.get_traffic(proxy_id, limit=200, offset=0)
        rules = mitm_service.get_rules(proxy_id)
        await websocket.send_json({
            "type": "init",
            "status": status,
            "traffic": traffic,
            "rules": rules
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        await mitm_stream_manager.disconnect(websocket, proxy_id)


@router.put("/proxies/{proxy_id}/traffic/{entry_id}")
async def update_traffic_entry(proxy_id: str, entry_id: str, update: TrafficUpdate):
    """Update notes or tags for a traffic entry"""
    try:
        return mitm_service.update_traffic_entry(
            proxy_id,
            entry_id,
            notes=update.notes,
            tags=update.tags
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/proxies/{proxy_id}/sessions")
async def list_sessions(proxy_id: str):
    """List saved traffic sessions."""
    try:
        return mitm_service.list_sessions(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/proxies/{proxy_id}/sessions")
async def create_session(proxy_id: str, payload: SessionCreateRequest):
    """Save current traffic log as a session."""
    try:
        return mitm_service.save_session(proxy_id, payload.name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/proxies/{proxy_id}/sessions/{session_id}")
async def get_session(proxy_id: str, session_id: str, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Get a saved session's traffic entries."""
    try:
        return mitm_service.load_session(proxy_id, session_id, limit, offset)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/proxies/{proxy_id}/replay/{entry_id}")
async def replay_traffic_entry(proxy_id: str, entry_id: str, payload: ReplayRequest):
    """Replay a captured request with optional overrides."""
    try:
        return await mitm_service.replay_entry(proxy_id, entry_id, payload.dict(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/proxies/{proxy_id}/rules")
async def add_rule(proxy_id: str, rule: RuleConfig):
    """Add an interception rule to a proxy"""
    try:
        return mitm_service.add_rule(proxy_id, rule.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/proxies/{proxy_id}/rules")
async def get_rules(proxy_id: str):
    """Get all rules for a proxy"""
    try:
        return mitm_service.get_rules(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/proxies/{proxy_id}/rules/{rule_id}")
async def remove_rule(proxy_id: str, rule_id: str):
    """Remove a rule from a proxy"""
    try:
        return mitm_service.remove_rule(proxy_id, rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/proxies/{proxy_id}/rules/{rule_id}/toggle")
async def toggle_rule(proxy_id: str, rule_id: str, enabled: bool = Query(...)):
    """Enable/disable a rule"""
    try:
        return mitm_service.toggle_rule(proxy_id, rule_id, enabled)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/proxies/{proxy_id}/rules/group/{group}/toggle")
async def toggle_rule_group(proxy_id: str, group: str, enabled: bool = Query(...)):
    """Enable/disable all rules in a group"""
    try:
        return mitm_service.toggle_rule_group(proxy_id, group, enabled)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Preset rules for common scenarios
PRESET_RULES = {
    "remove_csp": {
        "name": "Remove Content-Security-Policy",
        "match_direction": "response",
        "action": "modify",
        "remove_headers": ["Content-Security-Policy", "X-Content-Security-Policy"]
    },
    "remove_cors": {
        "name": "Bypass CORS",
        "match_direction": "response",
        "action": "modify",
        "modify_headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*"
        }
    },
    "downgrade_https": {
        "name": "Remove HSTS",
        "match_direction": "response",
        "action": "modify",
        "remove_headers": ["Strict-Transport-Security"]
    },
    "add_debug_header": {
        "name": "Add Debug Header",
        "match_direction": "request",
        "action": "modify",
        "modify_headers": {
            "X-Debug": "true",
            "X-Forwarded-For": "127.0.0.1"
        }
    },
    "slow_response": {
        "name": "Slow Response (2s)",
        "match_direction": "response",
        "action": "delay",
        "delay_ms": 2000
    },
    "inject_script": {
        "name": "Inject Script Tag",
        "match_direction": "response",
        "match_content_type": "text/html",
        "action": "modify",
        "body_find_replace": {
            "</body>": "<script>console.log('MITM Injected');</script></body>"
        }
    },
    "modify_json_response": {
        "name": "Modify JSON Response",
        "match_direction": "response",
        "match_content_type": "application/json",
        "action": "modify",
        "body_find_replace": {
            '"success":false': '"success":true',
            '"authorized":false': '"authorized":true'
        }
    },
    "block_analytics": {
        "name": "Block Analytics",
        "match_direction": "request",
        "match_host": "(google-analytics|googletagmanager|facebook|analytics)",
        "action": "drop"
    }
}


@router.get("/presets")
async def get_preset_rules():
    """Get available preset rules"""
    return [
        {"id": k, **v}
        for k, v in PRESET_RULES.items()
    ]


@router.post("/proxies/{proxy_id}/presets/{preset_id}")
async def apply_preset_rule(proxy_id: str, preset_id: str):
    """Apply a preset rule to a proxy"""
    if preset_id not in PRESET_RULES:
        raise HTTPException(status_code=404, detail=f"Preset {preset_id} not found")
    
    try:
        return mitm_service.add_rule(proxy_id, PRESET_RULES[preset_id])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================================
# AI Analysis Endpoints
# ============================================================================

@router.post("/proxies/{proxy_id}/analyze")
async def analyze_proxy_traffic(proxy_id: str):
    """
    AI-powered analysis of intercepted traffic.
    
    Analyzes traffic for:
    - Security vulnerabilities
    - Sensitive data exposure  
    - Authentication weaknesses
    - API security issues
    - Missing security headers
    """
    try:
        proxy = mitm_service._get_proxy(proxy_id)
        
        # Get traffic log
        traffic_log = mitm_service.get_traffic(proxy_id, limit=200, offset=0).get("entries", [])
        
        # Get rules
        rules = mitm_service.get_rules(proxy_id)
        
        # Get proxy config
        proxy_config = {
            "listen_host": proxy.listen_host,
            "listen_port": proxy.listen_port,
            "target_host": proxy.target_host,
            "target_port": proxy.target_port,
            "mode": proxy.mode.value,
            "tls_enabled": proxy.tls_enabled
        }
        
        # Run analysis
        analysis = await analyze_mitm_traffic(traffic_log, rules, proxy_config)
        
        return analysis
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Export Endpoints
# ============================================================================

@router.get("/proxies/{proxy_id}/export/{format}")
async def export_proxy_analysis(
    proxy_id: str, 
    format: str = Path(..., regex="^(markdown|pdf|docx)$")
):
    """
    Export MITM analysis report in various formats.
    
    Formats:
    - markdown: Markdown text report
    - pdf: PDF document
    - docx: Microsoft Word document
    """
    try:
        proxy = mitm_service._get_proxy(proxy_id)
        
        # Get traffic log
        traffic_log = mitm_service.get_traffic(proxy_id, limit=200, offset=0).get("entries", [])
        
        # Get rules
        rules = mitm_service.get_rules(proxy_id)
        
        # Get proxy config
        proxy_config = {
            "proxy_id": proxy_id,
            "listen_host": proxy.listen_host,
            "listen_port": proxy.listen_port,
            "target_host": proxy.target_host,
            "target_port": proxy.target_port,
            "mode": proxy.mode.value,
            "tls_enabled": proxy.tls_enabled
        }
        
        # Run analysis first
        analysis = await analyze_mitm_traffic(traffic_log, rules, proxy_config)
        
        # Generate report based on format
        if format == "markdown":
            content = generate_mitm_markdown_report(proxy_config, traffic_log, rules, analysis)
            return Response(
                content=content,
                media_type="text/markdown",
                headers={"Content-Disposition": f"attachment; filename=mitm-report-{proxy_id}.md"}
            )
        
        elif format == "pdf":
            content = generate_mitm_pdf_report(proxy_config, traffic_log, rules, analysis)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=mitm-report-{proxy_id}.pdf"}
            )
        
        elif format == "docx":
            content = generate_mitm_docx_report(proxy_config, traffic_log, rules, analysis)
            return Response(
                content=content,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f"attachment; filename=mitm-report-{proxy_id}.docx"}
            )
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Guided Setup Endpoint
# ============================================================================

@router.get("/guided-setup")
async def get_guided_setup():
    """
    Get guided setup information for beginners.
    
    Returns step-by-step instructions for setting up MITM proxies.
    """
    return {
        "title": "Man-in-the-Middle Workbench Setup Guide",
        "description": "Learn to intercept and analyze HTTP traffic between application components",
        "difficulty": "Beginner",
        "estimated_time": "10-15 minutes",
        "steps": [
            {
                "step": 1,
                "title": "Understand What MITM Does",
                "description": "A Man-in-the-Middle proxy sits between a client and server, allowing you to observe, modify, or inject traffic. This is useful for security testing, debugging APIs, and understanding application behavior.",
                "tips": [
                    "MITM is commonly used for testing mobile apps and web applications",
                    "You can see exactly what data is being sent and received",
                    "This helps identify security vulnerabilities like exposed credentials"
                ],
                "icon": "info"
            },
            {
                "step": 2,
                "title": "Create Your First Proxy",
                "description": "Click 'New Proxy' and configure the proxy to listen on a local port (e.g., 8080) and forward traffic to your target server (e.g., localhost:3000 for a local API).",
                "fields": {
                    "proxy_id": "A unique name for your proxy (e.g., 'api-proxy')",
                    "listen_port": "The port your proxy will listen on (default: 8080)",
                    "target_host": "The server to forward traffic to (e.g., 'localhost' or 'api.example.com')",
                    "target_port": "The port of the target server (e.g., 80 for HTTP, 443 for HTTPS)"
                },
                "icon": "add"
            },
            {
                "step": 3,
                "title": "Choose Interception Mode",
                "description": "Select how the proxy handles traffic:",
                "modes": [
                    {
                        "name": "Passthrough",
                        "description": "Just observe traffic without modifying it. Best for initial analysis.",
                        "use_case": "Start here to understand what traffic looks like"
                    },
                    {
                        "name": "Auto Modify",
                        "description": "Automatically apply rules to modify requests/responses.",
                        "use_case": "Use after creating rules to test security scenarios"
                    },
                    {
                        "name": "Intercept",
                        "description": "Hold each request for manual review before forwarding.",
                        "use_case": "For detailed inspection of specific requests"
                    }
                ],
                "icon": "settings"
            },
            {
                "step": 4,
                "title": "Configure Your Application",
                "description": "Point your application to use the MITM proxy instead of connecting directly to the server.",
                "examples": [
                    {
                        "type": "Browser",
                        "instructions": "Set HTTP proxy to 127.0.0.1:8080 in browser or OS settings"
                    },
                    {
                        "type": "curl",
                        "instructions": "Use: curl --proxy http://127.0.0.1:8080 http://target.com/api"
                    },
                    {
                        "type": "Node.js",
                        "instructions": "Set HTTP_PROXY=http://127.0.0.1:8080 environment variable"
                    },
                    {
                        "type": "Python",
                        "instructions": "Use proxies={'http': 'http://127.0.0.1:8080'} in requests"
                    }
                ],
                "icon": "link"
            },
            {
                "step": 5,
                "title": "Start the Proxy and Generate Traffic",
                "description": "Click 'Start' to activate the proxy, then use your application normally. Traffic will appear in the Traffic Log tab.",
                "tips": [
                    "Watch for requests/responses appearing in real-time",
                    "Enable 'Auto Refresh' to see traffic as it flows",
                    "Click on any entry to see full request/response details"
                ],
                "icon": "play"
            },
            {
                "step": 6,
                "title": "Apply Preset Rules for Testing",
                "description": "Use the Preset Rules tab to quickly apply common security test scenarios.",
                "presets": [
                    {
                        "name": "Bypass CORS",
                        "description": "Add permissive CORS headers to test cross-origin restrictions"
                    },
                    {
                        "name": "Remove CSP",
                        "description": "Remove Content-Security-Policy to test XSS scenarios"
                    },
                    {
                        "name": "Add Debug Headers",
                        "description": "Inject debugging headers into requests"
                    },
                    {
                        "name": "Slow Response",
                        "description": "Add artificial delay to test timeout handling"
                    }
                ],
                "icon": "rule"
            },
            {
                "step": 7,
                "title": "Analyze Traffic for Security Issues",
                "description": "Click 'Analyze Traffic' to run AI-powered security analysis on captured traffic. This will identify vulnerabilities like:",
                "checks": [
                    "Sensitive data (passwords, tokens) in clear text",
                    "Missing security headers (CSP, HSTS, X-Frame-Options)",
                    "Insecure cookie configurations",
                    "CORS misconfigurations",
                    "Information disclosure in error responses"
                ],
                "icon": "security"
            },
            {
                "step": 8,
                "title": "Export Your Findings",
                "description": "Generate professional reports of your MITM analysis:",
                "formats": [
                    {
                        "format": "Markdown",
                        "description": "Plain text format, great for documentation and Git"
                    },
                    {
                        "format": "PDF",
                        "description": "Professional formatted report for sharing"
                    },
                    {
                        "format": "Word",
                        "description": "Editable document for custom reporting"
                    }
                ],
                "icon": "download"
            }
        ],
        "common_use_cases": [
            {
                "title": "API Security Testing",
                "description": "Intercept API calls to find authentication bypasses, injection vulnerabilities, and data exposure",
                "steps": ["Set up proxy", "Configure app to use proxy", "Test different API endpoints", "Check for security headers"]
            },
            {
                "title": "Mobile App Testing",
                "description": "Analyze traffic between mobile apps and their backend servers",
                "steps": ["Configure phone to use proxy", "Trust proxy certificate for HTTPS", "Use the app normally", "Analyze captured traffic"]
            },
            {
                "title": "Debugging Integrations",
                "description": "See exactly what data is being exchanged between services",
                "steps": ["Place proxy between services", "Monitor traffic in real-time", "Identify request/response issues"]
            }
        ],
        "troubleshooting": [
            {
                "issue": "No traffic appearing",
                "solutions": [
                    "Verify the proxy is started (green status)",
                    "Check your application is configured to use the proxy",
                    "Ensure firewall isn't blocking the proxy port"
                ]
            },
            {
                "issue": "HTTPS traffic not visible",
                "solutions": [
                    "Enable TLS in proxy settings",
                    "Configure your application to trust the proxy certificate",
                    "Some apps may use certificate pinning - check app settings"
                ]
            },
            {
                "issue": "Connection refused errors",
                "solutions": [
                    "Verify target host and port are correct",
                    "Ensure target server is running",
                    "Check for network connectivity between proxy and target"
                ]
            }
        ]
    }


# ============================================================================
# Test Scenarios for Beginners
# ============================================================================

TEST_SCENARIOS = {
    "csrf_bypass": {
        "id": "csrf_bypass",
        "name": "CSRF Protection Bypass",
        "description": "Test Cross-Site Request Forgery protection by removing/modifying CSRF tokens",
        "difficulty": "Beginner",
        "category": "authentication",
        "icon": "security",
        "estimated_time": "2 minutes",
        "rules": [
            {
                "name": "Remove CSRF Token Header",
                "match_direction": "request",
                "action": "modify",
                "remove_headers": ["X-CSRF-Token", "X-XSRF-Token", "csrf-token"]
            },
            {
                "name": "Remove Referer Check",
                "match_direction": "request",
                "action": "modify",
                "remove_headers": ["Referer", "Origin"]
            }
        ],
        "what_to_look_for": [
            "Requests that succeed without CSRF tokens",
            "State-changing operations (POST/PUT/DELETE) that work without validation",
            "Missing Origin/Referer validation"
        ],
        "learning_points": [
            "CSRF attacks trick users into performing unwanted actions",
            "Proper CSRF protection uses tokens AND origin checking",
            "APIs should validate both token and request origin"
        ]
    },
    "auth_bypass": {
        "id": "auth_bypass",
        "name": "Authentication Header Testing",
        "description": "Test how the application handles missing or modified authentication headers",
        "difficulty": "Beginner",
        "category": "authentication",
        "icon": "lock_open",
        "estimated_time": "3 minutes",
        "rules": [
            {
                "name": "Remove Auth Header",
                "match_direction": "request",
                "action": "modify",
                "remove_headers": ["Authorization", "X-Auth-Token", "X-API-Key"]
            },
            {
                "name": "Add Admin Role",
                "match_direction": "request",
                "action": "modify",
                "modify_headers": {"X-User-Role": "admin", "X-Is-Admin": "true"}
            }
        ],
        "what_to_look_for": [
            "Endpoints that work without authentication",
            "Privilege escalation when role headers are added",
            "Sensitive data exposed without auth"
        ],
        "learning_points": [
            "Authentication should be enforced on the server, not trusted from headers",
            "Role-based access control must be verified server-side",
            "Always test what happens when auth is missing"
        ]
    },
    "cors_test": {
        "id": "cors_test",
        "name": "CORS Misconfiguration Test",
        "description": "Test Cross-Origin Resource Sharing policies by modifying response headers",
        "difficulty": "Beginner",
        "category": "browser_security",
        "icon": "public",
        "estimated_time": "2 minutes",
        "rules": [
            {
                "name": "Permissive CORS",
                "match_direction": "response",
                "action": "modify",
                "modify_headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Credentials": "true"
                }
            }
        ],
        "what_to_look_for": [
            "Whether the app accepts requests from any origin",
            "If credentials can be sent cross-origin",
            "Sensitive endpoints that lack CORS protection"
        ],
        "learning_points": [
            "CORS prevents unauthorized cross-origin requests",
            "Allow-Origin: * with credentials is a security risk",
            "Whitelist specific origins instead of using wildcards"
        ]
    },
    "header_injection": {
        "id": "header_injection",
        "name": "Security Header Removal",
        "description": "Remove security headers to test client-side vulnerability exposure",
        "difficulty": "Beginner",
        "category": "browser_security",
        "icon": "remove_circle",
        "estimated_time": "2 minutes",
        "rules": [
            {
                "name": "Remove All Security Headers",
                "match_direction": "response",
                "action": "modify",
                "remove_headers": [
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-XSS-Protection",
                    "X-Content-Type-Options",
                    "Strict-Transport-Security",
                    "Referrer-Policy",
                    "Permissions-Policy"
                ]
            }
        ],
        "what_to_look_for": [
            "XSS vulnerabilities that were blocked by CSP",
            "Clickjacking possibilities without X-Frame-Options",
            "MIME sniffing attacks"
        ],
        "learning_points": [
            "Security headers provide defense-in-depth",
            "CSP prevents many XSS attacks",
            "X-Frame-Options protects against clickjacking"
        ]
    },
    "response_tampering": {
        "id": "response_tampering",
        "name": "Response Modification Test",
        "description": "Modify server responses to test client-side validation",
        "difficulty": "Intermediate",
        "category": "data_validation",
        "icon": "edit",
        "estimated_time": "3 minutes",
        "rules": [
            {
                "name": "Success All Requests",
                "match_direction": "response",
                "match_content_type": "application/json",
                "action": "modify",
                "body_find_replace": {
                    "\"success\":false": "\"success\":true",
                    "\"authorized\":false": "\"authorized\":true",
                    "\"valid\":false": "\"valid\":true",
                    "\"error\":": "\"_hidden_error\":"
                }
            }
        ],
        "what_to_look_for": [
            "Client accepting modified responses without server verification",
            "Actions proceeding despite backend rejection",
            "UI showing unauthorized features"
        ],
        "learning_points": [
            "Never trust client-side validation alone",
            "Critical decisions must be enforced server-side",
            "Response modification can expose logic flaws"
        ]
    },
    "slow_connection": {
        "id": "slow_connection",
        "name": "Network Latency Simulation",
        "description": "Add artificial delays to test timeout handling and race conditions",
        "difficulty": "Beginner",
        "category": "reliability",
        "icon": "speed",
        "estimated_time": "2 minutes",
        "rules": [
            {
                "name": "Add 3 Second Delay",
                "match_direction": "response",
                "action": "delay",
                "delay_ms": 3000
            }
        ],
        "what_to_look_for": [
            "UI freezing or poor loading states",
            "Timeout errors and how they're handled",
            "Race conditions when responses arrive late"
        ],
        "learning_points": [
            "Apps should gracefully handle slow connections",
            "Proper loading states improve user experience",
            "Timeouts should have reasonable defaults"
        ]
    },
    "script_injection": {
        "id": "script_injection",
        "name": "Script Injection Test",
        "description": "Inject JavaScript into HTML responses to test XSS defenses",
        "difficulty": "Intermediate",
        "category": "xss",
        "icon": "code",
        "estimated_time": "3 minutes",
        "rules": [
            {
                "name": "Inject Console Log",
                "match_direction": "response",
                "match_content_type": "text/html",
                "action": "modify",
                "body_find_replace": {
                    "</body>": "<script>console.log('[MITM] Script injected successfully!');</script></body>",
                    "</head>": "<script>window.__MITM_INJECTED=true;</script></head>"
                }
            }
        ],
        "what_to_look_for": [
            "Console messages indicating successful injection",
            "Whether CSP blocks the injected script",
            "DOM modifications from injected code"
        ],
        "learning_points": [
            "XSS attacks inject malicious scripts into pages",
            "Content-Security-Policy can block inline scripts",
            "Input sanitization prevents stored XSS"
        ]
    },
    "sensitive_data": {
        "id": "sensitive_data",
        "name": "Sensitive Data Detection",
        "description": "Monitor traffic for exposed sensitive information",
        "difficulty": "Beginner",
        "category": "data_exposure",
        "icon": "visibility",
        "estimated_time": "5 minutes",
        "rules": [],
        "what_to_look_for": [
            "Passwords or tokens in URLs (query strings)",
            "API keys or secrets in request/response bodies",
            "PII (emails, phone numbers, SSNs) in clear text",
            "Session tokens without HttpOnly flag"
        ],
        "learning_points": [
            "Sensitive data should never appear in URLs",
            "Use HTTPS to encrypt data in transit",
            "Mask or encrypt PII in responses"
        ]
    }
}


@router.get("/test-scenarios")
async def get_test_scenarios():
    """
    Get available beginner-friendly test scenarios.
    
    Each scenario includes pre-configured rules and learning materials.
    """
    return list(TEST_SCENARIOS.values())


@router.get("/test-scenarios/{scenario_id}")
async def get_test_scenario(scenario_id: str):
    """Get details for a specific test scenario"""
    if scenario_id not in TEST_SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return TEST_SCENARIOS[scenario_id]


@router.post("/proxies/{proxy_id}/run-scenario/{scenario_id}")
async def run_test_scenario(proxy_id: str, scenario_id: str):
    """
    Apply a test scenario to a proxy.
    
    This adds all the scenario's rules to the proxy and sets it to auto_modify mode.
    """
    if scenario_id not in TEST_SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    
    try:
        proxy = mitm_service._get_proxy(proxy_id)
        scenario = TEST_SCENARIOS[scenario_id]
        
        # Apply all scenario rules
        added_rules = []
        for rule in scenario.get("rules", []):
            result = mitm_service.add_rule(proxy_id, rule)
            added_rules.append(result)
        
        # Set proxy to auto_modify mode if it has rules
        if scenario.get("rules"):
            mitm_service.set_mode(proxy_id, "auto_modify")
        
        return {
            "message": f"Scenario '{scenario['name']}' applied successfully",
            "scenario": scenario,
            "rules_added": len(added_rules),
            "mode": "auto_modify" if scenario.get("rules") else "passthrough",
            "next_steps": [
                "Start the proxy if not already running",
                "Send traffic through the proxy",
                "Watch the traffic log for intercepted requests",
                "Check what the scenario highlights"
            ]
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Health Check / Connectivity Test
# ============================================================================

@router.get("/proxies/{proxy_id}/health")
async def check_proxy_health(proxy_id: str):
    """
    Check the health and connectivity of a proxy.
    
    Tests:
    - Proxy is running
    - Target host is reachable
    - Listen port is available
    """
    import socket as sock
    
    try:
        proxy = mitm_service._get_proxy(proxy_id)
        
        health = {
            "proxy_id": proxy_id,
            "status": "healthy",
            "checks": [],
            "recommendations": []
        }
        
        # Check 1: Proxy running status
        health["checks"].append({
            "name": "Proxy Running",
            "status": "pass" if proxy.running else "fail",
            "message": "Proxy is running" if proxy.running else "Proxy is stopped"
        })
        
        if not proxy.running:
            health["status"] = "warning"
            health["recommendations"].append("Start the proxy to begin intercepting traffic")
        
        # Check 2: Target host reachability
        target_reachable = False
        try:
            test_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            test_socket.settimeout(3)
            result = test_socket.connect_ex((proxy.target_host, proxy.target_port))
            target_reachable = result == 0
            test_socket.close()
        except:
            pass
        
        health["checks"].append({
            "name": "Target Reachable",
            "status": "pass" if target_reachable else "fail",
            "message": f"Target {proxy.target_host}:{proxy.target_port} is reachable" if target_reachable 
                       else f"Cannot connect to {proxy.target_host}:{proxy.target_port}"
        })
        
        if not target_reachable:
            health["status"] = "error" if not proxy.running else "warning"
            health["recommendations"].append(f"Ensure the target server at {proxy.target_host}:{proxy.target_port} is running")
            health["recommendations"].append("Check firewall rules allow the connection")
        
        # Check 3: Traffic captured
        traffic_count = len(proxy.traffic_log) if hasattr(proxy, 'traffic_log') else 0
        health["checks"].append({
            "name": "Traffic Captured",
            "status": "pass" if traffic_count > 0 else "info",
            "message": f"{traffic_count} requests captured" if traffic_count > 0 
                       else "No traffic captured yet"
        })
        
        if traffic_count == 0 and proxy.running:
            health["recommendations"].append("Configure your client to use the proxy address")
            health["recommendations"].append(f"Set HTTP proxy to {proxy.listen_host}:{proxy.listen_port}")
        
        # Check 4: Rules configured
        rules_count = len(proxy.rules) if hasattr(proxy, 'rules') else 0
        health["checks"].append({
            "name": "Rules Configured",
            "status": "pass" if rules_count > 0 else "info",
            "message": f"{rules_count} interception rules active" if rules_count > 0 
                       else "No interception rules configured"
        })
        
        if rules_count == 0:
            health["recommendations"].append("Add rules or apply a test scenario to modify traffic")
        
        # Check 5: Mode status
        mode = proxy.mode.value if hasattr(proxy.mode, 'value') else str(proxy.mode)
        health["checks"].append({
            "name": "Interception Mode",
            "status": "info",
            "message": f"Mode is set to '{mode}'"
        })
        
        if mode == "passthrough" and rules_count > 0:
            health["recommendations"].append("Switch to 'auto_modify' mode to apply your rules")
        
        # Overall status calculation
        failed_checks = [c for c in health["checks"] if c["status"] == "fail"]
        if len(failed_checks) > 1:
            health["status"] = "error"
        elif len(failed_checks) == 1:
            health["status"] = "warning"
        elif health["status"] != "warning":
            health["status"] = "healthy"
        
        return health
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# NATURAL LANGUAGE RULE CREATION
# =============================================================================

class NaturalLanguageRuleRequest(BaseModel):
    """Request model for natural language rule creation."""
    description: str
    proxy_id: Optional[str] = None  # If provided, auto-apply to proxy

class NaturalLanguageRuleResponse(BaseModel):
    """Response model for natural language rule creation."""
    success: bool
    rule: Optional[Dict[str, Any]] = None
    interpretation: str
    applied: bool = False
    error: Optional[str] = None


@router.post("/ai/create-rule", response_model=NaturalLanguageRuleResponse)
async def create_rule_from_natural_language_endpoint(
    request: NaturalLanguageRuleRequest
):
    """
    Create an interception rule from a natural language description.
    
    Examples:
    - "Block all requests to analytics.google.com"
    - "Add a 2 second delay to all API responses"
    - "Remove the Authorization header from all requests"
    - "Replace all prices with $0.00"
    - "Add X-Custom-Header: test123 to all requests"
    """
    try:
        result = await create_rule_from_natural_language(request.description)
        
        response = NaturalLanguageRuleResponse(
            success=result.get("success", False),
            rule=result.get("rule"),
            interpretation=result.get("interpretation", ""),
            error=result.get("error")
        )
        
        # Auto-apply to proxy if specified
        if result.get("success") and request.proxy_id and result.get("rule"):
            try:
                rule_data = result["rule"]
                # Use add_rule through mitm_service
                mitm_service.add_rule(request.proxy_id, {
                    "name": rule_data.get("description", request.description)[:50],
                    "match_host": rule_data.get("pattern"),
                    "match_path": rule_data.get("pattern"),
                    "action": rule_data.get("action", "modify"),
                    "modify_headers": rule_data.get("modifications", {}).get("add_headers"),
                    "remove_headers": rule_data.get("modifications", {}).get("remove_headers"),
                    "modify_body": rule_data.get("modifications", {}).get("body_replace"),
                    "delay_ms": rule_data.get("modifications", {}).get("delay_ms", 0),
                    "enabled": True
                })
                response.applied = True
            except Exception:
                # Rule created but not applied - still a success
                pass
        
        return response
        
    except Exception as e:
        return NaturalLanguageRuleResponse(
            success=False,
            interpretation="Failed to process natural language request",
            error=str(e)
        )


# =============================================================================
# REAL-TIME AI SUGGESTIONS
# =============================================================================

class AISuggestion(BaseModel):
    """A single AI-generated suggestion."""
    id: str
    title: str
    description: str
    category: str  # security, performance, debug, learning
    priority: str  # high, medium, low
    rule: Optional[Dict[str, Any]] = None  # Quick-apply rule
    natural_language: str  # What user would type

class AISuggestionsResponse(BaseModel):
    """Response model for AI suggestions."""
    proxy_id: str
    suggestions: List[AISuggestion]
    traffic_summary: Dict[str, Any]
    generated_at: str


@router.get("/proxies/{proxy_id}/ai-suggestions", response_model=AISuggestionsResponse)
async def get_ai_suggestions_endpoint(proxy_id: str):
    """
    Get AI-generated suggestions based on current traffic patterns.
    
    Analyzes the proxy's traffic log and existing rules to suggest:
    - Security tests to perform
    - Performance improvements
    - Debugging techniques
    - Learning opportunities
    """
    try:
        # Get traffic data using mitm_service
        traffic_result = mitm_service.get_traffic(proxy_id, limit=50, offset=0)
        traffic_log = traffic_result.get("entries", [])

        # Get existing rules using mitm_service
        existing_rules = mitm_service.get_rules(proxy_id)

        # Get proxy config using mitm_service
        status = mitm_service.get_proxy_status(proxy_id)
        proxy_config = {
            "target_host": status.get("target_host", ""),
            "target_port": status.get("target_port", 80),
            "mode": status.get("mode", "passthrough"),
            "ssl_enabled": status.get("tls_enabled", False)
        }

        # Call AI suggestion service
        result = await get_ai_traffic_suggestions(traffic_log, existing_rules, proxy_config)

        # Convert to response model
        suggestions = []
        for sug in result.get("suggestions", []):
            suggestions.append(AISuggestion(
                id=sug.get("id", f"sug_{len(suggestions)}"),
                title=sug.get("title", "Suggestion"),
                description=sug.get("description", ""),
                category=sug.get("category", "learning"),
                priority=sug.get("priority", "medium"),
                rule=sug.get("rule"),
                natural_language=sug.get("natural_language", "")
            ))

        return AISuggestionsResponse(
            proxy_id=proxy_id,
            suggestions=suggestions,
            traffic_summary=result.get("traffic_summary", {}),
            generated_at=result.get("generated_at", "")
        )
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WebSocket Deep Inspection Endpoints
# ============================================================================

class WebSocketRuleConfig(BaseModel):
    """WebSocket rule configuration"""
    name: str
    enabled: bool = True
    priority: int = 100
    match_direction: str = "both"  # client_to_server, server_to_client, both
    match_opcode: Optional[int] = None  # 1=TEXT, 2=BINARY
    match_payload_pattern: Optional[str] = None
    match_json_path: Optional[str] = None
    action: str = "modify"  # modify, drop, delay
    payload_find_replace: Optional[Dict[str, str]] = None
    json_path_edits: Optional[List[Dict[str, Any]]] = None
    delay_ms: int = 0


@router.get("/proxies/{proxy_id}/websocket/connections")
async def get_websocket_connections(proxy_id: str):
    """
    Get all WebSocket connections for a proxy.
    
    Returns active and closed WebSocket connections with stats.
    """
    try:
        return mitm_service.get_websocket_connections(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/proxies/{proxy_id}/websocket/connections/{connection_id}/frames")
async def get_websocket_frames(
    proxy_id: str,
    connection_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Get WebSocket frames for a specific connection.
    
    Returns parsed frame data including:
    - Frame opcode (TEXT, BINARY, PING, PONG, CLOSE)
    - Direction (client_to_server, server_to_client)
    - Payload (text/JSON parsed when possible)
    - Modification status
    """
    try:
        return mitm_service.get_websocket_frames(proxy_id, connection_id, limit, offset)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/proxies/{proxy_id}/websocket/stats")
async def get_websocket_stats(proxy_id: str):
    """
    Get WebSocket inspection statistics.
    
    Returns frame counts, byte totals, and connection stats.
    """
    try:
        return mitm_service.get_websocket_stats(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/proxies/{proxy_id}/websocket/rules")
async def add_websocket_rule(proxy_id: str, rule: WebSocketRuleConfig):
    """
    Add a WebSocket interception rule.
    
    Rules can match on:
    - Direction (client_to_server, server_to_client, both)
    - Frame opcode (TEXT=1, BINARY=2)
    - Payload pattern (regex)
    - JSON path values
    
    Actions:
    - modify: Apply find/replace or JSON path edits
    - drop: Silently drop the frame
    - delay: Add latency before forwarding
    """
    try:
        return mitm_service.add_websocket_rule(proxy_id, rule.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/proxies/{proxy_id}/websocket/rules")
async def get_websocket_rules(proxy_id: str):
    """Get all WebSocket rules"""
    try:
        return mitm_service.get_websocket_rules(proxy_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/proxies/{proxy_id}/websocket/rules/{rule_id}")
async def remove_websocket_rule(proxy_id: str, rule_id: str):
    """Remove a WebSocket rule"""
    try:
        return mitm_service.remove_websocket_rule(proxy_id, rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# Certificate Management Endpoints
# ============================================================================

class CACertificateConfig(BaseModel):
    """CA certificate generation configuration"""
    common_name: str = "VRAgent MITM CA"
    organization: str = "VRAgent Security"
    country: str = "US"
    validity_days: int = 3650  # 10 years


@router.get("/certificates/ca")
async def get_ca_certificate():
    """
    Get the current CA certificate information.
    
    Returns certificate details including fingerprint for verification.
    """
    try:
        ca = mitm_service.get_ca_certificate()
        if not ca:
            return {
                "status": "not_generated",
                "message": "No CA certificate has been generated yet. Generate one to enable HTTPS interception."
            }
        return ca
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/certificates/ca/generate")
async def generate_ca_certificate(config: CACertificateConfig):
    """
    Generate a new CA certificate for HTTPS MITM interception.
    
    ⚠️ Warning: This will invalidate all previously generated host certificates.
    
    The CA certificate must be installed on clients to trust HTTPS interception.
    """
    try:
        return mitm_service.generate_ca_certificate(
            common_name=config.common_name,
            organization=config.organization,
            country=config.country,
            validity_days=config.validity_days
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates/ca/download")
async def download_ca_certificate(format: str = Query("pem", regex="^(pem|crt|der)$")):
    """
    Download the CA certificate for installation.
    
    Formats:
    - pem: PEM format (default, works everywhere)
    - crt: Same as PEM but with .crt extension (Windows-friendly)
    - der: Binary DER format
    """
    try:
        content, media_type, filename = mitm_service.download_ca_certificate(format)
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates/ca/installation")
async def get_certificate_installation_instructions():
    """
    Get instructions for installing the CA certificate on various platforms.
    
    Returns step-by-step guides for:
    - Windows
    - macOS
    - Linux
    - Firefox
    - Android
    - iOS
    """
    try:
        return mitm_service.get_certificate_installation_instructions()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates/hosts")
async def list_host_certificates():
    """
    List all generated host certificates.
    
    Returns certificates that have been generated for specific hosts
    during HTTPS interception.
    """
    try:
        return mitm_service.list_host_certificates()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates/hosts/{hostname}")
async def get_host_certificate(hostname: str):
    """
    Get or generate a certificate for a specific hostname.
    
    If a valid certificate exists, returns it.
    Otherwise, generates a new certificate signed by the CA.
    """
    try:
        cert = mitm_service.get_host_certificate(hostname)
        if not cert:
            raise HTTPException(
                status_code=404,
                detail="No CA certificate. Generate a CA certificate first."
            )
        return cert
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/certificates/hosts/{hostname}")
async def delete_host_certificate(hostname: str):
    """Delete a host certificate"""
    try:
        return mitm_service.delete_host_certificate(hostname)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Request/Response Diff Viewer Endpoints
# ============================================================================

@router.get("/proxies/{proxy_id}/traffic/{entry_id}/diff")
async def get_traffic_diff(
    proxy_id: str = Path(..., description="Proxy ID"),
    entry_id: str = Path(..., description="Traffic entry ID")
):
    """
    Get diff between original and modified traffic entry.
    
    Returns a detailed comparison showing:
    - Header changes (added, removed, modified)
    - Body changes (line-by-line or JSON diff)
    - Change summary
    """
    try:
        return mitm_service.get_traffic_diff(proxy_id, entry_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class DiffCompareRequest(BaseModel):
    original_request: Dict[str, Any]
    modified_request: Optional[Dict[str, Any]] = None
    original_response: Optional[Dict[str, Any]] = None
    modified_response: Optional[Dict[str, Any]] = None


@router.post("/diff/compare")
async def compare_traffic(request: DiffCompareRequest):
    """
    Compare two traffic entries directly.
    
    Useful for comparing traffic from different sources
    or testing modifications before applying.
    """
    try:
        from ..services.mitm_service import TrafficDiffViewer
        results = TrafficDiffViewer.compare_traffic(
            request.original_request,
            request.modified_request,
            request.original_response,
            request.modified_response
        )
        # Convert DiffResult dataclasses to dicts
        return {
            key: {
                "has_changes": result.has_changes,
                "change_type": result.change_type,
                "header_changes": result.header_changes,
                "body_changes": result.body_changes,
                "summary": result.summary,
                "original_size": result.original_size,
                "modified_size": result.modified_size
            }
            for key, result in results.items()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# HTTP/2 & gRPC Endpoints
# ============================================================================

@router.get("/proxies/{proxy_id}/http2/frames")
async def get_http2_frames(
    proxy_id: str = Path(..., description="Proxy ID"),
    stream_id: Optional[int] = Query(None, description="Filter by stream ID"),
    frame_type: Optional[str] = Query(None, description="Filter by frame type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Get HTTP/2 frames captured for a proxy.
    
    Returns parsed HTTP/2 frames including:
    - Frame type (DATA, HEADERS, etc.)
    - Stream ID
    - Flags and payload
    """
    try:
        return mitm_service.get_http2_frames(
            proxy_id,
            stream_id=stream_id,
            frame_type=frame_type,
            limit=limit,
            offset=offset
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/proxies/{proxy_id}/http2/streams")
async def get_http2_streams(
    proxy_id: str = Path(..., description="Proxy ID")
):
    """
    Get active HTTP/2 streams for a proxy.
    
    Returns a list of active streams with their status,
    method, path, and frame counts.
    """
    try:
        return mitm_service.get_http2_streams(proxy_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/proxies/{proxy_id}/grpc/messages")
async def get_grpc_messages(
    proxy_id: str = Path(..., description="Proxy ID"),
    service: Optional[str] = Query(None, description="Filter by gRPC service"),
    method: Optional[str] = Query(None, description="Filter by gRPC method"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Get gRPC messages captured for a proxy.
    
    Returns decoded gRPC messages with:
    - Service and method names
    - Message payloads (if decodable)
    - Stream information
    """
    try:
        return mitm_service.get_grpc_messages(
            proxy_id,
            service=service,
            method=method,
            limit=limit,
            offset=offset
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class HTTP2ParseRequest(BaseModel):
    data: str  # Base64 encoded raw data


@router.post("/http2/parse")
async def parse_http2_data(request: HTTP2ParseRequest):
    """
    Parse raw HTTP/2 frame data.
    
    Useful for analyzing captured HTTP/2 traffic
    or debugging HTTP/2 issues.
    """
    try:
        import base64
        from ..services.mitm_service import HTTP2Parser
        
        raw_data = base64.b64decode(request.data)
        
        frames = []
        offset = 0
        while offset < len(raw_data):
            result = HTTP2Parser.parse_frame(raw_data, offset)
            if not result:
                break
            frame, new_offset = result
            frames.append({
                "id": frame.id,
                "stream_id": frame.stream_id,
                "frame_type": frame.frame_type,
                "frame_type_name": frame.frame_type_name,
                "flags": frame.flags,
                "length": frame.length,
                "is_grpc": frame.is_grpc
            })
            offset = new_offset
        
        return {
            "frames": frames,
            "total_bytes": len(raw_data),
            "frames_parsed": len(frames),
            "is_http2": HTTP2Parser.detect_http2(raw_data)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Match & Replace Templates Endpoints
# ============================================================================

@router.get("/templates")
async def list_templates(
    category: Optional[str] = Query(None, description="Filter by category"),
    tag: Optional[str] = Query(None, description="Filter by tag")
):
    """
    List available match/replace templates.
    
    Returns pre-built and custom templates for common
    MITM modifications like security testing, debugging, etc.
    """
    try:
        return mitm_service.get_match_replace_templates(
            category=category,
            tag=tag
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/categories")
async def list_template_categories():
    """Get available template categories"""
    try:
        return {"categories": mitm_service.get_template_categories()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/{template_id}")
async def get_template(template_id: str = Path(..., description="Template ID")):
    """Get a specific template by ID"""
    try:
        template = mitm_service.get_template(template_id)
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")
        return template
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class CustomTemplateConfig(BaseModel):
    name: str
    category: str = "Custom"
    description: str
    match_type: str  # "header", "body", "path", "query"
    match_pattern: str
    replace_pattern: str
    is_regex: bool = False
    case_sensitive: bool = True
    direction: str = "both"
    match_host: Optional[str] = None
    match_content_type: Optional[str] = None
    tags: List[str] = []


@router.post("/templates")
async def create_custom_template(config: CustomTemplateConfig):
    """
    Create a custom match/replace template.
    
    Custom templates are saved and can be used alongside
    built-in templates.
    """
    try:
        return mitm_service.create_custom_template(config.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/templates/{template_id}")
async def delete_template(template_id: str = Path(..., description="Template ID")):
    """Delete a custom template"""
    try:
        success = mitm_service.delete_custom_template(template_id)
        if not success:
            raise HTTPException(status_code=404, detail="Template not found or is built-in")
        return {"status": "deleted", "template_id": template_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/proxies/{proxy_id}/apply-template/{template_id}")
async def apply_template_to_proxy(
    proxy_id: str = Path(..., description="Proxy ID"),
    template_id: str = Path(..., description="Template ID")
):
    """
    Apply a template to a proxy as an interception rule.
    
    Converts the template into a rule that will be
    applied to matching traffic.
    """
    try:
        return mitm_service.apply_template_to_proxy(proxy_id, template_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class TestTemplateRequest(BaseModel):
    template_id: str
    request_data: Dict[str, Any]
    response_data: Optional[Dict[str, Any]] = None


@router.post("/templates/test")
async def test_template(request: TestTemplateRequest):
    """
    Test a template against sample data.
    
    Returns the modified data showing what changes
    the template would make.
    """
    try:
        return mitm_service.test_template(
            request.template_id,
            request.request_data,
            request.response_data
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Network Throttling Endpoints
# ============================================================================

@router.get("/throttle/profiles")
async def list_throttle_profiles():
    """
    List all available network throttling profiles.
    """
    return [p.to_dict() for p in network_throttler.get_all_profiles()]


@router.get("/throttle/profiles/{profile_id}")
async def get_throttle_profile(profile_id: str):
    """Get a specific throttle profile."""
    profile = network_throttler.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile.to_dict()


@router.get("/throttle/active")
async def get_active_throttle():
    """Get the currently active throttle profile."""
    profile = network_throttler.get_active_profile()
    return {"active_profile": profile.to_dict() if profile else None}


@router.post("/throttle/activate/{profile_id}")
async def activate_throttle(profile_id: str):
    """Activate a throttle profile."""
    if not network_throttler.set_active_profile(profile_id):
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"status": "activated", "profile_id": profile_id}


@router.post("/throttle/deactivate")
async def deactivate_throttle():
    """Deactivate throttling."""
    network_throttler.set_active_profile(None)
    return {"status": "deactivated"}


class ThrottleProfileCreate(BaseModel):
    name: str
    description: str
    bandwidth_kbps: int = 0
    latency_ms: int = 0
    packet_loss_percent: float = 0.0
    jitter_ms: int = 0


@router.post("/throttle/profiles")
async def create_throttle_profile(config: ThrottleProfileCreate):
    """Create a custom throttle profile."""
    import uuid
    profile = ThrottleProfile(
        id=f"custom_{uuid.uuid4().hex[:8]}",
        name=config.name,
        description=config.description,
        bandwidth_kbps=config.bandwidth_kbps,
        latency_ms=config.latency_ms,
        packet_loss_percent=config.packet_loss_percent,
        jitter_ms=config.jitter_ms,
        is_builtin=False
    )
    network_throttler.add_custom_profile(profile)
    return profile.to_dict()


@router.delete("/throttle/profiles/{profile_id}")
async def delete_throttle_profile(profile_id: str):
    """Delete a custom throttle profile."""
    profile = network_throttler.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    if profile.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in profiles")
    network_throttler.remove_custom_profile(profile_id)
    return {"status": "deleted"}


# ============================================================================
# Macro Recorder Endpoints
# ============================================================================

@router.get("/macros")
async def list_macros():
    """List all recorded macros."""
    return [m.to_dict() for m in macro_recorder.list_macros()]


@router.get("/macros/{macro_id}")
async def get_macro(macro_id: str):
    """Get a specific macro."""
    macro = macro_recorder.get_macro(macro_id)
    if not macro:
        raise HTTPException(status_code=404, detail="Macro not found")
    return macro.to_dict()


class MacroCreateRequest(BaseModel):
    name: str
    description: str = ""


@router.post("/macros/start-recording")
async def start_macro_recording(request: MacroCreateRequest):
    """Start recording a new macro."""
    if macro_recorder.recording:
        raise HTTPException(status_code=400, detail="Already recording a macro")
    macro = macro_recorder.start_recording(request.name, request.description)
    return {"status": "recording", "macro_id": macro.id, "macro": macro.to_dict()}


@router.post("/macros/stop-recording")
async def stop_macro_recording():
    """Stop recording and save the macro."""
    macro = macro_recorder.stop_recording()
    if not macro:
        raise HTTPException(status_code=400, detail="Not currently recording")
    return {"status": "stopped", "macro": macro.to_dict()}


@router.get("/macros/recording-status")
async def get_recording_status():
    """Get current recording status."""
    return {
        "recording": macro_recorder.recording,
        "macro_id": macro_recorder.recording_macro_id
    }


class MacroFromTrafficRequest(BaseModel):
    traffic_ids: List[str]
    name: str
    description: str = ""
    proxy_id: str


@router.post("/macros/from-traffic")
async def create_macro_from_traffic(request: MacroFromTrafficRequest):
    """Create a macro from captured traffic entries."""
    # Get traffic entries from the proxy
    proxy = mitm_service.proxies.get(request.proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    entries = []
    for entry_id in request.traffic_ids:
        for entry in proxy.traffic_log:
            if entry.get("id") == entry_id:
                entries.append(entry)
                break
    
    if not entries:
        raise HTTPException(status_code=404, detail="No traffic entries found")
    
    macro = macro_recorder.create_macro_from_traffic(
        entries,
        request.name,
        request.description
    )
    return macro.to_dict()


class MacroUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    variables: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None


@router.patch("/macros/{macro_id}")
async def update_macro(macro_id: str, request: MacroUpdateRequest):
    """Update macro metadata."""
    macro = macro_recorder.update_macro(
        macro_id,
        name=request.name,
        description=request.description,
        variables=request.variables,
        tags=request.tags
    )
    if not macro:
        raise HTTPException(status_code=404, detail="Macro not found")
    return macro.to_dict()


@router.delete("/macros/{macro_id}")
async def delete_macro(macro_id: str):
    """Delete a macro."""
    if not macro_recorder.delete_macro(macro_id):
        raise HTTPException(status_code=404, detail="Macro not found")
    return {"status": "deleted"}


class MacroRunRequest(BaseModel):
    base_url: str
    variables: Optional[Dict[str, str]] = None
    timeout_per_step: float = 30.0


@router.post("/macros/{macro_id}/run")
async def run_macro(macro_id: str, request: MacroRunRequest):
    """Run a macro."""
    result = await macro_recorder.run_macro(
        macro_id,
        request.base_url,
        initial_variables=request.variables,
        timeout_per_step=request.timeout_per_step
    )
    return result.to_dict()


@router.get("/macros/{macro_id}/last-result")
async def get_macro_last_result(macro_id: str):
    """Get the last run result for a macro."""
    result = macro_recorder.get_run_result(macro_id)
    if not result:
        raise HTTPException(status_code=404, detail="No run result found")
    return result.to_dict()


# ============================================================================
# HAR Export Endpoints
# ============================================================================

@router.get("/proxies/{proxy_id}/export/har")
async def export_traffic_as_har(
    proxy_id: str,
    limit: Optional[int] = Query(None, description="Maximum entries to export"),
    offset: Optional[int] = Query(0, description="Skip entries")
):
    """
    Export proxy traffic to HAR format.
    
    HAR (HTTP Archive) files can be imported into browser developer tools
    for analysis and debugging.
    """
    proxy = mitm_service.proxies.get(proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    traffic = proxy.traffic_log[offset:]
    if limit:
        traffic = traffic[:limit]
    
    har_data = har_exporter.traffic_to_har(traffic)
    
    return Response(
        content=json.dumps(har_data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{proxy_id}_traffic.har"'
        }
    )


# ============================================================================
# Protocol Decoder Endpoints
# ============================================================================

@router.get("/decoders")
async def list_protocol_decoders():
    """List all available protocol decoders."""
    return [d.to_dict() for d in protocol_decoder_manager.get_all_decoders()]


@router.get("/decoders/{decoder_id}")
async def get_protocol_decoder(decoder_id: str):
    """Get a specific decoder."""
    decoder = protocol_decoder_manager.get_decoder(decoder_id)
    if not decoder:
        raise HTTPException(status_code=404, detail="Decoder not found")
    return decoder.to_dict()


class DecodeRequest(BaseModel):
    content_type: str
    data: str  # Base64 encoded


@router.post("/decoders/decode")
async def decode_data(request: DecodeRequest):
    """
    Decode binary data using available decoders.
    
    The system will automatically detect and use the appropriate decoder
    based on content type or magic bytes.
    """
    import base64
    try:
        data = base64.b64decode(request.data)
        result = protocol_decoder_manager.decode(request.content_type, data)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================================
# Collaborative Session Sharing Endpoints
# ============================================================================

@router.get("/sessions/shared")
async def list_shared_sessions(
    current_user: User = Depends(get_current_active_user)
):
    """List shared sessions for the current user."""
    sessions = session_sharing_manager.list_sessions_for_user(str(current_user.id))
    return [s.to_dict() for s in sessions]


@router.get("/sessions/shared/{session_id}")
async def get_shared_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific shared session."""
    session = session_sharing_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session_sharing_manager.check_access(session_id, str(current_user.id)):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return session.to_dict()


class CreateSharedSessionRequest(BaseModel):
    proxy_id: str
    name: str
    description: str = ""
    access_level: str = "view"  # view, interact, full
    expires_hours: Optional[int] = None
    enable_link_sharing: bool = False


@router.post("/sessions/shared")
async def create_shared_session(
    request: CreateSharedSessionRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Create a new shared session."""
    proxy = mitm_service.proxies.get(request.proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    session = session_sharing_manager.create_shared_session(
        proxy_id=request.proxy_id,
        name=request.name,
        owner_id=str(current_user.id),
        owner_name=current_user.username,
        description=request.description,
        access_level=request.access_level,
        expires_hours=request.expires_hours,
        enable_link_sharing=request.enable_link_sharing
    )
    
    return session.to_dict()


class ShareWithUserRequest(BaseModel):
    user_id: str


@router.post("/sessions/shared/{session_id}/share")
async def share_session_with_user(
    session_id: str,
    request: ShareWithUserRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Share a session with another user."""
    if not session_sharing_manager.share_with_user(
        session_id,
        request.user_id,
        str(current_user.id)
    ):
        raise HTTPException(status_code=403, detail="Cannot share session")
    
    return {"status": "shared"}


@router.delete("/sessions/shared/{session_id}/share/{user_id}")
async def revoke_session_access(
    session_id: str,
    user_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Revoke a user's access to a session."""
    if not session_sharing_manager.revoke_user_access(
        session_id,
        user_id,
        str(current_user.id)
    ):
        raise HTTPException(status_code=403, detail="Cannot revoke access")
    
    return {"status": "revoked"}


@router.post("/sessions/shared/{session_id}/join")
async def join_shared_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Join a shared session as a viewer."""
    if not session_sharing_manager.join_session(session_id, str(current_user.id)):
        raise HTTPException(status_code=403, detail="Cannot join session")
    
    return {"status": "joined"}


@router.post("/sessions/shared/{session_id}/leave")
async def leave_shared_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Leave a shared session."""
    session_sharing_manager.leave_session(session_id, str(current_user.id))
    return {"status": "left"}


@router.get("/sessions/shared/token/{token}")
async def get_session_by_token(token: str):
    """Get a shared session by share token (for link sharing)."""
    session = session_sharing_manager.get_session_by_token(token)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    return session.to_dict()


class UpdateSharedSessionRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    access_level: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None


@router.patch("/sessions/shared/{session_id}")
async def update_shared_session(
    session_id: str,
    request: UpdateSharedSessionRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Update shared session settings."""
    session = session_sharing_manager.update_session(
        session_id,
        str(current_user.id),
        name=request.name,
        description=request.description,
        access_level=request.access_level,
        settings=request.settings
    )
    if not session:
        raise HTTPException(status_code=403, detail="Cannot update session")
    
    return session.to_dict()


@router.delete("/sessions/shared/{session_id}")
async def delete_shared_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Delete a shared session."""
    if not session_sharing_manager.delete_session(session_id, str(current_user.id)):
        raise HTTPException(status_code=403, detail="Cannot delete session")
    
    return {"status": "deleted"}


# ============================================================================
# AI-Powered MITM Analysis Endpoints
# ============================================================================

class NaturalLanguageQueryRequest(BaseModel):
    query: str


class FindingGenerationRequest(BaseModel):
    vulnerability_type: str
    affected_endpoint: str
    parameter: str
    evidence: str
    severity: str = "medium"


@router.post("/ai/sensitive-data")
async def analyze_sensitive_data(
    proxy_id: str = Query(..., description="Proxy ID to analyze"),
    current_user: User = Depends(get_current_active_user)
):
    """
    AI-powered sensitive data detection.
    
    Scans traffic for:
    - Credentials (passwords, API keys, tokens)
    - PII (emails, SSNs, phone numbers)
    - Financial data (credit cards)
    - Health information
    
    Returns detected items with risk levels and recommendations.
    """
    if proxy_id not in mitm_service.proxies:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    proxy_data = mitm_service.proxies[proxy_id]
    traffic_entries = list(proxy_data.get("traffic", {}).values())
    
    if not traffic_entries:
        return {
            "matches": [],
            "total": 0,
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
    
    matches = await analyze_traffic_sensitive_data(traffic_entries)
    
    # Build summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for match in matches:
        risk = match.get("risk_level", "medium")
        if risk in summary:
            summary[risk] += 1
    
    return {
        "matches": matches,
        "total": len(matches),
        "summary": summary
    }


@router.post("/ai/injection-points")
async def analyze_injection_points(
    proxy_id: str = Query(..., description="Proxy ID to analyze"),
    entry_id: Optional[str] = Query(None, description="Specific entry to analyze"),
    current_user: User = Depends(get_current_active_user)
):
    """
    AI-powered injection point detection.
    
    Identifies parameters vulnerable to:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Command Injection
    - XXE
    - Server-Side Template Injection
    - Path Traversal
    - IDOR
    
    Returns injection points with confidence scores and suggested payloads.
    """
    if proxy_id not in mitm_service.proxies:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    proxy_data = mitm_service.proxies[proxy_id]
    traffic_entries = list(proxy_data.get("traffic", {}).values())
    
    if entry_id:
        traffic_entries = [e for e in traffic_entries if e.get("id") == entry_id]
        if not traffic_entries:
            raise HTTPException(status_code=404, detail="Entry not found")
    
    if not traffic_entries:
        return {
            "injection_points": [],
            "total": 0,
            "by_type": {}
        }
    
    points = await analyze_traffic_injection_points(traffic_entries)
    
    # Build type summary
    by_type = {}
    for point in points:
        for inj_type in point.get("injection_types", []):
            by_type[inj_type] = by_type.get(inj_type, 0) + 1
    
    return {
        "injection_points": points,
        "total": len(points),
        "by_type": by_type
    }


@router.post("/ai/query")
async def natural_language_traffic_query(
    proxy_id: str = Query(..., description="Proxy ID to query"),
    request: NaturalLanguageQueryRequest = ...,
    current_user: User = Depends(get_current_active_user)
):
    """
    Natural language traffic query.
    
    Query traffic using plain English:
    - "Find all authentication requests"
    - "Show error responses"
    - "Find requests with user IDs"
    - "Show admin endpoints"
    - "Find POST requests with JSON body"
    
    Returns matching traffic entries.
    """
    if proxy_id not in mitm_service.proxies:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    proxy_data = mitm_service.proxies[proxy_id]
    traffic_entries = list(proxy_data.get("traffic", {}).values())
    
    if not traffic_entries:
        return {
            "query": request.query,
            "interpretation": "No traffic to query",
            "matches": [],
            "total_matches": 0
        }
    
    result = await query_traffic_natural_language(traffic_entries, request.query)
    return result


@router.post("/ai/test-cases")
async def generate_test_cases(
    proxy_id: str = Query(..., description="Proxy ID to analyze"),
    entry_id: Optional[str] = Query(None, description="Specific entry to target"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Auto-generate security test cases.
    
    Analyzes traffic and generates test cases for:
    - SQL Injection testing
    - XSS testing
    - Command injection testing
    - Authentication bypass
    - IDOR testing
    
    Each test case includes payloads and expected indicators.
    """
    if proxy_id not in mitm_service.proxies:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    proxy_data = mitm_service.proxies[proxy_id]
    traffic_entries = list(proxy_data.get("traffic", {}).values())
    
    if not traffic_entries:
        return {
            "test_cases": [],
            "total": 0,
            "by_attack_type": {}
        }
    
    test_cases = await generate_security_test_cases(traffic_entries, entry_id)
    
    # Build attack type summary
    by_attack_type = {}
    for tc in test_cases:
        attack = tc.get("attack_type", "unknown")
        by_attack_type[attack] = by_attack_type.get(attack, 0) + 1
    
    return {
        "test_cases": test_cases,
        "total": len(test_cases),
        "by_attack_type": by_attack_type
    }


@router.post("/ai/generate-finding")
async def generate_finding_description(
    request: FindingGenerationRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate a professional vulnerability finding description.
    
    Creates structured findings with:
    - Title
    - Description
    - Impact assessment
    - Remediation steps
    - References
    
    Useful for report generation.
    """
    finding = await generate_vulnerability_finding(
        vulnerability_type=request.vulnerability_type,
        affected_endpoint=request.affected_endpoint,
        parameter=request.parameter,
        evidence=request.evidence,
        severity=request.severity
    )
    return finding


@router.post("/ai/full-analysis")
async def full_ai_analysis(
    proxy_id: str = Query(..., description="Proxy ID to analyze"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Run comprehensive AI analysis on traffic.
    
    Combines all AI analysis features:
    - Sensitive data detection
    - Injection point identification
    - Test case generation
    
    Returns a complete security assessment.
    """
    if proxy_id not in mitm_service.proxies:
        raise HTTPException(status_code=404, detail="Proxy not found")
    
    proxy_data = mitm_service.proxies[proxy_id]
    traffic_entries = list(proxy_data.get("traffic", {}).values())
    
    if not traffic_entries:
        return {
            "sensitive_data": {"matches": [], "total": 0, "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}},
            "injection_points": {"points": [], "total": 0, "by_type": {}},
            "test_cases": {"cases": [], "total": 0, "by_attack_type": {}},
            "traffic_analyzed": 0,
            "risk_score": 0,
            "risk_level": "low"
        }
    
    # Run all analyses in parallel with error handling
    try:
        sensitive_data, injection_points, test_cases = await asyncio.gather(
            analyze_traffic_sensitive_data(traffic_entries),
            analyze_traffic_injection_points(traffic_entries),
            generate_security_test_cases(traffic_entries),
            return_exceptions=True  # Don't fail if one analysis fails
        )
        
        # Handle any exceptions from individual tasks
        if isinstance(sensitive_data, Exception):
            sensitive_data = []
        if isinstance(injection_points, Exception):
            injection_points = []
        if isinstance(test_cases, Exception):
            test_cases = []
    except Exception:
        sensitive_data = []
        injection_points = []
        test_cases = []
    
    # Calculate risk score with defensive null checks
    risk_score = 0
    sensitive_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sd in (sensitive_data or []):
        risk = sd.get("risk_level", "medium") if isinstance(sd, dict) else "medium"
        if risk in sensitive_summary:
            sensitive_summary[risk] += 1
        risk_score += {"critical": 25, "high": 15, "medium": 5, "low": 1}.get(risk, 5)
    
    injection_by_type = {}
    for ip in (injection_points or []):
        if isinstance(ip, dict):
            for inj_type in ip.get("injection_types", []):
                injection_by_type[inj_type] = injection_by_type.get(inj_type, 0) + 1
                risk_score += {"sqli": 20, "cmdi": 20, "xxe": 15, "xss": 10, "ssti": 15, "idor": 10}.get(inj_type, 5)
    
    tc_by_attack = {}
    for tc in (test_cases or []):
        if isinstance(tc, dict):
            attack = tc.get("attack_type", "unknown")
            tc_by_attack[attack] = tc_by_attack.get(attack, 0) + 1
    
    # Normalize risk score (0-100)
    risk_score = min(100, risk_score)
    
    return {
        "sensitive_data": {
            "matches": sensitive_data or [],
            "total": len(sensitive_data) if sensitive_data else 0,
            "summary": sensitive_summary
        },
        "injection_points": {
            "points": injection_points or [],
            "total": len(injection_points) if injection_points else 0,
            "by_type": injection_by_type
        },
        "test_cases": {
            "cases": test_cases or [],
            "total": len(test_cases) if test_cases else 0,
            "by_attack_type": tc_by_attack
        },
        "traffic_analyzed": len(traffic_entries),
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"
    }

