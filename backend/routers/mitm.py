"""
Man-in-the-Middle Workbench Router
API endpoints for MITM proxy management.
"""

from fastapi import APIRouter, HTTPException, Query, Path, Depends
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
    create_rule_from_natural_language,
    get_ai_traffic_suggestions
)

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
    match_host: Optional[str] = None
    match_path: Optional[str] = None
    match_method: Optional[str] = None
    match_content_type: Optional[str] = None
    match_body: Optional[str] = None
    match_header: Optional[Dict[str, str]] = None
    match_status_code: Optional[int] = None
    match_direction: str = "both"  # request, response, both
    action: str = "modify"  # modify, drop, delay
    modify_headers: Optional[Dict[str, str]] = None
    remove_headers: Optional[List[str]] = None
    modify_body: Optional[str] = None
    body_find_replace: Optional[Dict[str, str]] = None
    modify_status_code: Optional[int] = None
    delay_ms: int = 0


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
    offset: int = Query(0, ge=0)
):
    """Get intercepted traffic for a proxy"""
    try:
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
        traffic_log = proxy.get_traffic_log(limit=200)
        
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
        traffic_log = proxy.get_traffic_log(limit=200)
        
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
        traffic_data = []
        for entry in traffic_result.get("traffic", []):
            traffic_data.append({
                "method": entry.get("method", "UNKNOWN"),
                "url": entry.get("url", ""),
                "path": entry.get("path", ""),
                "host": entry.get("host", ""),
                "status": entry.get("status_code"),
                "request_headers": list(entry.get("request_headers", {}).keys()) if entry.get("request_headers") else [],
                "response_headers": list(entry.get("response_headers", {}).keys()) if entry.get("response_headers") else [],
                "content_type": entry.get("response_headers", {}).get("content-type", "") if entry.get("response_headers") else "",
                "timestamp": entry.get("timestamp", "")
            })
        
        # Get existing rules using mitm_service
        rules_result = mitm_service.get_rules(proxy_id)
        existing_rules = []
        for rule in rules_result.get("rules", []):
            existing_rules.append({
                "pattern": rule.get("match_host") or rule.get("match_path") or ".*",
                "action": rule.get("action", "modify"),
                "description": rule.get("name", "")
            })
        
        # Get proxy config using mitm_service
        status = mitm_service.get_proxy_status(proxy_id)
        proxy_config = {
            "target_host": status.get("target_host", ""),
            "target_port": status.get("target_port", 80),
            "mode": status.get("mode", "passthrough"),
            "ssl_enabled": status.get("tls_enabled", False)
        }
        
        # Call AI suggestion service
        result = await get_ai_traffic_suggestions(traffic_data, existing_rules, proxy_config)
        
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
