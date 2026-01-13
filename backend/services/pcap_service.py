"""
PCAP Analysis Service for VRAgent.

Analyzes Wireshark packet captures for security issues including:
- Cleartext credentials (HTTP Basic Auth, FTP, Telnet)
- Suspicious traffic patterns (port scans, beaconing)
- Unencrypted protocols
- DNS queries and HTTP hosts
- Network conversations and statistics

OFFENSIVE SECURITY FEATURES (for sandbox app analysis):
- API endpoint discovery and parameter extraction
- Authentication flow analysis (JWT, tokens, sessions)
- Sensitive data in transit detection
- Protocol weakness identification
- Attack surface mapping and export

Also supports live packet capture using tshark (Wireshark CLI).
"""

import json
import shutil
import subprocess
import tempfile
import re
import base64
import hashlib
import math
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Set
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, unquote

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Try to import scapy - it's optional
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, ICMP, ARP, TLS, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
    SCAPY_AVAILABLE = True
    TLS_AVAILABLE = True
except ImportError:
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, ICMP, ARP, Ether
        from scapy.layers.http import HTTPRequest, HTTPResponse
        SCAPY_AVAILABLE = True
        TLS_AVAILABLE = False
    except ImportError:
        SCAPY_AVAILABLE = False
        TLS_AVAILABLE = False
        logger.warning("scapy not installed. PCAP analysis will be unavailable. Install with: pip install scapy")


@dataclass
class PcapFinding:
    """A security finding from PCAP analysis."""
    category: str  # credential_exposure, cleartext_protocol, suspicious_traffic, etc.
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    packet_number: Optional[int] = None
    evidence: Optional[str] = None  # Relevant packet data (sanitized)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# OFFENSIVE SECURITY DATACLASSES - API & Attack Surface Analysis
# ============================================================================

@dataclass
class APIEndpoint:
    """Discovered API endpoint from traffic analysis."""
    method: str  # GET, POST, PUT, DELETE, PATCH, etc.
    url: str  # Full URL path
    host: str  # Target host
    path: str  # URL path without query string
    query_params: Dict[str, List[str]] = field(default_factory=dict)  # Query parameters
    body_params: Dict[str, str] = field(default_factory=dict)  # POST body parameters
    headers: Dict[str, str] = field(default_factory=dict)  # Request headers
    content_type: Optional[str] = None
    auth_type: Optional[str] = None  # bearer, basic, api_key, cookie, none
    auth_value: Optional[str] = None  # The actual token/key (partially masked)
    response_status: Optional[int] = None
    response_content_type: Optional[str] = None
    request_count: int = 1
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthToken:
    """Extracted authentication token or credential."""
    token_type: str  # jwt, bearer, api_key, session_cookie, basic_auth, oauth
    token_value: str  # The actual token (may be partially masked for display)
    token_hash: str  # SHA256 hash for deduplication
    source_ip: str
    dest_ip: str
    dest_host: str
    endpoint: str  # Where it was used
    header_name: Optional[str] = None  # Authorization, X-API-Key, Cookie, etc.
    issued_at: Optional[str] = None  # For JWTs
    expires_at: Optional[str] = None  # For JWTs
    jwt_algorithm: Optional[str] = None  # HS256, RS256, etc.
    jwt_claims: Optional[Dict[str, Any]] = None  # Decoded JWT payload
    jwt_weaknesses: List[str] = field(default_factory=list)  # Identified issues
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Mask token for display safety
        if len(self.token_value) > 20:
            d["token_value_masked"] = self.token_value[:10] + "..." + self.token_value[-10:]
        return d


@dataclass
class SensitiveDataLeak:
    """Detected sensitive data in network traffic."""
    data_type: str  # pii_email, pii_phone, pii_ssn, api_key, password, internal_ip, debug_info, etc.
    data_value: str  # The actual data (masked if needed)
    context: str  # Where it was found (request body, response, header)
    source_ip: str
    dest_ip: str
    endpoint: Optional[str] = None
    severity: str = "high"
    packet_number: int = 0
    evidence: str = ""  # Surrounding context
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProtocolWeakness:
    """Identified protocol-level security weakness."""
    weakness_type: str  # cleartext_http, weak_tls, no_hsts, weak_cipher, etc.
    protocol: str
    description: str
    source_ip: str
    dest_ip: str
    port: int
    severity: str
    evidence: str
    exploitation_notes: str  # How this could be exploited
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSFingerprint:
    """JA3/JA3S TLS fingerprint for client/server identification."""
    fingerprint_type: str  # ja3, ja3s
    hash: str  # The JA3/JA3S hash
    raw_string: str  # The raw fingerprint string
    source_ip: str
    dest_ip: str
    sni: Optional[str] = None  # Server Name Indication
    known_match: Optional[str] = None  # Known tool/malware if matched
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# ENHANCED PROTOCOL ANALYSIS DATACLASSES
# ============================================================================

@dataclass
class WebSocketMessage:
    """Parsed WebSocket message from traffic."""
    opcode: int  # 1=text, 2=binary, 8=close, 9=ping, 10=pong
    opcode_name: str
    payload: str
    payload_length: int
    is_masked: bool
    direction: str  # "client_to_server" or "server_to_client"
    source_ip: str
    dest_ip: str
    timestamp: float
    packet_number: int
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebSocketSession:
    """A WebSocket session with upgrade handshake and messages."""
    session_id: str
    client_ip: str
    server_ip: str
    server_port: int
    url: str
    upgrade_request: Optional[Dict[str, Any]] = None
    upgrade_response: Optional[Dict[str, Any]] = None
    messages: List[WebSocketMessage] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    message_count: int = 0
    total_bytes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "url": self.url,
            "upgrade_request": self.upgrade_request,
            "upgrade_response": self.upgrade_response,
            "messages": [m.to_dict() for m in self.messages[:100]],  # Limit
            "start_time": self.start_time,
            "end_time": self.end_time,
            "message_count": self.message_count,
            "total_bytes": self.total_bytes,
        }


@dataclass
class GRPCCall:
    """A gRPC call extracted from HTTP/2 traffic."""
    service: str
    method: str
    path: str  # e.g., "/package.Service/Method"
    content_type: str
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    status_code: Optional[int] = None
    grpc_status: Optional[int] = None
    source_ip: str = ""
    dest_ip: str = ""
    duration_ms: Optional[float] = None
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MQTTMessage:
    """An MQTT message from IoT traffic."""
    message_type: str  # CONNECT, PUBLISH, SUBSCRIBE, etc.
    topic: Optional[str] = None
    payload: Optional[str] = None
    qos: int = 0
    retain: bool = False
    client_id: Optional[str] = None
    username: Optional[str] = None
    source_ip: str = ""
    dest_ip: str = ""
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CoAPMessage:
    """A CoAP message from IoT traffic."""
    message_type: str  # CON, NON, ACK, RST
    method: str  # GET, POST, PUT, DELETE for requests
    uri_path: str
    payload: Optional[str] = None
    token: Optional[str] = None
    message_id: int = 0
    source_ip: str = ""
    dest_ip: str = ""
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DatabaseQuery:
    """A database query/command extracted from traffic."""
    protocol: str  # MySQL, PostgreSQL, Redis, MongoDB
    query_type: str  # SELECT, INSERT, UPDATE, DELETE, AUTH, etc.
    query: str
    database: Optional[str] = None
    username: Optional[str] = None
    response_data: Optional[str] = None
    source_ip: str = ""
    dest_ip: str = ""
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HTTPSession:
    """An HTTP request/response pair."""
    session_id: str
    method: str
    url: str
    host: str
    path: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    response_size: int = 0
    source_ip: str = ""
    dest_ip: str = ""
    request_time: Optional[float] = None
    response_time: Optional[float] = None
    duration_ms: Optional[float] = None
    request_packet: int = 0
    response_packet: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Truncate large bodies
        if d.get("request_body") and len(d["request_body"]) > 5000:
            d["request_body"] = d["request_body"][:5000] + "... [truncated]"
        if d.get("response_body") and len(d["response_body"]) > 5000:
            d["response_body"] = d["response_body"][:5000] + "... [truncated]"
        return d


@dataclass
class TCPStream:
    """A reassembled TCP stream."""
    stream_id: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_data: bytes = field(default_factory=bytes)
    server_data: bytes = field(default_factory=bytes)
    protocol: str = "TCP"
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    packets_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "client_port": self.client_port,
            "server_port": self.server_port,
            "client_data_preview": self.client_data[:500].decode('utf-8', errors='replace') if self.client_data else "",
            "server_data_preview": self.server_data[:500].decode('utf-8', errors='replace') if self.server_data else "",
            "client_data_size": len(self.client_data),
            "server_data_size": len(self.server_data),
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "packets_count": self.packets_count,
        }


@dataclass
class ExtractedFile:
    """A file extracted from network traffic."""
    filename: str
    mime_type: str
    size: int
    md5_hash: str
    sha256_hash: str
    source_protocol: str  # HTTP, FTP, SMB
    source_url: Optional[str] = None
    source_ip: str = ""
    dest_ip: str = ""
    content_preview: Optional[str] = None  # First 200 bytes hex
    is_executable: bool = False
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    """A significant event in the capture timeline."""
    timestamp: float
    event_type: str  # connection, request, response, attack, credential, etc.
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    severity: str = "info"  # info, low, medium, high, critical
    details: Dict[str, Any] = field(default_factory=dict)
    packet_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnhancedProtocolAnalysis:
    """Enhanced protocol analysis results."""
    # WebSocket Analysis
    websocket_sessions: List[WebSocketSession] = field(default_factory=list)
    websocket_message_count: int = 0
    
    # gRPC Analysis  
    grpc_calls: List[GRPCCall] = field(default_factory=list)
    grpc_services: List[str] = field(default_factory=list)
    
    # IoT Protocols
    mqtt_messages: List[MQTTMessage] = field(default_factory=list)
    mqtt_topics: List[str] = field(default_factory=list)
    mqtt_clients: List[str] = field(default_factory=list)
    coap_messages: List[CoAPMessage] = field(default_factory=list)
    
    # Database Traffic
    database_queries: List[DatabaseQuery] = field(default_factory=list)
    databases_accessed: List[str] = field(default_factory=list)
    
    # Session Reconstruction
    http_sessions: List[HTTPSession] = field(default_factory=list)
    tcp_streams: List[TCPStream] = field(default_factory=list)
    
    # File Extraction
    extracted_files: List[ExtractedFile] = field(default_factory=list)
    
    # Timeline
    timeline_events: List[TimelineEvent] = field(default_factory=list)
    
    # QUIC Detection
    quic_connections: List[Dict[str, Any]] = field(default_factory=list)
    
    # HTTP/2 Analysis
    http2_streams: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "websocket_sessions": [s.to_dict() for s in self.websocket_sessions],
            "websocket_message_count": self.websocket_message_count,
            "grpc_calls": [c.to_dict() for c in self.grpc_calls],
            "grpc_services": self.grpc_services,
            "mqtt_messages": [m.to_dict() for m in self.mqtt_messages[:100]],
            "mqtt_topics": self.mqtt_topics,
            "mqtt_clients": self.mqtt_clients,
            "coap_messages": [c.to_dict() for c in self.coap_messages[:100]],
            "database_queries": [q.to_dict() for q in self.database_queries[:100]],
            "databases_accessed": self.databases_accessed,
            "http_sessions": [s.to_dict() for s in self.http_sessions[:200]],
            "tcp_streams": [s.to_dict() for s in self.tcp_streams[:50]],
            "extracted_files": [f.to_dict() for f in self.extracted_files],
            "timeline_events": [e.to_dict() for e in self.timeline_events[:500]],
            "quic_connections": self.quic_connections[:50],
            "http2_streams": self.http2_streams[:100],
        }


@dataclass
class AttackSurfaceReport:
    """Complete attack surface analysis from captured traffic."""
    # API Discovery
    total_endpoints: int = 0
    unique_hosts: List[str] = field(default_factory=list)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    
    # Authentication Analysis
    auth_tokens: List[AuthToken] = field(default_factory=list)
    auth_mechanisms: List[str] = field(default_factory=list)  # Types of auth seen
    auth_weaknesses: List[str] = field(default_factory=list)  # Issues found
    
    # Sensitive Data
    sensitive_data_leaks: List[SensitiveDataLeak] = field(default_factory=list)
    
    # Protocol Analysis
    protocol_weaknesses: List[ProtocolWeakness] = field(default_factory=list)
    tls_fingerprints: List[TLSFingerprint] = field(default_factory=list)
    
    # High-Value Targets
    high_value_endpoints: List[Dict[str, Any]] = field(default_factory=list)  # Auth, admin, payment
    
    # Export Formats
    curl_commands: List[str] = field(default_factory=list)
    burp_requests: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_endpoints": self.total_endpoints,
            "unique_hosts": self.unique_hosts,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "auth_tokens": [t.to_dict() for t in self.auth_tokens],
            "auth_mechanisms": self.auth_mechanisms,
            "auth_weaknesses": self.auth_weaknesses,
            "sensitive_data_leaks": [s.to_dict() for s in self.sensitive_data_leaks],
            "protocol_weaknesses": [p.to_dict() for p in self.protocol_weaknesses],
            "tls_fingerprints": [t.to_dict() for t in self.tls_fingerprints],
            "high_value_endpoints": self.high_value_endpoints,
            "curl_commands": self.curl_commands,
            "burp_requests": self.burp_requests,
        }


@dataclass 
class PcapSummary:
    """Summary statistics from PCAP analysis."""
    total_packets: int
    duration_seconds: float
    protocols: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Dict[str, Any]] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)
    potential_issues: int = 0
    # Network topology data for visualization
    topology_nodes: List[Dict[str, Any]] = field(default_factory=list)
    topology_links: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PcapAnalysisResult:
    """Complete PCAP analysis result."""
    filename: str
    summary: PcapSummary
    findings: List[PcapFinding] = field(default_factory=list)
    conversations: List[Dict[str, Any]] = field(default_factory=list)
    ai_analysis: Optional[str] = None
    # Offensive analysis results
    attack_surface: Optional[AttackSurfaceReport] = None
    # Enhanced protocol analysis
    enhanced_protocols: Optional[EnhancedProtocolAnalysis] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "conversations": self.conversations,
            "ai_analysis": self.ai_analysis,
            "attack_surface": self.attack_surface.to_dict() if self.attack_surface else None,
            "enhanced_protocols": self.enhanced_protocols.to_dict() if self.enhanced_protocols else None,
        }


# ============================================================================
# Tshark/Wireshark Live Capture Functions
# ============================================================================

# Available capture profiles with different filters and settings
CAPTURE_PROFILES = {
    "all": {
        "name": "All Traffic",
        "description": "Capture all network traffic",
        "filter": "",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 1,
    },
    "http": {
        "name": "HTTP/HTTPS Traffic",
        "description": "Capture web traffic on ports 80, 443, 8080",
        "filter": "port 80 or port 443 or port 8080",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 2,
    },
    "dns": {
        "name": "DNS Traffic",
        "description": "Capture DNS queries and responses",
        "filter": "port 53",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 2,
    },
    "auth": {
        "name": "Authentication Traffic",
        "description": "Capture FTP, Telnet, SSH, RDP, SMB traffic",
        "filter": "port 21 or port 22 or port 23 or port 3389 or port 445",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 3,
    },
    "email": {
        "name": "Email Traffic",
        "description": "Capture SMTP, POP3, IMAP traffic",
        "filter": "port 25 or port 110 or port 143 or port 465 or port 587 or port 993 or port 995",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 3,
    },
    "database": {
        "name": "Database Traffic",
        "description": "Capture MySQL, PostgreSQL, MSSQL, MongoDB traffic",
        "filter": "port 3306 or port 5432 or port 1433 or port 27017",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 3,
    },
    "suspicious": {
        "name": "Suspicious Ports",
        "description": "Capture traffic on commonly exploited ports",
        "filter": "port 4444 or port 5555 or port 6666 or port 1234 or port 31337 or port 8888",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 4,
    },
    "icmp": {
        "name": "ICMP Traffic",
        "description": "Capture ping and ICMP messages",
        "filter": "icmp",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 2,
    },
    "custom": {
        "name": "Custom Filter",
        "description": "Use a custom BPF capture filter",
        "filter": "",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 5,
    },
}


# ============================================================================
# OFFENSIVE SECURITY ANALYSIS FUNCTIONS
# ============================================================================

# Patterns for sensitive data detection
SENSITIVE_DATA_PATTERNS = {
    "email": (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "pii_email", "medium"),
    "phone_us": (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', "pii_phone", "medium"),
    "ssn": (r'\b\d{3}-\d{2}-\d{4}\b', "pii_ssn", "critical"),
    "credit_card": (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', "pii_credit_card", "critical"),
    "aws_key": (r'AKIA[0-9A-Z]{16}', "api_key_aws", "critical"),
    "aws_secret": (r'[A-Za-z0-9/+=]{40}', "api_secret_aws", "critical"),
    "github_token": (r'ghp_[a-zA-Z0-9]{36}', "api_key_github", "critical"),
    "private_key": (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "private_key", "critical"),
    "password_field": (r'(?:password|passwd|pwd|pass|secret)[\"\']?\s*[:=]\s*[\"\']?[^\s\"\'&]+', "password_field", "high"),
    "bearer_token": (r'[Bb]earer\s+[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*', "bearer_token", "high"),
    "basic_auth": (r'[Bb]asic\s+[A-Za-z0-9+/=]+', "basic_auth", "critical"),
    "api_key_generic": (r'(?:api[_-]?key|apikey|api[_-]?secret)[\"\']?\s*[:=]\s*[\"\']?[A-Za-z0-9_-]{16,}', "api_key_generic", "high"),
    "internal_ip": (r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "internal_ip", "low"),
    "debug_stacktrace": (r'(?:Traceback|Exception|Error|at\s+\w+\.\w+\()', "debug_info", "medium"),
    "sql_error": (r'(?:SQL syntax|mysql_fetch|ORA-\d+|SQLSTATE)', "sql_error", "high"),
    "jwt_token": (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "jwt_token", "high"),
}

# High-value endpoint patterns (for prioritizing attack targets)
HIGH_VALUE_PATTERNS = {
    "auth": [r'/auth', r'/login', r'/logout', r'/signin', r'/signup', r'/register', r'/oauth', r'/token', r'/session'],
    "admin": [r'/admin', r'/dashboard', r'/manage', r'/console', r'/control', r'/settings', r'/config'],
    "payment": [r'/payment', r'/checkout', r'/billing', r'/invoice', r'/subscribe', r'/charge', r'/order'],
    "user_data": [r'/user', r'/profile', r'/account', r'/me', r'/self'],
    "api_sensitive": [r'/api/v\d+/(?:users?|accounts?|credentials?|secrets?|keys?|tokens?)'],
    "file_ops": [r'/upload', r'/download', r'/file', r'/export', r'/import', r'/backup'],
    "debug": [r'/debug', r'/test', r'/dev', r'/staging', r'/internal', r'/_', r'/actuator', r'/swagger', r'/graphql'],
}

# JWT weakness checks
JWT_WEAK_ALGORITHMS = ['none', 'HS256', 'HS384', 'HS512']  # HS* are weak if secret is guessable


def _decode_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], List[str]]:
    """
    Decode a JWT token and analyze for weaknesses.
    
    Returns:
        (header, payload, weaknesses) or (None, None, []) if invalid
    """
    weaknesses = []
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, []
        
        # Decode header
        header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)  # Add padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        
        # Decode payload
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Check for weaknesses
        alg = header.get('alg', '').lower()
        if alg == 'none':
            weaknesses.append("CRITICAL: Algorithm 'none' - signature not verified!")
        elif alg in ['hs256', 'hs384', 'hs512']:
            weaknesses.append(f"Symmetric algorithm ({alg.upper()}) - vulnerable to brute force if weak secret")
        
        # Check expiration
        if 'exp' not in payload:
            weaknesses.append("No expiration claim (exp) - token never expires")
        else:
            import time
            if payload['exp'] < time.time():
                weaknesses.append("Token is EXPIRED but may still be accepted")
            elif payload['exp'] - time.time() > 86400 * 30:  # > 30 days
                weaknesses.append(f"Very long expiration ({(payload['exp'] - time.time()) / 86400:.0f} days)")
        
        # Check for sensitive claims
        sensitive_claims = ['password', 'secret', 'key', 'ssn', 'credit_card']
        for claim in sensitive_claims:
            if claim in payload:
                weaknesses.append(f"Sensitive data in claim: {claim}")
        
        # Check if admin/role claim is present
        if 'admin' in payload or 'role' in payload or 'is_admin' in payload:
            weaknesses.append("Contains role/admin claim - test for privilege escalation")
        
        return header, payload, weaknesses
        
    except Exception as e:
        logger.debug(f"JWT decode failed: {e}")
        return None, None, []


def _calculate_ja3(client_hello_bytes: bytes) -> Optional[str]:
    """
    Calculate JA3 fingerprint from TLS Client Hello.
    
    JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    """
    try:
        # This is a simplified implementation - full JA3 requires proper TLS parsing
        # For now, return a placeholder or use a library if available
        md5_hash = hashlib.md5(client_hello_bytes).hexdigest()
        return md5_hash  # Simplified - real JA3 needs proper parsing
    except Exception:
        return None


def _extract_http_request(payload: bytes, src_ip: str, dst_ip: str, dst_port: int, pkt_num: int) -> Optional[APIEndpoint]:
    """
    Parse HTTP request from raw payload and extract endpoint info.
    """
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        lines = payload_str.split('\r\n')
        
        if not lines:
            return None
        
        # Parse request line: METHOD /path HTTP/1.1
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 2:
            return None
        
        method = parts[0].upper()
        if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
            return None
        
        url_path = parts[1]
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Get host
        host = headers.get('host', dst_ip)
        
        # Parse URL
        if '?' in url_path:
            path, query_string = url_path.split('?', 1)
            query_params = parse_qs(query_string)
        else:
            path = url_path
            query_params = {}
        
        # Parse body parameters
        body_params = {}
        if body_start < len(lines):
            body = '\r\n'.join(lines[body_start:])
            content_type = headers.get('content-type', '')
            
            if 'application/x-www-form-urlencoded' in content_type:
                try:
                    body_params = {k: v[0] if len(v) == 1 else v 
                                   for k, v in parse_qs(body).items()}
                except:
                    pass
            elif 'application/json' in content_type:
                try:
                    body_params = json.loads(body)
                except:
                    pass
        
        # Detect auth type
        auth_type = None
        auth_value = None
        
        auth_header = headers.get('authorization', '')
        if auth_header:
            if auth_header.lower().startswith('bearer '):
                auth_type = 'bearer'
                auth_value = auth_header[7:]
            elif auth_header.lower().startswith('basic '):
                auth_type = 'basic'
                auth_value = auth_header[6:]
        elif 'x-api-key' in headers:
            auth_type = 'api_key'
            auth_value = headers['x-api-key']
        elif 'cookie' in headers:
            cookies = headers['cookie']
            if 'session' in cookies.lower() or 'token' in cookies.lower() or 'auth' in cookies.lower():
                auth_type = 'cookie'
                auth_value = cookies[:100]  # Truncate
        
        return APIEndpoint(
            method=method,
            url=f"http://{host}{url_path}",
            host=host,
            path=path,
            query_params=query_params,
            body_params=body_params,
            headers={k: v for k, v in headers.items() if k in 
                     ['content-type', 'accept', 'user-agent', 'x-requested-with', 'origin', 'referer']},
            content_type=headers.get('content-type'),
            auth_type=auth_type,
            auth_value=auth_value,
            source_ip=src_ip,
            dest_ip=dst_ip,
        )
        
    except Exception as e:
        logger.debug(f"HTTP parsing failed: {e}")
        return None


def _extract_auth_tokens(payload: bytes, src_ip: str, dst_ip: str, dst_host: str, 
                         endpoint: str, pkt_num: int) -> List[AuthToken]:
    """
    Extract authentication tokens from HTTP payload.
    """
    tokens = []
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Look for JWT tokens
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        for match in re.finditer(jwt_pattern, payload_str):
            jwt = match.group()
            token_hash = hashlib.sha256(jwt.encode()).hexdigest()
            header, payload_decoded, weaknesses = _decode_jwt(jwt)
            
            tokens.append(AuthToken(
                token_type='jwt',
                token_value=jwt,
                token_hash=token_hash,
                source_ip=src_ip,
                dest_ip=dst_ip,
                dest_host=dst_host,
                endpoint=endpoint,
                header_name='Authorization' if 'Authorization' in payload_str else None,
                jwt_algorithm=header.get('alg') if header else None,
                jwt_claims=payload_decoded,
                jwt_weaknesses=weaknesses,
                packet_number=pkt_num,
            ))
        
        # Look for Bearer tokens (non-JWT)
        bearer_pattern = r'[Bb]earer\s+([A-Za-z0-9_-]{20,})'
        for match in re.finditer(bearer_pattern, payload_str):
            token = match.group(1)
            if not token.startswith('eyJ'):  # Not a JWT
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                tokens.append(AuthToken(
                    token_type='bearer',
                    token_value=token,
                    token_hash=token_hash,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    dest_host=dst_host,
                    endpoint=endpoint,
                    header_name='Authorization',
                    packet_number=pkt_num,
                ))
        
        # Look for Basic Auth
        basic_pattern = r'[Bb]asic\s+([A-Za-z0-9+/=]+)'
        for match in re.finditer(basic_pattern, payload_str):
            b64_creds = match.group(1)
            try:
                decoded = base64.b64decode(b64_creds).decode('utf-8', errors='ignore')
            except:
                decoded = "[decode failed]"
            token_hash = hashlib.sha256(b64_creds.encode()).hexdigest()
            tokens.append(AuthToken(
                token_type='basic_auth',
                token_value=b64_creds,
                token_hash=token_hash,
                source_ip=src_ip,
                dest_ip=dst_ip,
                dest_host=dst_host,
                endpoint=endpoint,
                header_name='Authorization',
                jwt_claims={"decoded": decoded},
                jwt_weaknesses=["CRITICAL: Basic Auth credentials in cleartext"],
                packet_number=pkt_num,
            ))
        
        # Look for API keys in headers
        api_key_patterns = [
            (r'[Xx]-[Aa][Pp][Ii]-[Kk]ey[:\s]+([A-Za-z0-9_-]{16,})', 'X-API-Key'),
            (r'[Aa]pi[_-]?[Kk]ey[:\s=]+["\']?([A-Za-z0-9_-]{16,})', 'api_key'),
            (r'[Aa]uthorization[:\s]+[Aa]pikey\s+([A-Za-z0-9_-]{16,})', 'Authorization'),
        ]
        for pattern, header_name in api_key_patterns:
            for match in re.finditer(pattern, payload_str):
                key = match.group(1)
                token_hash = hashlib.sha256(key.encode()).hexdigest()
                tokens.append(AuthToken(
                    token_type='api_key',
                    token_value=key,
                    token_hash=token_hash,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    dest_host=dst_host,
                    endpoint=endpoint,
                    header_name=header_name,
                    packet_number=pkt_num,
                ))
        
    except Exception as e:
        logger.debug(f"Token extraction failed: {e}")
    
    return tokens


def _detect_sensitive_data(payload: bytes, src_ip: str, dst_ip: str, 
                            endpoint: str, pkt_num: int) -> List[SensitiveDataLeak]:
    """
    Scan payload for sensitive data leaks with strict noise filtering.
    """
    leaks = []
    seen_values = set()  # Deduplication within this payload
    
    # Skip binary payloads (images, compressed, etc.)
    if not payload or len(payload) < 10:
        return leaks
    
    # Check if payload is mostly binary
    try:
        text_chars = sum(1 for b in payload[:500] if 32 <= b <= 126 or b in (9, 10, 13))
        if text_chars / min(len(payload), 500) < 0.7:
            return leaks  # Skip mostly binary payloads
    except:
        return leaks
    
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Noise exclusion patterns (common false positives)
        noise_exclusions = [
            r'@example\.com',
            r'@test\.com', 
            r'@localhost',
            r'user@host',
            r'no-?reply@',
            r'0\.0\.0\.0',
            r'127\.0\.0\.1',
            r'placeholder',
            r'example',
            r'\$\{',  # Template variables
            r'%[sd]',  # Format strings
        ]
        
        for name, (pattern, data_type, severity) in SENSITIVE_DATA_PATTERNS.items():
            for match in re.finditer(pattern, payload_str, re.IGNORECASE):
                value = match.group()
                
                # Skip if we've seen this exact value
                if value in seen_values:
                    continue
                seen_values.add(value)
                
                # Skip noise/false positives
                is_noise = False
                for noise_pattern in noise_exclusions:
                    if re.search(noise_pattern, value, re.IGNORECASE):
                        is_noise = True
                        break
                if is_noise:
                    continue
                
                # Additional validation per type
                if name == "aws_secret":
                    # AWS secrets are exactly 40 chars of specific charset
                    if not re.match(r'^[A-Za-z0-9/+=]{40}$', value):
                        continue
                    # Must have some variation (not all same char)
                    if len(set(value)) < 10:
                        continue
                        
                if name == "internal_ip":
                    # Skip if it's clearly a version string or not an IP
                    if re.search(r'version|v\d|\.jar|\.zip|\.gz', payload_str[max(0, match.start()-20):match.end()+20], re.IGNORECASE):
                        continue
                        
                if name == "password_field":
                    # Must be in a clear assignment context
                    context_check = payload_str[max(0, match.start()-10):match.end()+10]
                    if 'password' not in context_check.lower() and 'passwd' not in context_check.lower():
                        continue
                        
                if name == "credit_card":
                    # Luhn check for credit cards
                    digits = re.sub(r'[\s-]', '', value)
                    if not _luhn_check(digits):
                        continue
                
                # Get context around the match
                start = max(0, match.start() - 30)
                end = min(len(payload_str), match.end() + 30)
                context = payload_str[start:end]
                
                # Mask the actual value for display
                if len(value) > 8:
                    masked = value[:4] + '*' * (len(value) - 8) + value[-4:]
                else:
                    masked = value
                
                leaks.append(SensitiveDataLeak(
                    data_type=data_type,
                    data_value=masked,
                    context="request" if "HTTP/" not in payload_str[:50] else "response",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    endpoint=endpoint,
                    severity=severity,
                    packet_number=pkt_num,
                    evidence=context.replace(value, masked),
                ))
        
    except Exception as e:
        logger.debug(f"Sensitive data detection failed: {e}")
    
    return leaks


def _luhn_check(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    try:
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0
    except:
        return False


def _classify_endpoint_value(endpoint: APIEndpoint) -> Dict[str, Any]:
    """
    Classify an endpoint as high-value based on patterns.
    """
    classification = {
        "is_high_value": False,
        "categories": [],
        "attack_priority": "low",
        "suggested_tests": [],
    }
    
    path_lower = endpoint.path.lower()
    
    for category, patterns in HIGH_VALUE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                classification["is_high_value"] = True
                classification["categories"].append(category)
    
    # Determine priority
    if "auth" in classification["categories"] or "payment" in classification["categories"]:
        classification["attack_priority"] = "critical"
        classification["suggested_tests"] = [
            "Brute force credentials",
            "Session fixation",
            "Authentication bypass",
            "Token manipulation",
        ]
    elif "admin" in classification["categories"]:
        classification["attack_priority"] = "high"
        classification["suggested_tests"] = [
            "Privilege escalation",
            "IDOR on admin functions",
            "Unauthenticated access",
        ]
    elif "file_ops" in classification["categories"]:
        classification["attack_priority"] = "high"
        classification["suggested_tests"] = [
            "Path traversal",
            "Arbitrary file upload",
            "File type bypass",
        ]
    elif "user_data" in classification["categories"]:
        classification["attack_priority"] = "medium"
        classification["suggested_tests"] = [
            "IDOR",
            "Horizontal privilege escalation",
            "Data enumeration",
        ]
    
    # Add tests based on method and parameters
    if endpoint.method == "POST":
        classification["suggested_tests"].extend([
            "SQL injection on parameters",
            "XSS in input fields",
            "Mass assignment",
        ])
    
    if endpoint.query_params:
        classification["suggested_tests"].append("Parameter tampering")
    
    return classification


def _generate_curl_command(endpoint: APIEndpoint) -> str:
    """
    Generate a curl command to replay the request.
    """
    cmd_parts = ["curl", "-X", endpoint.method]
    
    # Add headers
    for key, value in endpoint.headers.items():
        cmd_parts.extend(["-H", f"'{key}: {value}'"])
    
    # Add auth
    if endpoint.auth_type == "bearer" and endpoint.auth_value:
        cmd_parts.extend(["-H", f"'Authorization: Bearer {endpoint.auth_value}'"])
    elif endpoint.auth_type == "basic" and endpoint.auth_value:
        cmd_parts.extend(["-H", f"'Authorization: Basic {endpoint.auth_value}'"])
    elif endpoint.auth_type == "api_key" and endpoint.auth_value:
        cmd_parts.extend(["-H", f"'X-API-Key: {endpoint.auth_value}'"])
    
    # Add body
    if endpoint.body_params:
        if endpoint.content_type and "json" in endpoint.content_type:
            cmd_parts.extend(["-H", "'Content-Type: application/json'"])
            cmd_parts.extend(["-d", f"'{json.dumps(endpoint.body_params)}'"])
        else:
            body_str = "&".join(f"{k}={v}" for k, v in endpoint.body_params.items())
            cmd_parts.extend(["-d", f"'{body_str}'"])
    
    # Add URL
    cmd_parts.append(f"'{endpoint.url}'")
    
    return " ".join(cmd_parts)


def _generate_burp_request(endpoint: APIEndpoint) -> str:
    """
    Generate a Burp Suite-style raw request.
    """
    # Build request line
    path_with_query = endpoint.path
    if endpoint.query_params:
        query_str = "&".join(f"{k}={v[0] if isinstance(v, list) else v}" 
                            for k, v in endpoint.query_params.items())
        path_with_query = f"{endpoint.path}?{query_str}"
    
    lines = [f"{endpoint.method} {path_with_query} HTTP/1.1"]
    lines.append(f"Host: {endpoint.host}")
    
    # Add headers
    for key, value in endpoint.headers.items():
        lines.append(f"{key}: {value}")
    
    # Add auth header
    if endpoint.auth_type == "bearer" and endpoint.auth_value:
        lines.append(f"Authorization: Bearer {endpoint.auth_value}")
    elif endpoint.auth_type == "basic" and endpoint.auth_value:
        lines.append(f"Authorization: Basic {endpoint.auth_value}")
    elif endpoint.auth_type == "api_key" and endpoint.auth_value:
        lines.append(f"X-API-Key: {endpoint.auth_value}")
    
    # Add body
    body = ""
    if endpoint.body_params:
        if endpoint.content_type and "json" in endpoint.content_type:
            lines.append("Content-Type: application/json")
            body = json.dumps(endpoint.body_params)
        else:
            lines.append("Content-Type: application/x-www-form-urlencoded")
            body = "&".join(f"{k}={v}" for k, v in endpoint.body_params.items())
        lines.append(f"Content-Length: {len(body)}")
    
    lines.append("")  # Empty line before body
    if body:
        lines.append(body)
    
    return "\r\n".join(lines)


def analyze_attack_surface(packets: list, existing_endpoints: List[APIEndpoint] = None) -> AttackSurfaceReport:
    """
    Perform comprehensive offensive security analysis on captured packets.
    
    This analyzes traffic from an offensive perspective to identify:
    - All API endpoints and parameters
    - Authentication tokens and weaknesses
    - Sensitive data leaks
    - Protocol weaknesses
    - High-value attack targets
    """
    report = AttackSurfaceReport()
    
    endpoints: Dict[str, APIEndpoint] = {}  # key = method + path
    tokens_seen: Set[str] = set()  # Track by hash to dedupe
    hosts_seen: Set[str] = set()
    
    for i, pkt in enumerate(packets):
        if IP not in pkt:
            continue
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Process HTTP traffic
        if TCP in pkt and Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)
                dst_port = pkt[TCP].dport
                
                # Try to parse as HTTP request
                if payload[:4] in [b'GET ', b'POST', b'PUT ', b'DELE', b'PATC', b'HEAD', b'OPTI']:
                    endpoint = _extract_http_request(payload, src_ip, dst_ip, dst_port, i)
                    
                    if endpoint:
                        hosts_seen.add(endpoint.host)
                        key = f"{endpoint.method}:{endpoint.path}"
                        
                        if key in endpoints:
                            endpoints[key].request_count += 1
                            # Merge any new parameters
                            for k, v in endpoint.query_params.items():
                                if k not in endpoints[key].query_params:
                                    endpoints[key].query_params[k] = v
                            for k, v in endpoint.body_params.items():
                                if k not in endpoints[key].body_params:
                                    endpoints[key].body_params[k] = v
                        else:
                            endpoints[key] = endpoint
                        
                        # Extract auth tokens
                        dest_host = endpoint.host
                        extracted_tokens = _extract_auth_tokens(
                            payload, src_ip, dst_ip, dest_host, endpoint.path, i
                        )
                        for token in extracted_tokens:
                            if token.token_hash not in tokens_seen:
                                tokens_seen.add(token.token_hash)
                                report.auth_tokens.append(token)
                                if token.token_type not in report.auth_mechanisms:
                                    report.auth_mechanisms.append(token.token_type)
                        
                        # Detect sensitive data
                        leaks = _detect_sensitive_data(payload, src_ip, dst_ip, endpoint.path, i)
                        report.sensitive_data_leaks.extend(leaks)
                
                # Also check HTTP responses for sensitive data
                elif b'HTTP/' in payload[:10]:
                    leaks = _detect_sensitive_data(payload, src_ip, dst_ip, "response", i)
                    report.sensitive_data_leaks.extend(leaks)
                    
            except Exception as e:
                logger.debug(f"Packet {i} analysis failed: {e}")
        
        # Protocol weakness detection
        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            
            # Check for cleartext protocols
            if dport == 80 or sport == 80:
                if Raw in pkt:
                    report.protocol_weaknesses.append(ProtocolWeakness(
                        weakness_type="cleartext_http",
                        protocol="HTTP",
                        description="Application uses unencrypted HTTP",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=80,
                        severity="high",
                        evidence="HTTP traffic on port 80",
                        exploitation_notes="All traffic can be intercepted and modified via MITM attack",
                    ))
            
            # Check for other cleartext protocols
            cleartext_ports = {
                21: ("FTP", "File transfer credentials in cleartext"),
                23: ("Telnet", "Commands and credentials in cleartext"),
                25: ("SMTP", "Email contents in cleartext"),
                110: ("POP3", "Email credentials in cleartext"),
                143: ("IMAP", "Email credentials in cleartext"),
            }
            
            for port, (proto, desc) in cleartext_ports.items():
                if dport == port or sport == port:
                    report.protocol_weaknesses.append(ProtocolWeakness(
                        weakness_type=f"cleartext_{proto.lower()}",
                        protocol=proto,
                        description=desc,
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=port,
                        severity="critical",
                        evidence=f"{proto} traffic on port {port}",
                        exploitation_notes=f"Capture and replay {proto} credentials",
                    ))
    
    # Compile results
    report.endpoints = list(endpoints.values())
    report.total_endpoints = len(report.endpoints)
    report.unique_hosts = list(hosts_seen)
    
    # Classify high-value endpoints
    for endpoint in report.endpoints:
        classification = _classify_endpoint_value(endpoint)
        if classification["is_high_value"]:
            report.high_value_endpoints.append({
                "endpoint": endpoint.to_dict(),
                "classification": classification,
            })
    
    # Compile auth weaknesses
    for token in report.auth_tokens:
        if token.jwt_weaknesses:
            report.auth_weaknesses.extend(token.jwt_weaknesses)
    report.auth_weaknesses = list(set(report.auth_weaknesses))  # Dedupe
    
    # Generate export formats
    for endpoint in report.endpoints[:50]:  # Limit to 50 for performance
        report.curl_commands.append(_generate_curl_command(endpoint))
        report.burp_requests.append(_generate_burp_request(endpoint))
    
    # Deduplicate protocol weaknesses by type + port
    seen_weaknesses: Set[str] = set()
    unique_weaknesses: List[ProtocolWeakness] = []
    for w in report.protocol_weaknesses:
        key = f"{w.weakness_type}:{w.port}"
        if key not in seen_weaknesses:
            seen_weaknesses.add(key)
            unique_weaknesses.append(w)
    report.protocol_weaknesses = unique_weaknesses[:20]  # Limit
    
    # Deduplicate sensitive data leaks
    seen_leaks: Set[str] = set()
    unique_leaks: List[SensitiveDataLeak] = []
    for leak in report.sensitive_data_leaks:
        key = f"{leak.data_type}:{leak.data_value}"
        if key not in seen_leaks:
            seen_leaks.add(key)
            unique_leaks.append(leak)
    report.sensitive_data_leaks = unique_leaks[:100]  # Limit
    
    logger.info(f"Attack surface analysis: {report.total_endpoints} endpoints, "
                f"{len(report.auth_tokens)} tokens, {len(report.sensitive_data_leaks)} leaks")
    
    return report


# ============================================================================
# ENHANCED PROTOCOL ANALYSIS FUNCTIONS
# ============================================================================

def _parse_websocket_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a WebSocket frame from raw bytes.
    Returns frame info or None if not a valid WebSocket frame.
    """
    if len(data) < 2:
        return None
    
    try:
        # First byte: FIN + RSV + Opcode
        first_byte = data[0]
        fin = (first_byte >> 7) & 1
        opcode = first_byte & 0x0F
        
        # Second byte: MASK + Payload length
        second_byte = data[1]
        masked = (second_byte >> 7) & 1
        payload_len = second_byte & 0x7F
        
        offset = 2
        
        # Extended payload length
        if payload_len == 126:
            if len(data) < 4:
                return None
            payload_len = int.from_bytes(data[2:4], 'big')
            offset = 4
        elif payload_len == 127:
            if len(data) < 10:
                return None
            payload_len = int.from_bytes(data[2:10], 'big')
            offset = 10
        
        # Masking key
        mask_key = None
        if masked:
            if len(data) < offset + 4:
                return None
            mask_key = data[offset:offset + 4]
            offset += 4
        
        # Payload
        if len(data) < offset + payload_len:
            payload_data = data[offset:]  # Partial
        else:
            payload_data = data[offset:offset + payload_len]
        
        # Unmask if needed
        if masked and mask_key:
            unmasked = bytearray(len(payload_data))
            for i, byte in enumerate(payload_data):
                unmasked[i] = byte ^ mask_key[i % 4]
            payload_data = bytes(unmasked)
        
        opcode_names = {
            0: "continuation",
            1: "text",
            2: "binary",
            8: "close",
            9: "ping",
            10: "pong",
        }
        
        return {
            "fin": fin,
            "opcode": opcode,
            "opcode_name": opcode_names.get(opcode, f"unknown_{opcode}"),
            "masked": bool(masked),
            "payload_length": payload_len,
            "payload": payload_data.decode('utf-8', errors='replace') if opcode == 1 else payload_data.hex()[:200],
        }
    except Exception as e:
        logger.debug(f"WebSocket frame parse error: {e}")
        return None


def _detect_websocket_upgrade(payload: bytes) -> Optional[Dict[str, Any]]:
    """Detect and parse WebSocket upgrade handshake."""
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Check for upgrade request
        if 'Upgrade: websocket' in payload_str or 'upgrade: websocket' in payload_str:
            lines = payload_str.split('\r\n')
            headers = {}
            request_line = lines[0] if lines else ""
            
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Parse request line for path
            parts = request_line.split(' ')
            path = parts[1] if len(parts) > 1 else "/"
            
            if 'sec-websocket-key' in headers:
                return {
                    "type": "request",
                    "path": path,
                    "host": headers.get('host', ''),
                    "sec_websocket_key": headers.get('sec-websocket-key', ''),
                    "sec_websocket_version": headers.get('sec-websocket-version', ''),
                    "origin": headers.get('origin', ''),
                    "protocols": headers.get('sec-websocket-protocol', ''),
                }
            elif 'sec-websocket-accept' in headers:
                return {
                    "type": "response",
                    "sec_websocket_accept": headers.get('sec-websocket-accept', ''),
                    "protocols": headers.get('sec-websocket-protocol', ''),
                }
    except Exception as e:
        logger.debug(f"WebSocket upgrade detection error: {e}")
    
    return None


def _parse_mqtt_packet(data: bytes) -> Optional[MQTTMessage]:
    """Parse MQTT packet from raw bytes."""
    if len(data) < 2:
        return None
    
    try:
        # MQTT packet type is in the first 4 bits of first byte
        packet_type = (data[0] >> 4) & 0x0F
        
        mqtt_types = {
            1: "CONNECT",
            2: "CONNACK",
            3: "PUBLISH",
            4: "PUBACK",
            5: "PUBREC",
            6: "PUBREL",
            7: "PUBCOMP",
            8: "SUBSCRIBE",
            9: "SUBACK",
            10: "UNSUBSCRIBE",
            11: "UNSUBACK",
            12: "PINGREQ",
            13: "PINGRESP",
            14: "DISCONNECT",
        }
        
        if packet_type not in mqtt_types:
            return None
        
        msg = MQTTMessage(message_type=mqtt_types[packet_type])
        
        # Parse CONNECT for client info
        if packet_type == 1:  # CONNECT
            # Skip remaining length and protocol name/version
            if len(data) > 12:
                # Try to find client ID
                try:
                    # After variable header, look for client ID
                    idx = 12  # Approximate offset
                    if idx + 2 < len(data):
                        client_id_len = int.from_bytes(data[idx:idx+2], 'big')
                        if idx + 2 + client_id_len <= len(data):
                            msg.client_id = data[idx+2:idx+2+client_id_len].decode('utf-8', errors='replace')
                except:
                    pass
        
        # Parse PUBLISH for topic and payload
        elif packet_type == 3:  # PUBLISH
            qos = (data[0] >> 1) & 0x03
            retain = data[0] & 0x01
            msg.qos = qos
            msg.retain = bool(retain)
            
            # Get remaining length
            multiplier = 1
            remaining_len = 0
            idx = 1
            while idx < len(data) and idx < 5:
                byte = data[idx]
                remaining_len += (byte & 0x7F) * multiplier
                multiplier *= 128
                idx += 1
                if (byte & 0x80) == 0:
                    break
            
            # Topic length is next 2 bytes
            if idx + 2 < len(data):
                topic_len = int.from_bytes(data[idx:idx+2], 'big')
                if idx + 2 + topic_len <= len(data):
                    msg.topic = data[idx+2:idx+2+topic_len].decode('utf-8', errors='replace')
                    
                    # Payload starts after topic (and message ID if QoS > 0)
                    payload_start = idx + 2 + topic_len
                    if qos > 0:
                        payload_start += 2  # Skip message ID
                    
                    if payload_start < len(data):
                        msg.payload = data[payload_start:payload_start+200].decode('utf-8', errors='replace')
        
        return msg
        
    except Exception as e:
        logger.debug(f"MQTT parse error: {e}")
        return None


def _parse_coap_packet(data: bytes) -> Optional[CoAPMessage]:
    """Parse CoAP packet from raw bytes (typically UDP port 5683)."""
    if len(data) < 4:
        return None
    
    try:
        # CoAP header format
        version = (data[0] >> 6) & 0x03
        if version != 1:  # CoAP version must be 1
            return None
        
        msg_type = (data[0] >> 4) & 0x03
        token_len = data[0] & 0x0F
        code = data[1]
        message_id = int.from_bytes(data[2:4], 'big')
        
        type_names = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
        
        # Code format: class.detail
        code_class = (code >> 5) & 0x07
        code_detail = code & 0x1F
        
        method = ""
        if code_class == 0:  # Method
            methods = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE"}
            method = methods.get(code_detail, f"0.{code_detail:02d}")
        else:
            method = f"{code_class}.{code_detail:02d}"  # Response code
        
        msg = CoAPMessage(
            message_type=type_names.get(msg_type, str(msg_type)),
            method=method,
            uri_path="",
            message_id=message_id,
        )
        
        # Extract token
        idx = 4
        if token_len > 0 and idx + token_len <= len(data):
            msg.token = data[idx:idx+token_len].hex()
            idx += token_len
        
        # Parse options to find Uri-Path
        uri_parts = []
        prev_opt_number = 0
        
        while idx < len(data) and data[idx] != 0xFF:  # 0xFF = payload marker
            if data[idx] == 0x00:
                break
            
            delta = (data[idx] >> 4) & 0x0F
            length = data[idx] & 0x0F
            idx += 1
            
            # Extended delta/length handling
            if delta == 13:
                delta = data[idx] + 13
                idx += 1
            elif delta == 14:
                delta = int.from_bytes(data[idx:idx+2], 'big') + 269
                idx += 2
            
            if length == 13:
                length = data[idx] + 13
                idx += 1
            elif length == 14:
                length = int.from_bytes(data[idx:idx+2], 'big') + 269
                idx += 2
            
            opt_number = prev_opt_number + delta
            prev_opt_number = opt_number
            
            if idx + length <= len(data):
                opt_value = data[idx:idx+length]
                idx += length
                
                # Uri-Path option (11)
                if opt_number == 11:
                    uri_parts.append(opt_value.decode('utf-8', errors='replace'))
        
        msg.uri_path = "/" + "/".join(uri_parts) if uri_parts else "/"
        
        # Extract payload if present
        if idx < len(data) and data[idx] == 0xFF:
            idx += 1
            if idx < len(data):
                msg.payload = data[idx:idx+200].decode('utf-8', errors='replace')
        
        return msg
        
    except Exception as e:
        logger.debug(f"CoAP parse error: {e}")
        return None


def _parse_mysql_packet(data: bytes, direction: str) -> Optional[DatabaseQuery]:
    """Parse MySQL protocol packet."""
    if len(data) < 5:
        return None
    
    try:
        # MySQL packet header: 3 bytes length, 1 byte sequence ID
        payload_len = int.from_bytes(data[0:3], 'little')
        seq_id = data[3]
        
        if len(data) < 4 + payload_len:
            return None
        
        payload = data[4:4+payload_len]
        
        if len(payload) < 1:
            return None
        
        command = payload[0]
        
        mysql_commands = {
            0x00: "SLEEP",
            0x01: "QUIT",
            0x02: "INIT_DB",
            0x03: "QUERY",
            0x04: "FIELD_LIST",
            0x05: "CREATE_DB",
            0x06: "DROP_DB",
            0x16: "STMT_PREPARE",
            0x17: "STMT_EXECUTE",
            0x19: "STMT_CLOSE",
        }
        
        # Focus on queries and auth
        if command == 0x03:  # COM_QUERY
            query_text = payload[1:].decode('utf-8', errors='replace')
            
            # Determine query type
            query_upper = query_text.strip().upper()
            if query_upper.startswith("SELECT"):
                query_type = "SELECT"
            elif query_upper.startswith("INSERT"):
                query_type = "INSERT"
            elif query_upper.startswith("UPDATE"):
                query_type = "UPDATE"
            elif query_upper.startswith("DELETE"):
                query_type = "DELETE"
            elif query_upper.startswith("CREATE"):
                query_type = "CREATE"
            elif query_upper.startswith("DROP"):
                query_type = "DROP"
            elif query_upper.startswith("ALTER"):
                query_type = "ALTER"
            else:
                query_type = "OTHER"
            
            return DatabaseQuery(
                protocol="MySQL",
                query_type=query_type,
                query=query_text[:1000],
            )
        
        elif command == 0x02:  # COM_INIT_DB
            db_name = payload[1:].decode('utf-8', errors='replace')
            return DatabaseQuery(
                protocol="MySQL",
                query_type="USE_DATABASE",
                query=f"USE {db_name}",
                database=db_name,
            )
        
    except Exception as e:
        logger.debug(f"MySQL parse error: {e}")
    
    return None


def _parse_postgresql_packet(data: bytes, direction: str) -> Optional[DatabaseQuery]:
    """Parse PostgreSQL protocol packet."""
    if len(data) < 5:
        return None
    
    try:
        # PostgreSQL message format: 1 byte type, 4 bytes length
        msg_type = chr(data[0]) if data[0] < 128 else None
        
        if msg_type == 'Q':  # Simple Query
            msg_len = int.from_bytes(data[1:5], 'big')
            if len(data) >= 5 + msg_len - 4:
                query = data[5:5+msg_len-5].decode('utf-8', errors='replace').rstrip('\x00')
                
                query_upper = query.strip().upper()
                if query_upper.startswith("SELECT"):
                    query_type = "SELECT"
                elif query_upper.startswith("INSERT"):
                    query_type = "INSERT"
                elif query_upper.startswith("UPDATE"):
                    query_type = "UPDATE"
                elif query_upper.startswith("DELETE"):
                    query_type = "DELETE"
                else:
                    query_type = "OTHER"
                
                return DatabaseQuery(
                    protocol="PostgreSQL",
                    query_type=query_type,
                    query=query[:1000],
                )
        
        elif msg_type == 'P':  # Parse (prepared statement)
            return DatabaseQuery(
                protocol="PostgreSQL",
                query_type="PREPARE",
                query="[Prepared Statement]",
            )
        
        # Startup message (no type byte, just length + protocol version)
        elif data[0:4] == b'\x00\x00\x00':  # Length at start
            msg_len = int.from_bytes(data[0:4], 'big')
            if msg_len > 8 and len(data) >= msg_len:
                # Look for user= in startup params
                params = data[8:msg_len].split(b'\x00')
                username = None
                database = None
                for i, param in enumerate(params):
                    if param == b'user' and i + 1 < len(params):
                        username = params[i+1].decode('utf-8', errors='replace')
                    elif param == b'database' and i + 1 < len(params):
                        database = params[i+1].decode('utf-8', errors='replace')
                
                if username:
                    return DatabaseQuery(
                        protocol="PostgreSQL",
                        query_type="CONNECT",
                        query=f"Connection from user: {username}",
                        username=username,
                        database=database,
                    )
        
    except Exception as e:
        logger.debug(f"PostgreSQL parse error: {e}")
    
    return None


def _parse_redis_command(data: bytes) -> Optional[DatabaseQuery]:
    """Parse Redis RESP protocol command."""
    if len(data) < 3:
        return None
    
    try:
        # Redis RESP protocol starts with type byte
        text = data.decode('utf-8', errors='replace')
        
        # Array format: *<count>\r\n$<len>\r\n<data>\r\n...
        if text.startswith('*'):
            lines = text.split('\r\n')
            if len(lines) < 3:
                return None
            
            # Extract command parts
            parts = []
            i = 1
            while i < len(lines):
                if lines[i].startswith('$'):
                    if i + 1 < len(lines):
                        parts.append(lines[i + 1])
                    i += 2
                else:
                    i += 1
            
            if parts:
                command = parts[0].upper()
                query_type = "READ" if command in ['GET', 'MGET', 'HGET', 'HGETALL', 'LRANGE', 'SMEMBERS', 'KEYS'] else "WRITE"
                
                return DatabaseQuery(
                    protocol="Redis",
                    query_type=query_type,
                    query=' '.join(parts)[:500],
                )
        
        # Simple inline command
        elif text.strip():
            parts = text.strip().split()
            if parts:
                return DatabaseQuery(
                    protocol="Redis",
                    query_type="COMMAND",
                    query=text.strip()[:500],
                )
        
    except Exception as e:
        logger.debug(f"Redis parse error: {e}")
    
    return None


def _detect_quic(data: bytes, src_port: int, dst_port: int) -> Optional[Dict[str, Any]]:
    """Detect QUIC/HTTP3 traffic."""
    if len(data) < 5:
        return None
    
    try:
        # QUIC long header starts with 0x80-0xFF
        first_byte = data[0]
        
        if first_byte & 0x80:  # Long header
            # Version is bytes 1-4
            version = int.from_bytes(data[1:5], 'big')
            
            # Known QUIC versions
            quic_versions = {
                0x00000001: "RFC 9000 (QUIC v1)",
                0xff000000: "Draft Version",
                0x51474F00: "Google QUIC (Q000)",
            }
            
            # Check for QUIC version patterns
            if version in quic_versions or (version & 0xff000000) == 0xff000000:
                # Destination Connection ID length
                dcid_len = data[5] if len(data) > 5 else 0
                
                return {
                    "version": hex(version),
                    "version_name": quic_versions.get(version, f"Draft {version & 0xFF}" if (version & 0xff000000) == 0xff000000 else "Unknown"),
                    "dcid_length": dcid_len,
                    "header_type": "long",
                    "likely_http3": dst_port == 443 or src_port == 443,
                }
        
        # Short header (after connection established)
        # Harder to detect without connection state
        
    except Exception as e:
        logger.debug(f"QUIC detection error: {e}")
    
    return None


def _detect_http2_preface(data: bytes) -> bool:
    """Detect HTTP/2 connection preface."""
    HTTP2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    return data.startswith(HTTP2_PREFACE)


def _detect_grpc(data: bytes, content_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Detect and parse gRPC traffic markers."""
    try:
        # gRPC uses application/grpc content-type
        if content_type and 'grpc' in content_type.lower():
            return {"detected": True, "via": "content-type"}
        
        # gRPC length-prefixed message format: 1 byte compression, 4 bytes length
        if len(data) >= 5:
            compression = data[0]
            msg_len = int.from_bytes(data[1:5], 'big')
            
            # Reasonable message length and valid compression flag
            if compression in (0, 1) and 0 < msg_len < 10000000:
                if len(data) >= 5 + msg_len:
                    return {
                        "detected": True,
                        "via": "length-prefix",
                        "compressed": bool(compression),
                        "message_length": msg_len,
                    }
        
    except Exception as e:
        logger.debug(f"gRPC detection error: {e}")
    
    return None


def _extract_file_from_http(headers: Dict[str, str], body: bytes, url: str) -> Optional[ExtractedFile]:
    """Extract file metadata from HTTP response."""
    if not body or len(body) < 10:
        return None
    
    try:
        content_type = headers.get('content-type', '').lower()
        content_disp = headers.get('content-disposition', '')
        
        # Determine filename
        filename = None
        if 'filename=' in content_disp:
            match = re.search(r'filename=["\']?([^"\';\s]+)', content_disp)
            if match:
                filename = match.group(1)
        
        if not filename:
            # Try to extract from URL
            path = urlparse(url).path
            if path and '/' in path:
                filename = path.split('/')[-1]
                if '?' in filename:
                    filename = filename.split('?')[0]
        
        if not filename:
            filename = "unknown_file"
        
        # Determine MIME type
        mime_type = content_type.split(';')[0].strip() if content_type else "application/octet-stream"
        
        # Check if this is a downloadable file type
        file_types = [
            'application/pdf',
            'application/zip',
            'application/x-rar',
            'application/x-7z-compressed',
            'application/octet-stream',
            'application/x-executable',
            'application/x-msdownload',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats',
            'image/',
            'audio/',
            'video/',
        ]
        
        is_file = any(ft in mime_type for ft in file_types) or 'attachment' in content_disp.lower()
        
        if not is_file and len(body) < 1000:
            return None  # Skip small non-file responses
        
        # Calculate hashes
        md5_hash = hashlib.md5(body).hexdigest()
        sha256_hash = hashlib.sha256(body).hexdigest()
        
        # Check for executable
        is_executable = (
            body[:2] == b'MZ' or  # PE/EXE
            body[:4] == b'\x7fELF' or  # ELF
            body[:4] == b'\xfe\xed\xfa\xce' or  # Mach-O
            body[:4] == b'\xce\xfa\xed\xfe' or  # Mach-O (reverse)
            body[:2] == b'#!' or  # Script
            'executable' in mime_type or
            'x-msdownload' in mime_type
        )
        
        return ExtractedFile(
            filename=filename,
            mime_type=mime_type,
            size=len(body),
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
            source_protocol="HTTP",
            source_url=url,
            content_preview=body[:100].hex(),
            is_executable=is_executable,
        )
        
    except Exception as e:
        logger.debug(f"File extraction error: {e}")
    
    return None


def analyze_enhanced_protocols(packets: list) -> EnhancedProtocolAnalysis:
    """
    Perform enhanced protocol analysis on captured packets.
    
    This includes:
    - WebSocket session detection and message parsing
    - gRPC/HTTP2 detection
    - MQTT/CoAP IoT protocol parsing
    - Database protocol analysis (MySQL, PostgreSQL, Redis)
    - HTTP session reconstruction
    - TCP stream reassembly
    - File extraction from HTTP
    - Timeline event generation
    - QUIC/HTTP3 detection
    """
    result = EnhancedProtocolAnalysis()
    
    # Track TCP streams for reassembly
    tcp_streams: Dict[str, TCPStream] = {}
    
    # Track HTTP request/response pairs
    http_requests: Dict[str, Dict[str, Any]] = {}  # key = src:sport->dst:dport
    
    # Track WebSocket sessions
    ws_sessions: Dict[str, WebSocketSession] = {}
    ws_upgraded: Set[str] = set()  # Connections that have upgraded to WebSocket
    
    # Track seen items for deduplication
    seen_mqtt_topics: Set[str] = set()
    seen_mqtt_clients: Set[str] = set()
    seen_grpc_services: Set[str] = set()
    seen_databases: Set[str] = set()
    
    for i, pkt in enumerate(packets):
        try:
            timestamp = float(pkt.time) if hasattr(pkt, 'time') else 0
            
            if IP not in pkt:
                continue
            
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # UDP-based protocols
            if UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    
                    # MQTT over UDP (rare but possible)
                    if dst_port == 1883 or src_port == 1883:
                        mqtt_msg = _parse_mqtt_packet(payload)
                        if mqtt_msg:
                            mqtt_msg.source_ip = src_ip
                            mqtt_msg.dest_ip = dst_ip
                            mqtt_msg.packet_number = i
                            result.mqtt_messages.append(mqtt_msg)
                            
                            if mqtt_msg.topic and mqtt_msg.topic not in seen_mqtt_topics:
                                seen_mqtt_topics.add(mqtt_msg.topic)
                                result.mqtt_topics.append(mqtt_msg.topic)
                            if mqtt_msg.client_id and mqtt_msg.client_id not in seen_mqtt_clients:
                                seen_mqtt_clients.add(mqtt_msg.client_id)
                                result.mqtt_clients.append(mqtt_msg.client_id)
                    
                    # CoAP (UDP port 5683)
                    if dst_port == 5683 or src_port == 5683:
                        coap_msg = _parse_coap_packet(payload)
                        if coap_msg:
                            coap_msg.source_ip = src_ip
                            coap_msg.dest_ip = dst_ip
                            coap_msg.packet_number = i
                            result.coap_messages.append(coap_msg)
                    
                    # QUIC detection (typically UDP 443)
                    if dst_port == 443 or src_port == 443:
                        quic_info = _detect_quic(payload, src_port, dst_port)
                        if quic_info:
                            quic_info.update({
                                "source_ip": src_ip,
                                "dest_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "packet_number": i,
                            })
                            result.quic_connections.append(quic_info)
                            
                            # Add timeline event for QUIC detection
                            result.timeline_events.append(TimelineEvent(
                                timestamp=timestamp,
                                event_type="protocol",
                                description=f"QUIC/HTTP3 connection detected: {quic_info.get('version_name', 'Unknown')}",
                                source_ip=src_ip,
                                dest_ip=dst_ip,
                                protocol="QUIC",
                                severity="info",
                                packet_number=i,
                            ))
            
            # TCP-based protocols
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                
                # Create stream identifier
                stream_key = f"{min(src_ip, dst_ip)}:{min(src_port, dst_port)}-{max(src_ip, dst_ip)}:{max(src_port, dst_port)}"
                
                # Determine direction (who initiated based on port numbers)
                is_client_to_server = dst_port < src_port or dst_port in [80, 443, 8080, 3306, 5432, 6379, 1883, 27017]
                
                # TCP stream reassembly
                if stream_key not in tcp_streams:
                    if is_client_to_server:
                        tcp_streams[stream_key] = TCPStream(
                            stream_id=stream_key,
                            client_ip=src_ip,
                            server_ip=dst_ip,
                            client_port=src_port,
                            server_port=dst_port,
                            start_time=timestamp,
                        )
                    else:
                        tcp_streams[stream_key] = TCPStream(
                            stream_id=stream_key,
                            client_ip=dst_ip,
                            server_ip=src_ip,
                            client_port=dst_port,
                            server_port=src_port,
                            start_time=timestamp,
                        )
                
                stream = tcp_streams[stream_key]
                stream.packets_count += 1
                stream.end_time = timestamp
                
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    
                    # Add to stream data
                    if src_ip == stream.client_ip:
                        stream.client_data += payload
                    else:
                        stream.server_data += payload
                    
                    # HTTP key for request/response matching
                    http_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                    http_key_reverse = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                    
                    # WebSocket check - look for upgrade or check if already upgraded
                    ws_key = stream_key
                    
                    if ws_key in ws_upgraded:
                        # Parse WebSocket frames
                        frame = _parse_websocket_frame(payload)
                        if frame:
                            direction = "client_to_server" if is_client_to_server else "server_to_client"
                            ws_msg = WebSocketMessage(
                                opcode=frame["opcode"],
                                opcode_name=frame["opcode_name"],
                                payload=frame["payload"],
                                payload_length=frame["payload_length"],
                                is_masked=frame["masked"],
                                direction=direction,
                                source_ip=src_ip,
                                dest_ip=dst_ip,
                                timestamp=timestamp,
                                packet_number=i,
                            )
                            
                            if ws_key in ws_sessions:
                                ws_sessions[ws_key].messages.append(ws_msg)
                                ws_sessions[ws_key].message_count += 1
                                ws_sessions[ws_key].total_bytes += frame["payload_length"]
                                ws_sessions[ws_key].end_time = timestamp
                    
                    else:
                        # Check for WebSocket upgrade
                        upgrade_info = _detect_websocket_upgrade(payload)
                        if upgrade_info:
                            if upgrade_info["type"] == "request":
                                ws_sessions[ws_key] = WebSocketSession(
                                    session_id=ws_key,
                                    client_ip=src_ip,
                                    server_ip=dst_ip,
                                    server_port=dst_port,
                                    url=upgrade_info.get("path", "/"),
                                    upgrade_request=upgrade_info,
                                    start_time=timestamp,
                                )
                                
                                result.timeline_events.append(TimelineEvent(
                                    timestamp=timestamp,
                                    event_type="websocket",
                                    description=f"WebSocket upgrade requested to {upgrade_info.get('path', '/')}",
                                    source_ip=src_ip,
                                    dest_ip=dst_ip,
                                    protocol="WebSocket",
                                    severity="info",
                                    packet_number=i,
                                ))
                            
                            elif upgrade_info["type"] == "response":
                                if ws_key in ws_sessions:
                                    ws_sessions[ws_key].upgrade_response = upgrade_info
                                    ws_upgraded.add(ws_key)
                                    
                                    result.timeline_events.append(TimelineEvent(
                                        timestamp=timestamp,
                                        event_type="websocket",
                                        description="WebSocket connection established",
                                        source_ip=src_ip,
                                        dest_ip=dst_ip,
                                        protocol="WebSocket",
                                        severity="info",
                                        packet_number=i,
                                    ))
                    
                    # HTTP request detection and reconstruction
                    if payload[:4] in [b'GET ', b'POST', b'PUT ', b'DELE', b'PATC', b'HEAD', b'OPTI']:
                        try:
                            payload_str = payload.decode('utf-8', errors='ignore')
                            lines = payload_str.split('\r\n')
                            request_line = lines[0]
                            parts = request_line.split(' ')
                            
                            if len(parts) >= 2:
                                method = parts[0]
                                path = parts[1]
                                
                                # Parse headers
                                headers = {}
                                body_start = 0
                                for j, line in enumerate(lines[1:], 1):
                                    if line == '':
                                        body_start = j + 1
                                        break
                                    if ':' in line:
                                        key, value = line.split(':', 1)
                                        headers[key.strip().lower()] = value.strip()
                                
                                host = headers.get('host', dst_ip)
                                url = f"http://{host}{path}"
                                
                                # Extract body
                                body = None
                                if body_start < len(lines):
                                    body = '\r\n'.join(lines[body_start:])
                                
                                session_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{i}"
                                
                                http_requests[http_key] = {
                                    "session_id": session_id,
                                    "method": method,
                                    "url": url,
                                    "host": host,
                                    "path": path,
                                    "headers": headers,
                                    "body": body,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "timestamp": timestamp,
                                    "packet": i,
                                    "content_type": headers.get('content-type', ''),
                                }
                                
                                # Check for gRPC
                                if 'grpc' in headers.get('content-type', '').lower():
                                    # Extract gRPC service and method from path
                                    if path.startswith('/') and '/' in path[1:]:
                                        path_parts = path[1:].split('/')
                                        if len(path_parts) >= 2:
                                            service = path_parts[0]
                                            grpc_method = path_parts[1]
                                            
                                            result.grpc_calls.append(GRPCCall(
                                                service=service,
                                                method=grpc_method,
                                                path=path,
                                                content_type=headers.get('content-type', ''),
                                                source_ip=src_ip,
                                                dest_ip=dst_ip,
                                                packet_number=i,
                                            ))
                                            
                                            if service not in seen_grpc_services:
                                                seen_grpc_services.add(service)
                                                result.grpc_services.append(service)
                                
                                # Timeline event
                                result.timeline_events.append(TimelineEvent(
                                    timestamp=timestamp,
                                    event_type="http_request",
                                    description=f"{method} {path}",
                                    source_ip=src_ip,
                                    dest_ip=dst_ip,
                                    protocol="HTTP",
                                    severity="info",
                                    details={"host": host, "method": method},
                                    packet_number=i,
                                ))
                        
                        except Exception as e:
                            logger.debug(f"HTTP request parsing error: {e}")
                    
                    # HTTP response detection
                    elif payload[:5] == b'HTTP/':
                        try:
                            payload_str = payload.decode('utf-8', errors='ignore')
                            lines = payload_str.split('\r\n')
                            status_line = lines[0]
                            
                            # Parse status code
                            parts = status_line.split(' ', 2)
                            status_code = int(parts[1]) if len(parts) >= 2 else 0
                            
                            # Parse headers
                            headers = {}
                            body_start = 0
                            for j, line in enumerate(lines[1:], 1):
                                if line == '':
                                    body_start = j + 1
                                    break
                                if ':' in line:
                                    key, value = line.split(':', 1)
                                    headers[key.strip().lower()] = value.strip()
                            
                            # Extract body
                            body = None
                            body_bytes = b''
                            if body_start < len(lines):
                                body = '\r\n'.join(lines[body_start:])
                                body_bytes = body.encode('utf-8', errors='ignore')
                            
                            # Match with request
                            if http_key_reverse in http_requests:
                                req = http_requests[http_key_reverse]
                                
                                duration = (timestamp - req["timestamp"]) * 1000 if req["timestamp"] else None
                                
                                session = HTTPSession(
                                    session_id=req["session_id"],
                                    method=req["method"],
                                    url=req["url"],
                                    host=req["host"],
                                    path=req["path"],
                                    request_headers=req["headers"],
                                    request_body=req["body"],
                                    response_status=status_code,
                                    response_headers=headers,
                                    response_body=body[:5000] if body else None,
                                    response_size=len(body) if body else 0,
                                    source_ip=req["src_ip"],
                                    dest_ip=req["dst_ip"],
                                    request_time=req["timestamp"],
                                    response_time=timestamp,
                                    duration_ms=duration,
                                    request_packet=req["packet"],
                                    response_packet=i,
                                )
                                result.http_sessions.append(session)
                                
                                # Try to extract file
                                if body_bytes and len(body_bytes) > 100:
                                    extracted = _extract_file_from_http(headers, body_bytes, req["url"])
                                    if extracted:
                                        extracted.source_ip = req["src_ip"]
                                        extracted.dest_ip = req["dst_ip"]
                                        extracted.packet_number = i
                                        result.extracted_files.append(extracted)
                                        
                                        result.timeline_events.append(TimelineEvent(
                                            timestamp=timestamp,
                                            event_type="file_transfer",
                                            description=f"File downloaded: {extracted.filename} ({extracted.size} bytes)",
                                            source_ip=src_ip,
                                            dest_ip=dst_ip,
                                            protocol="HTTP",
                                            severity="medium" if extracted.is_executable else "info",
                                            details={"filename": extracted.filename, "mime_type": extracted.mime_type},
                                            packet_number=i,
                                        ))
                                
                                del http_requests[http_key_reverse]
                            
                            # Timeline event for response
                            if status_code >= 400:
                                result.timeline_events.append(TimelineEvent(
                                    timestamp=timestamp,
                                    event_type="http_error",
                                    description=f"HTTP {status_code} response",
                                    source_ip=src_ip,
                                    dest_ip=dst_ip,
                                    protocol="HTTP",
                                    severity="medium" if status_code >= 500 else "low",
                                    details={"status_code": status_code},
                                    packet_number=i,
                                ))
                        
                        except Exception as e:
                            logger.debug(f"HTTP response parsing error: {e}")
                    
                    # MQTT (TCP port 1883)
                    if dst_port == 1883 or src_port == 1883:
                        mqtt_msg = _parse_mqtt_packet(payload)
                        if mqtt_msg:
                            mqtt_msg.source_ip = src_ip
                            mqtt_msg.dest_ip = dst_ip
                            mqtt_msg.packet_number = i
                            result.mqtt_messages.append(mqtt_msg)
                            
                            if mqtt_msg.topic and mqtt_msg.topic not in seen_mqtt_topics:
                                seen_mqtt_topics.add(mqtt_msg.topic)
                                result.mqtt_topics.append(mqtt_msg.topic)
                            if mqtt_msg.client_id and mqtt_msg.client_id not in seen_mqtt_clients:
                                seen_mqtt_clients.add(mqtt_msg.client_id)
                                result.mqtt_clients.append(mqtt_msg.client_id)
                            
                            # Critical: credentials in MQTT CONNECT
                            if mqtt_msg.message_type == "CONNECT" and mqtt_msg.username:
                                result.timeline_events.append(TimelineEvent(
                                    timestamp=timestamp,
                                    event_type="credential",
                                    description=f"MQTT authentication: user={mqtt_msg.username}",
                                    source_ip=src_ip,
                                    dest_ip=dst_ip,
                                    protocol="MQTT",
                                    severity="high",
                                    packet_number=i,
                                ))
                    
                    # MySQL (port 3306)
                    if dst_port == 3306 or src_port == 3306:
                        direction = "client" if dst_port == 3306 else "server"
                        mysql_query = _parse_mysql_packet(payload, direction)
                        if mysql_query:
                            mysql_query.source_ip = src_ip
                            mysql_query.dest_ip = dst_ip
                            mysql_query.packet_number = i
                            result.database_queries.append(mysql_query)
                            
                            if mysql_query.database and mysql_query.database not in seen_databases:
                                seen_databases.add(f"MySQL:{mysql_query.database}")
                                result.databases_accessed.append(f"MySQL:{mysql_query.database}")
                    
                    # PostgreSQL (port 5432)
                    if dst_port == 5432 or src_port == 5432:
                        direction = "client" if dst_port == 5432 else "server"
                        pg_query = _parse_postgresql_packet(payload, direction)
                        if pg_query:
                            pg_query.source_ip = src_ip
                            pg_query.dest_ip = dst_ip
                            pg_query.packet_number = i
                            result.database_queries.append(pg_query)
                            
                            if pg_query.database and f"PostgreSQL:{pg_query.database}" not in seen_databases:
                                seen_databases.add(f"PostgreSQL:{pg_query.database}")
                                result.databases_accessed.append(f"PostgreSQL:{pg_query.database}")
                            
                            if pg_query.query_type == "CONNECT":
                                result.timeline_events.append(TimelineEvent(
                                    timestamp=timestamp,
                                    event_type="database",
                                    description=f"PostgreSQL connection: {pg_query.query}",
                                    source_ip=src_ip,
                                    dest_ip=dst_ip,
                                    protocol="PostgreSQL",
                                    severity="info",
                                    packet_number=i,
                                ))
                    
                    # Redis (port 6379)
                    if dst_port == 6379 or src_port == 6379:
                        redis_cmd = _parse_redis_command(payload)
                        if redis_cmd:
                            redis_cmd.source_ip = src_ip
                            redis_cmd.dest_ip = dst_ip
                            redis_cmd.packet_number = i
                            result.database_queries.append(redis_cmd)
                            
                            if "Redis" not in seen_databases:
                                seen_databases.add("Redis")
                                result.databases_accessed.append("Redis")
                    
                    # HTTP/2 detection
                    if _detect_http2_preface(payload):
                        result.http2_streams.append({
                            "source_ip": src_ip,
                            "dest_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "packet_number": i,
                            "preface_detected": True,
                        })
                        
                        result.timeline_events.append(TimelineEvent(
                            timestamp=timestamp,
                            event_type="protocol",
                            description="HTTP/2 connection initiated",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            protocol="HTTP/2",
                            severity="info",
                            packet_number=i,
                        ))
        
        except Exception as e:
            logger.debug(f"Packet {i} enhanced analysis error: {e}")
    
    # Finalize WebSocket sessions
    for ws_key, session in ws_sessions.items():
        if session.upgrade_response:  # Only include completed handshakes
            result.websocket_sessions.append(session)
            result.websocket_message_count += session.message_count
    
    # Finalize TCP streams (only include meaningful ones)
    for stream_key, stream in tcp_streams.items():
        if stream.packets_count > 5 and (len(stream.client_data) > 100 or len(stream.server_data) > 100):
            # Determine protocol from port
            if stream.server_port == 80:
                stream.protocol = "HTTP"
            elif stream.server_port == 443:
                stream.protocol = "HTTPS"
            elif stream.server_port == 3306:
                stream.protocol = "MySQL"
            elif stream.server_port == 5432:
                stream.protocol = "PostgreSQL"
            elif stream.server_port == 6379:
                stream.protocol = "Redis"
            elif stream.server_port == 1883:
                stream.protocol = "MQTT"
            
            result.tcp_streams.append(stream)
    
    # Sort timeline by timestamp
    result.timeline_events.sort(key=lambda e: e.timestamp)
    
    logger.info(f"Enhanced protocol analysis: {len(result.websocket_sessions)} WS sessions, "
                f"{len(result.grpc_calls)} gRPC calls, {len(result.mqtt_messages)} MQTT messages, "
                f"{len(result.database_queries)} DB queries, {len(result.http_sessions)} HTTP sessions, "
                f"{len(result.extracted_files)} files extracted, {len(result.timeline_events)} timeline events")
    
    return result


def is_tshark_installed() -> bool:
    """Check if tshark is installed and available."""
    return shutil.which("tshark") is not None


def get_capture_profiles() -> List[Dict[str, Any]]:
    """Get list of available capture profiles."""
    return [
        {
            "id": profile_id,
            "name": profile["name"],
            "description": profile["description"],
            "default_filter": profile["filter"],
            "timeout": profile["timeout"],
            "estimated_time": profile["estimated_time"],
            "intensity": profile["intensity"],
        }
        for profile_id, profile in CAPTURE_PROFILES.items()
    ]


def get_network_interfaces() -> List[Dict[str, str]]:
    """Get list of available network interfaces for capture."""
    if not is_tshark_installed():
        return []
    
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        interfaces = []
        for line in result.stdout.strip().split("\n"):
            if line:
                # Parse format: "1. eth0" or "1. eth0 (Description)"
                parts = line.split(".", 1)
                if len(parts) == 2:
                    iface_info = parts[1].strip()
                    # Extract interface name
                    if " (" in iface_info:
                        name = iface_info.split(" (")[0].strip()
                        desc = iface_info.split(" (")[1].rstrip(")")
                    else:
                        name = iface_info
                        desc = iface_info
                    interfaces.append({"name": name, "description": desc})
        
        return interfaces
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        return []


def validate_capture_filter(filter_expr: str) -> Tuple[bool, str]:
    """
    Validate a BPF capture filter expression.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not filter_expr:
        return True, ""
    
    if not is_tshark_installed():
        return False, "tshark is not installed"
    
    try:
        # Use tshark to validate the filter
        result = subprocess.run(
            ["tshark", "-f", filter_expr, "-c", "0", "-a", "duration:0"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        # Check for filter syntax errors
        if "Invalid capture filter" in result.stderr or "syntax error" in result.stderr.lower():
            return False, f"Invalid capture filter: {result.stderr.strip()}"
        
        return True, ""
    except subprocess.TimeoutExpired:
        return True, ""  # Timeout is OK, filter was likely valid
    except Exception as e:
        return False, str(e)


def run_packet_capture(
    interface: str = "any",
    duration: int = 30,
    packet_count: Optional[int] = None,
    capture_filter: Optional[str] = None,
    profile: str = "all",
) -> Tuple[Optional[Path], Optional[str], Optional[str]]:
    """
    Run a live packet capture using tshark.
    
    Args:
        interface: Network interface to capture on (default: "any")
        duration: Capture duration in seconds (default: 30)
        packet_count: Maximum packets to capture (optional)
        capture_filter: BPF filter expression (optional)
        profile: Capture profile ID (default: "all")
        
    Returns:
        Tuple of (output_pcap_path, command_used, error_message)
    """
    if not is_tshark_installed():
        return None, None, "tshark is not installed on the server"
    
    # Get profile settings
    profile_config = CAPTURE_PROFILES.get(profile, CAPTURE_PROFILES["all"])
    
    # Use profile filter if no custom filter provided
    if capture_filter is None:
        capture_filter = profile_config["filter"]
    
    # Validate filter
    if capture_filter:
        is_valid, error = validate_capture_filter(capture_filter)
        if not is_valid:
            return None, None, error
    
    # Limit duration for safety
    max_duration = 300  # 5 minutes max
    if duration > max_duration:
        duration = max_duration
    
    # Limit packet count
    max_packets = 100000
    if packet_count and packet_count > max_packets:
        packet_count = max_packets
    
    # Create output file
    output_dir = Path(tempfile.mkdtemp(prefix="tshark_capture_"))
    output_file = output_dir / "capture.pcap"
    
    # Build command
    cmd = ["tshark", "-i", interface, "-w", str(output_file)]
    
    # Add duration limit
    cmd.extend(["-a", f"duration:{duration}"])
    
    # Add packet count limit if specified
    if packet_count:
        cmd.extend(["-c", str(packet_count)])
    
    # Add capture filter
    if capture_filter:
        cmd.extend(["-f", capture_filter])
    
    command_str = " ".join(cmd)
    logger.info(f"Starting packet capture: {command_str}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 30,  # Add buffer for startup/shutdown
        )
        
        # Log output
        if result.stdout:
            logger.debug(f"tshark stdout: {result.stdout[:500]}")
        if result.stderr:
            # tshark outputs stats to stderr, not necessarily errors
            logger.debug(f"tshark stderr: {result.stderr[:500]}")
        
        # Check for permission errors
        if "permission" in (result.stderr or "").lower():
            return None, command_str, "Permission denied. The server needs root privileges for packet capture."
        
        # Check if file exists and has content
        if not output_file.exists():
            error_msg = result.stderr or result.stdout or "tshark did not produce output"
            return None, command_str, f"Capture failed: {error_msg}"
        
        if output_file.stat().st_size == 0:
            return None, command_str, "No packets captured. Check interface and filter settings."
        
        logger.info(f"Capture completed successfully: {output_file} ({output_file.stat().st_size} bytes)")
        return output_file, command_str, None
        
    except subprocess.TimeoutExpired:
        # This shouldn't happen since tshark has its own duration limit
        if output_file.exists() and output_file.stat().st_size > 0:
            return output_file, command_str, None
        return None, command_str, f"Capture timed out after {duration + 30} seconds"
    except PermissionError:
        return None, command_str, "Permission denied. The server needs root privileges for packet capture."
    except Exception as e:
        logger.error(f"Capture failed: {e}")
        return None, command_str, f"Capture failed: {str(e)}"


def is_pcap_analysis_available() -> bool:
    """Check if PCAP analysis dependencies are available."""
    return SCAPY_AVAILABLE


def _lazy_load_pcap(
    file_path: Path,
    max_packets: int = 100000,
    sample_rate: float = 1.0,
    chunk_size: int = 10000,
    progress_callback: Optional[callable] = None,
) -> List:
    """
    Lazy load packets from large PCAP files using chunked reading and sampling.
    
    This function provides memory-efficient loading for large captures by:
    1. Reading packets in chunks to avoid loading entire file into memory
    2. Applying statistical sampling when file exceeds max_packets threshold
    3. Providing progress updates via callback
    
    Args:
        file_path: Path to PCAP file
        max_packets: Maximum packets to return (will sample if exceeded)
        sample_rate: Sampling rate (1.0 = all packets, 0.1 = 10% sample)
        chunk_size: Packets to read per chunk
        progress_callback: Optional callback(current, total, message)
        
    Returns:
        List of scapy packets
    """
    import random
    from scapy.all import PcapReader
    
    collected_packets = []
    packets_read = 0
    
    # First pass: count total packets for progress reporting
    logger.info("Counting packets for lazy loading...")
    if progress_callback:
        progress_callback(0, 100, "Counting packets...")
    
    try:
        total_count = 0
        with PcapReader(str(file_path)) as reader:
            for _ in reader:
                total_count += 1
                if total_count > max_packets * 10:  # Don't count beyond reasonable limit
                    break
        logger.info(f"Total packets in file: ~{total_count}")
    except Exception as e:
        logger.warning(f"Could not count packets: {e}, using estimate")
        total_count = max_packets
    
    # Determine effective sample rate
    effective_sample_rate = sample_rate
    if total_count > max_packets and sample_rate >= 1.0:
        # Auto-calculate sample rate to stay under max_packets
        effective_sample_rate = max_packets / total_count
        logger.info(f"Auto-adjusting sample rate to {effective_sample_rate:.2%} for large file")
    
    # Second pass: collect packets with sampling
    logger.info(f"Loading packets with {effective_sample_rate:.2%} sampling rate...")
    
    try:
        with PcapReader(str(file_path)) as reader:
            for pkt in reader:
                packets_read += 1
                
                # Apply sampling
                if effective_sample_rate < 1.0:
                    if random.random() > effective_sample_rate:
                        continue
                
                collected_packets.append(pkt)
                
                # Progress callback
                if progress_callback and packets_read % chunk_size == 0:
                    pct = min(100, int(packets_read / total_count * 100))
                    progress_callback(pct, 100, f"Loaded {len(collected_packets):,} packets ({packets_read:,} read)")
                
                # Stop if we've collected enough
                if len(collected_packets) >= max_packets:
                    logger.info(f"Reached max_packets limit ({max_packets}), stopping")
                    break
                    
    except Exception as e:
        logger.error(f"Error during lazy loading: {e}")
        # Fall back to standard loading
        logger.info("Falling back to standard loading...")
        return rdpcap(str(file_path), count=max_packets)
    
    if progress_callback:
        progress_callback(100, 100, f"Loaded {len(collected_packets):,} packets")
    
    logger.info(f"Lazy loading complete: {len(collected_packets):,} packets from {packets_read:,} total")
    return collected_packets


def analyze_pcap(
    file_path: Path, 
    max_packets: int = 100000,
    lazy_loading: bool = True,
    sample_rate: float = 1.0,
    chunk_size: int = 10000,
    progress_callback: Optional[callable] = None,
) -> PcapAnalysisResult:
    """
    Analyze a single PCAP file for security issues with lazy loading support.
    
    Args:
        file_path: Path to .pcap or .pcapng file
        max_packets: Maximum packets to analyze (for large files)
        lazy_loading: If True, uses chunked reading for large files to conserve memory
        sample_rate: Sample rate for large files (0.1 = analyze 10% of packets). 
                    Only applies when total packets exceed max_packets threshold.
        chunk_size: Number of packets to process per chunk in lazy loading mode
        progress_callback: Optional callback(current, total, message) for progress updates
        
    Returns:
        PcapAnalysisResult with findings and statistics
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not installed. Run: pip install scapy")
    
    logger.info(f"Loading PCAP file: {file_path}")
    
    # Get file size for smart loading decisions
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    
    # Determine loading strategy based on file size
    if lazy_loading and file_size_mb > 50:  # Files > 50MB use chunked loading
        logger.info(f"Large file detected ({file_size_mb:.1f}MB), using lazy loading with sampling")
        packets = _lazy_load_pcap(
            file_path, 
            max_packets=max_packets, 
            sample_rate=sample_rate,
            chunk_size=chunk_size,
            progress_callback=progress_callback
        )
    else:
        # Standard loading for smaller files
        if progress_callback:
            progress_callback(0, 100, "Loading PCAP file...")
        packets = rdpcap(str(file_path), count=max_packets)
        if progress_callback:
            progress_callback(100, 100, f"Loaded {len(packets)} packets")
    
    logger.info(f"Loaded {len(packets)} packets")
    
    findings: List[PcapFinding] = []
    protocols: Dict[str, int] = defaultdict(int)
    ip_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    dns_queries: List[str] = []
    http_hosts: List[str] = []
    
    # Track for pattern detection
    syn_packets: Dict[str, set] = defaultdict(set)  # src_ip -> set of dest ports
    
    for i, pkt in enumerate(packets):
        # Count protocols
        proto = _get_protocol(pkt)
        protocols[proto] += 1
        
        # Track IP statistics
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            pkt_len = len(pkt)
            ip_stats[src]["packets"] += 1
            ip_stats[src]["bytes"] += pkt_len
            ip_stats[dst]["packets"] += 1
            ip_stats[dst]["bytes"] += pkt_len
            
            # Track SYN packets for port scan detection
            if TCP in pkt and pkt[TCP].flags == 0x02:  # SYN only
                syn_packets[src].add(pkt[TCP].dport)
        
        # Check for security issues
        pkt_findings = _check_packet_security(pkt, i)
        findings.extend(pkt_findings)
        
        # Extract DNS queries
        if DNS in pkt:
            try:
                if pkt[DNS].qr == 0 and pkt[DNS].qd:  # Query
                    qname = pkt[DNS].qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('utf-8', errors='ignore')
                    qname = qname.rstrip('.')
                    if qname and qname not in dns_queries:
                        dns_queries.append(qname)
            except Exception:
                pass
        
        # Extract HTTP hosts
        if TCP in pkt and Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)
                if b"Host:" in payload or b"host:" in payload:
                    lines = payload.split(b"\r\n")
                    for line in lines:
                        if line.lower().startswith(b"host:"):
                            host = line.split(b":", 1)[1].strip().decode('utf-8', errors='ignore')
                            if host and host not in http_hosts:
                                http_hosts.append(host)
                            break
            except Exception:
                pass
    
    # Detect port scanning
    for src_ip, ports in syn_packets.items():
        if len(ports) > 20:  # More than 20 different ports = likely scan
            findings.append(PcapFinding(
                category="suspicious_traffic",
                severity="high",
                title="Potential Port Scan Detected",
                description=f"Host {src_ip} sent SYN packets to {len(ports)} different ports, indicating possible port scanning activity",
                source_ip=src_ip,
                protocol="TCP",
                evidence=f"Targeted ports include: {', '.join(str(p) for p in sorted(list(ports))[:20])}...",
            ))
    
    # Build top talkers list
    top_talkers = sorted(
        [{"ip": ip, "packets": stats["packets"], "bytes": stats["bytes"]} 
         for ip, stats in ip_stats.items()],
        key=lambda x: x["packets"],
        reverse=True
    )[:10]
    
    # Calculate duration
    duration = _get_capture_duration(packets)
    
    # Build network topology data for visualization
    topology_nodes, topology_links = _build_network_topology(packets, ip_stats, findings)
    
    # Build summary
    summary = PcapSummary(
        total_packets=len(packets),
        duration_seconds=round(duration, 2),
        protocols=dict(protocols),
        top_talkers=top_talkers,
        dns_queries=dns_queries[:100],  # Limit to 100
        http_hosts=http_hosts[:100],
        potential_issues=len(findings),
        topology_nodes=topology_nodes,
        topology_links=topology_links,
    )
    
    # Extract conversations
    conversations = _extract_conversations(packets)
    
    # Deduplicate findings by title + source_ip + dest_ip
    seen_findings: set = set()
    unique_findings: List[PcapFinding] = []
    for f in findings:
        key = (f.title, f.source_ip, f.dest_ip, f.port)
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)
    
    # Perform offensive attack surface analysis
    logger.info("Performing attack surface analysis...")
    attack_surface = analyze_attack_surface(packets)
    
    # Perform enhanced protocol analysis
    logger.info("Performing enhanced protocol analysis...")
    enhanced_protocols = analyze_enhanced_protocols(packets)
    
    logger.info(f"Analysis complete: {len(unique_findings)} findings, {len(conversations)} conversations, "
                f"{attack_surface.total_endpoints} endpoints discovered, "
                f"{len(enhanced_protocols.http_sessions)} HTTP sessions, "
                f"{len(enhanced_protocols.websocket_sessions)} WebSocket sessions")
    
    return PcapAnalysisResult(
        filename=file_path.name,
        summary=summary,
        findings=unique_findings,
        conversations=conversations,
        attack_surface=attack_surface,
        enhanced_protocols=enhanced_protocols,
    )


def _get_protocol(pkt) -> str:
    """Determine the highest-layer protocol."""
    if DNS in pkt:
        return "DNS"
    if TCP in pkt:
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        # Check common ports
        ports = {dport, sport}
        if 80 in ports:
            return "HTTP"
        if 443 in ports:
            return "HTTPS/TLS"
        if 8080 in ports or 8443 in ports:
            return "HTTP-Alt"
        if 21 in ports:
            return "FTP"
        if 22 in ports:
            return "SSH"
        if 23 in ports:
            return "Telnet"
        if 25 in ports:
            return "SMTP"
        if 110 in ports:
            return "POP3"
        if 143 in ports:
            return "IMAP"
        if 3389 in ports:
            return "RDP"
        if 3306 in ports:
            return "MySQL"
        if 5432 in ports:
            return "PostgreSQL"
        if 1433 in ports:
            return "MSSQL"
        if 6379 in ports:
            return "Redis"
        if 27017 in ports:
            return "MongoDB"
        if 1883 in ports:
            return "MQTT"
        if 8883 in ports:
            return "MQTT-TLS"
        if 5672 in ports:
            return "AMQP"
        if 9092 in ports:
            return "Kafka"
        if 50051 in ports:
            return "gRPC"
        return "TCP"
    if UDP in pkt:
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport
        ports = {dport, sport}
        if 53 in ports:
            return "DNS"
        if 67 in ports or 68 in ports:
            return "DHCP"
        if 123 in ports:
            return "NTP"
        if 161 in ports or 162 in ports:
            return "SNMP"
        if 500 in ports:
            return "IKE"
        if 1900 in ports:
            return "SSDP"
        if 5683 in ports:
            return "CoAP"
        if 443 in ports:
            return "QUIC"
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if ARP in pkt:
        return "ARP"
    if IP in pkt:
        return "IP"
    return "Other"


def _build_network_topology(
    packets: List, 
    ip_stats: Dict[str, Dict[str, int]], 
    findings: List[PcapFinding]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Build network topology data for visualization.
    Returns (nodes, links) suitable for D3.js force-directed graph.
    """
    from collections import defaultdict
    
    # Track connections between IPs
    connections: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "protocols": set(), "ports": set()}
    )
    
    # Track services/ports seen on each IP
    ip_ports: Dict[str, set] = defaultdict(set)
    ip_protocols: Dict[str, set] = defaultdict(set)
    
    # Find IPs with findings (for risk level)
    risky_ips: Dict[str, str] = {}  # ip -> highest severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for finding in findings:
        for ip in [finding.source_ip, finding.dest_ip]:
            if ip:
                current = risky_ips.get(ip, "none")
                current_rank = severity_order.get(current, -1)
                finding_rank = severity_order.get(finding.severity.lower(), 0)
                if finding_rank > current_rank:
                    risky_ips[ip] = finding.severity.lower()
    
    # Process packets to build connections
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Create ordered tuple for connection (smaller IP first for consistency)
            conn_key = (min(src, dst), max(src, dst))
            
            # Get packet size
            pkt_size = len(pkt)
            
            connections[conn_key]["packets"] += 1
            connections[conn_key]["bytes"] += pkt_size
            
            # Track protocol
            proto = _get_protocol(pkt)
            connections[conn_key]["protocols"].add(proto)
            ip_protocols[src].add(proto)
            ip_protocols[dst].add(proto)
            
            # Track ports
            if TCP in pkt:
                ip_ports[dst].add(pkt[TCP].dport)
                ip_ports[src].add(pkt[TCP].sport)
                connections[conn_key]["ports"].add(pkt[TCP].dport)
            elif UDP in pkt:
                ip_ports[dst].add(pkt[UDP].dport)
                ip_ports[src].add(pkt[UDP].sport)
                connections[conn_key]["ports"].add(pkt[UDP].dport)
    
    # Build nodes list
    nodes: List[Dict[str, Any]] = []
    for ip, stats in ip_stats.items():
        # Determine node type based on ports and behavior
        ports = ip_ports.get(ip, set())
        protocols = ip_protocols.get(ip, set())
        
        node_type = "host"  # default
        if any(p in ports for p in [80, 443, 8080, 8443]):
            node_type = "server"
        elif any(p in ports for p in [22, 3389]):
            if stats["packets"] > 100:  # receiving many connections
                node_type = "server"
        elif any(p in ports for p in [53, 67, 68]):
            node_type = "router"  # DNS/DHCP often on routers
        
        # Determine services from ports
        services = []
        port_to_service = {
            22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP", 23: "Telnet",
            25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 3389: "RDP",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 445: "SMB", 139: "NetBIOS"
        }
        for port in sorted(ports)[:10]:  # Limit to 10 services
            if port in port_to_service:
                services.append(port_to_service[port])
        
        nodes.append({
            "id": ip,
            "ip": ip,
            "type": node_type,
            "services": services,
            "ports": sorted(list(ports))[:20],  # Limit to 20 ports
            "packets": stats["packets"],
            "bytes": stats["bytes"],
            "riskLevel": risky_ips.get(ip, "none"),
        })
    
    # Build links list
    links: List[Dict[str, Any]] = []
    for (src, dst), data in connections.items():
        # Determine primary protocol
        proto = "TCP"  # default
        if "HTTP" in data["protocols"]:
            proto = "HTTP"
        elif "HTTPS/TLS" in data["protocols"]:
            proto = "HTTPS"
        elif "DNS" in data["protocols"]:
            proto = "DNS"
        elif "SSH" in data["protocols"]:
            proto = "SSH"
        elif data["protocols"]:
            proto = list(data["protocols"])[0]
        
        # Get primary port
        port = None
        if data["ports"]:
            common_ports = [80, 443, 22, 53, 21, 25, 3389, 3306, 5432]
            for cp in common_ports:
                if cp in data["ports"]:
                    port = cp
                    break
            if port is None:
                port = min(data["ports"])
        
        links.append({
            "source": src,
            "target": dst,
            "protocol": proto,
            "port": port,
            "packets": data["packets"],
            "bytes": data["bytes"],
            "bidirectional": True,  # We're aggregating both directions
        })
    
    # Limit to top connections by packet count (for performance)
    links = sorted(links, key=lambda x: x["packets"], reverse=True)[:100]
    
    # Only include nodes that are part of the top connections
    linked_ips = set()
    for link in links:
        linked_ips.add(link["source"])
        linked_ips.add(link["target"])
    nodes = [n for n in nodes if n["ip"] in linked_ips]
    
    logger.info(f"Built topology: {len(nodes)} nodes, {len(links)} links")
    return nodes, links


def _check_packet_security(pkt, packet_num: int) -> List[PcapFinding]:
    """Check a packet for security issues."""
    findings: List[PcapFinding] = []
    
    if IP not in pkt:
        return findings
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    # Check for cleartext credentials and sensitive data
    if Raw in pkt:
        try:
            payload = bytes(pkt[Raw].load)
            payload_lower = payload.lower()
            
            # HTTP Basic Auth
            if b"authorization: basic" in payload_lower:
                findings.append(PcapFinding(
                    category="credential_exposure",
                    severity="critical",
                    title="HTTP Basic Authentication in Cleartext",
                    description="Credentials transmitted via HTTP Basic Auth without TLS encryption. Base64-encoded credentials can be trivially decoded.",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=pkt[TCP].dport if TCP in pkt else None,
                    protocol="HTTP",
                    packet_number=packet_num,
                ))
            
            # HTTP form data with password
            if b"password=" in payload_lower or b"passwd=" in payload_lower or b"pwd=" in payload_lower:
                if TCP in pkt and pkt[TCP].dport == 80:
                    findings.append(PcapFinding(
                        category="credential_exposure",
                        severity="critical",
                        title="Password Submitted Over HTTP",
                        description="Password field detected in HTTP POST data. Credentials transmitted in cleartext.",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=80,
                        protocol="HTTP",
                        packet_number=packet_num,
                    ))
            
            # FTP credentials
            if TCP in pkt:
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport == 21 or sport == 21:
                    if payload_lower.startswith(b"user ") or payload_lower.startswith(b"pass "):
                        findings.append(PcapFinding(
                            category="credential_exposure",
                            severity="critical",
                            title="FTP Credentials in Cleartext",
                            description="FTP username or password transmitted without encryption. FTP is inherently insecure.",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            port=21,
                            protocol="FTP",
                            packet_number=packet_num,
                        ))
            
            # SMTP Auth
            if b"auth login" in payload_lower or b"auth plain" in payload_lower:
                if TCP in pkt and pkt[TCP].dport == 25:
                    findings.append(PcapFinding(
                        category="credential_exposure",
                        severity="critical",
                        title="SMTP Authentication in Cleartext",
                        description="Email credentials transmitted via unencrypted SMTP.",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=25,
                        protocol="SMTP",
                        packet_number=packet_num,
                    ))
            
            # Database connection strings
            db_patterns = [
                (b"mysql://", "MySQL"),
                (b"postgres://", "PostgreSQL"),
                (b"mongodb://", "MongoDB"),
                (b"redis://", "Redis"),
            ]
            for pattern, db_name in db_patterns:
                if pattern in payload_lower:
                    findings.append(PcapFinding(
                        category="credential_exposure",
                        severity="critical",
                        title=f"{db_name} Connection String Exposed",
                        description=f"{db_name} connection string (potentially containing credentials) transmitted in cleartext.",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=pkt[TCP].dport if TCP in pkt else None,
                        protocol="TCP",
                        packet_number=packet_num,
                    ))
            
            # API keys and tokens
            token_patterns = [
                (b"api_key=", "API Key"),
                (b"apikey=", "API Key"),
                (b"api-key:", "API Key"),
                (b"x-api-key:", "API Key"),
                (b"authorization: bearer", "Bearer Token"),
                (b"access_token=", "Access Token"),
                (b"secret_key=", "Secret Key"),
            ]
            for pattern, token_type in token_patterns:
                if pattern in payload_lower:
                    if TCP in pkt and pkt[TCP].dport == 80:  # Only flag if HTTP (not HTTPS)
                        findings.append(PcapFinding(
                            category="credential_exposure",
                            severity="high",
                            title=f"{token_type} Transmitted Over HTTP",
                            description=f"{token_type} detected in unencrypted HTTP traffic.",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            port=80,
                            protocol="HTTP",
                            packet_number=packet_num,
                        ))
                    break
            
            # Credit card patterns (basic check - 16 digits)
            if _contains_credit_card_pattern(payload):
                findings.append(PcapFinding(
                    category="sensitive_data",
                    severity="critical",
                    title="Potential Credit Card Number Detected",
                    description="Data resembling a credit card number was transmitted in cleartext.",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=pkt[TCP].dport if TCP in pkt else None,
                    protocol=_get_protocol(pkt),
                    packet_number=packet_num,
                ))
            
        except Exception as e:
            logger.debug(f"Error checking packet payload: {e}")
    
    # Check for insecure protocols
    if TCP in pkt:
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        
        # Telnet
        if dport == 23 or sport == 23:
            findings.append(PcapFinding(
                category="cleartext_protocol",
                severity="high",
                title="Telnet Session Detected",
                description="Telnet transmits all data (including credentials) in cleartext. Use SSH instead.",
                source_ip=src_ip,
                dest_ip=dst_ip,
                port=23,
                protocol="Telnet",
                packet_number=packet_num,
            ))
        
        # Unencrypted database connections
        insecure_db_ports = {
            3306: ("MySQL", "MySQL connection without TLS. Database traffic may contain sensitive queries and data."),
            5432: ("PostgreSQL", "PostgreSQL connection without SSL. Consider enabling SSL mode."),
            1433: ("MSSQL", "Microsoft SQL Server connection detected. Ensure encryption is enabled."),
            6379: ("Redis", "Redis connection detected. Redis traffic is unencrypted by default."),
            27017: ("MongoDB", "MongoDB connection detected. Ensure TLS is configured."),
        }
        
        for port, (db_name, desc) in insecure_db_ports.items():
            if dport == port or sport == port:
                findings.append(PcapFinding(
                    category="cleartext_protocol",
                    severity="medium",
                    title=f"Unencrypted {db_name} Connection",
                    description=desc,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=port,
                    protocol=db_name,
                    packet_number=packet_num,
                ))
    
    return findings


def _contains_credit_card_pattern(data: bytes) -> bool:
    """Check if data contains a potential credit card number."""
    import re
    try:
        text = data.decode('utf-8', errors='ignore')
        # Look for 16 consecutive digits or groups of 4 digits separated by spaces/dashes
        patterns = [
            r'\b\d{16}\b',
            r'\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b',
        ]
        for pattern in patterns:
            if re.search(pattern, text):
                return True
    except Exception:
        pass
    return False


def _get_capture_duration(packets) -> float:
    """Calculate capture duration in seconds."""
    if len(packets) < 2:
        return 0.0
    try:
        return float(packets[-1].time - packets[0].time)
    except Exception:
        return 0.0


def _extract_conversations(packets, max_convos: int = 50) -> List[Dict[str, Any]]:
    """Extract top TCP/UDP conversations."""
    convos: Dict[tuple, Dict[str, Any]] = {}
    
    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                proto = "TCP"
            else:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                proto = "UDP"
            
            # Normalize conversation key (sort to make bidirectional)
            endpoints = tuple(sorted([(src, sport), (dst, dport)]))
            key = (endpoints, proto)
            
            if key not in convos:
                convos[key] = {
                    "src": endpoints[0][0],
                    "sport": endpoints[0][1],
                    "dst": endpoints[1][0],
                    "dport": endpoints[1][1],
                    "protocol": proto,
                    "service": _guess_service(endpoints[0][1], endpoints[1][1]),
                    "packets": 0,
                    "bytes": 0,
                }
            convos[key]["packets"] += 1
            convos[key]["bytes"] += len(pkt)
    
    # Sort by packets and return top N
    sorted_convos = sorted(convos.values(), key=lambda x: x["packets"], reverse=True)
    return sorted_convos[:max_convos]


def _guess_service(port1: int, port2: int) -> str:
    """Guess the service based on port numbers."""
    services = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
        123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    for port in (port1, port2):
        if port in services:
            return services[port]
    # Assume lower port is the service
    min_port = min(port1, port2)
    if min_port < 1024:
        return f"Port-{min_port}"
    return "Unknown"


@dataclass
class AISecurityReport:
    """Structured AI security assessment report."""
    risk_level: str  # Critical, High, Medium, Low
    risk_score: int  # 0-100
    executive_summary: str
    key_findings: List[Dict[str, str]]  # List of {title, severity, description, recommendation}
    traffic_analysis: Dict[str, Any]  # {patterns, anomalies, protocols_of_concern}
    dns_analysis: Dict[str, Any]  # {suspicious_domains, potential_dga, tunneling_indicators}
    credential_exposure: Dict[str, Any]  # {exposed_credentials, affected_services, risk}
    indicators_of_compromise: List[Dict[str, str]]  # List of {type, value, context, threat_level}
    attack_indicators: Dict[str, Any]  # {reconnaissance, lateral_movement, exfiltration, c2}
    recommendations: List[Dict[str, str]]  # List of {priority, action, rationale}
    timeline_analysis: str  # Temporal patterns
    affected_assets: List[Dict[str, str]]  # List of {ip, role, risk, services}
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


async def analyze_pcap_with_ai(
    analysis_result: PcapAnalysisResult,
    additional_context: str = "",
) -> Dict[str, Any]:
    """
    Use Gemini to provide AI-powered analysis of PCAP findings.
    
    Analyzes traffic from a sandbox environment to understand app behavior
    and identify security-relevant findings.
    
    Args:
        analysis_result: The parsed PCAP analysis
        additional_context: Optional additional context (e.g., document analysis, notes)
        
    Returns:
        Structured analysis report as dictionary
    """
    if not settings.gemini_api_key:
        return {"error": "AI analysis unavailable: GEMINI_API_KEY not configured"}
    
    try:
        from google import genai
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build findings text
        findings_text = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description} (src: {f.source_ip}, dst: {f.dest_ip}, port: {f.port})"
            for f in analysis_result.findings[:50]
        )
        
        dns_sample = analysis_result.summary.dns_queries[:150]
        http_sample = analysis_result.summary.http_hosts[:100]
        
        # Build attack surface data for AI - only include what was actually found
        attack_surface_data = ""
        if analysis_result.attack_surface:
            atk = analysis_result.attack_surface
            
            # Only include sections that have data
            sections = []
            
            if atk.endpoints:
                endpoints_list = []
                for ep in atk.endpoints[:50]:
                    ep_info = f"    {ep.method} {ep.url}"
                    if ep.query_params:
                        ep_info += f"\n      Query: {json.dumps(ep.query_params)}"
                    if ep.body_params:
                        ep_info += f"\n      Body: {json.dumps(ep.body_params, default=str)[:300]}"
                    if ep.auth_type:
                        ep_info += f"\n      Auth: {ep.auth_type}"
                    if ep.headers:
                        ep_info += f"\n      Headers: {json.dumps(ep.headers)}"
                    endpoints_list.append(ep_info)
                sections.append(f"### API Endpoints Found ({atk.total_endpoints} total)\nHosts: {', '.join(atk.unique_hosts)}\n\n" + "\n\n".join(endpoints_list))
            
            if atk.auth_tokens:
                tokens_list = []
                for token in atk.auth_tokens[:15]:
                    token_info = f"    Type: {token.token_type}\n    Value: {token.token_value[:80]}{'...' if len(token.token_value) > 80 else ''}\n    Used at: {token.dest_host}{token.endpoint}"
                    if token.jwt_claims:
                        token_info += f"\n    JWT Claims: {json.dumps(token.jwt_claims, default=str)[:300]}"
                    if token.jwt_weaknesses:
                        token_info += f"\n    Issues: {'; '.join(token.jwt_weaknesses)}"
                    tokens_list.append(token_info)
                sections.append(f"### Authentication Tokens Extracted ({len(atk.auth_tokens)} found)\n\n" + "\n\n".join(tokens_list))
            
            if atk.sensitive_data_leaks:
                leaks_list = [f"    [{l.severity}] {l.data_type}: {l.data_value} in {l.context} @ {l.endpoint}\n      Evidence: {l.evidence[:150]}" for l in atk.sensitive_data_leaks[:30]]
                sections.append(f"### Sensitive Data Found ({len(atk.sensitive_data_leaks)} items)\n\n" + "\n\n".join(leaks_list))
            
            if atk.protocol_weaknesses:
                pw_list = [f"    [{p.severity}] {p.weakness_type} on port {p.port}: {p.description}" for p in atk.protocol_weaknesses[:15]]
                sections.append(f"### Protocol Issues ({len(atk.protocol_weaknesses)} found)\n\n" + "\n".join(pw_list))
            
            if atk.high_value_endpoints:
                hv_list = []
                for hv in atk.high_value_endpoints[:15]:
                    ep = hv["endpoint"]
                    cls = hv["classification"]
                    hv_list.append(f"    {ep['method']} {ep['path']} - Categories: {', '.join(cls['categories'])}")
                sections.append(f"### Notable Endpoints ({len(atk.high_value_endpoints)} identified)\n\n" + "\n".join(hv_list))
            
            if sections:
                attack_surface_data = "\n\n## EXTRACTED DATA\n\n" + "\n\n".join(sections)

        # Build enhanced protocol analysis data for AI
        enhanced_protocol_data = ""
        if analysis_result.enhanced_protocols:
            epa = analysis_result.enhanced_protocols
            epa_sections = []
            
            # HTTP Sessions - valuable for understanding app behavior
            if epa.http_sessions:
                http_sessions_list = []
                for session in epa.http_sessions[:30]:
                    session_info = f"    {session.method} {session.host}{session.path}"
                    if session.response_status:
                        session_info += f" -> {session.response_status}"
                    if session.duration_ms:
                        session_info += f" ({session.duration_ms:.1f}ms)"
                    if session.request_body:
                        session_info += f"\n      Request Body: {session.request_body[:200]}{'...' if len(session.request_body) > 200 else ''}"
                    if session.response_body:
                        session_info += f"\n      Response Body: {session.response_body[:200]}{'...' if len(session.response_body) > 200 else ''}"
                    http_sessions_list.append(session_info)
                epa_sections.append(f"### HTTP Sessions Reconstructed ({len(epa.http_sessions)} total)\n\n" + "\n\n".join(http_sessions_list))
            
            # WebSocket Sessions - real-time communication analysis
            if epa.websocket_sessions:
                ws_list = []
                for ws in epa.websocket_sessions[:10]:
                    ws_info = f"    Session: {ws.client_ip}:{ws.client_port} <-> {ws.server_ip}:{ws.server_port}"
                    ws_info += f"\n      Messages: {ws.message_count} ({ws.text_messages} text, {ws.binary_messages} binary)"
                    if ws.is_secure:
                        ws_info += " [SECURE]"
                    if ws.messages:
                        ws_info += "\n      Sample messages:"
                        for msg in ws.messages[:5]:
                            if msg.payload_preview:
                                ws_info += f"\n        - {msg.direction}: {msg.payload_preview[:100]}"
                    ws_list.append(ws_info)
                epa_sections.append(f"### WebSocket Real-Time Communication ({len(epa.websocket_sessions)} sessions, {epa.websocket_message_count} messages)\n\n" + "\n\n".join(ws_list))
            
            # gRPC Calls - microservice communication
            if epa.grpc_calls:
                grpc_list = []
                for call in epa.grpc_calls[:15]:
                    grpc_info = f"    {call.service}/{call.method}"
                    if call.status:
                        grpc_info += f" -> {call.status}"
                    if call.request_size or call.response_size:
                        grpc_info += f" (req: {call.request_size or 0}B, resp: {call.response_size or 0}B)"
                    grpc_list.append(grpc_info)
                epa_sections.append(f"### gRPC Service Calls ({len(epa.grpc_calls)} calls)\nServices: {', '.join(epa.grpc_services[:10])}\n\n" + "\n".join(grpc_list))
            
            # Database Queries - CRITICAL for security analysis
            if epa.database_queries:
                db_list = []
                for query in epa.database_queries[:20]:
                    db_info = f"    [{query.protocol}] {query.query_type}: {query.query[:200]}"
                    if query.database:
                        db_info += f" (DB: {query.database})"
                    if query.username:
                        db_info += f" (User: {query.username})"
                    db_list.append(db_info)
                epa_sections.append(f"### Database Traffic ({len(epa.database_queries)} queries)\nDatabases Accessed: {', '.join(epa.databases_accessed)}\n\n" + "\n\n".join(db_list))
            
            # MQTT Messages - IoT analysis
            if epa.mqtt_messages:
                mqtt_list = []
                for msg in epa.mqtt_messages[:15]:
                    mqtt_info = f"    {msg.message_type} topic: {msg.topic}"
                    if msg.payload:
                        mqtt_info += f"\n      Payload: {msg.payload[:150]}"
                    mqtt_list.append(mqtt_info)
                epa_sections.append(f"### MQTT IoT Messages ({len(epa.mqtt_messages)} messages)\nTopics: {', '.join(epa.mqtt_topics[:20])}\nClients: {', '.join(epa.mqtt_clients[:10])}\n\n" + "\n\n".join(mqtt_list))
            
            # CoAP Messages - IoT constrained devices
            if epa.coap_messages:
                coap_list = [f"    {msg.method} {msg.uri} from {msg.source_ip}" for msg in epa.coap_messages[:10]]
                epa_sections.append(f"### CoAP IoT Protocol ({len(epa.coap_messages)} messages)\n\n" + "\n".join(coap_list))
            
            # Extracted Files - malware analysis relevance
            if epa.extracted_files:
                files_list = []
                for f in epa.extracted_files[:15]:
                    file_info = f"    {f.filename} ({f.mime_type}, {f.size} bytes)"
                    file_info += f"\n      MD5: {f.md5_hash}"
                    file_info += f"\n      SHA256: {f.sha256_hash}"
                    if f.is_executable:
                        file_info += " [EXECUTABLE - HIGH RISK]"
                    if f.source_url:
                        file_info += f"\n      Source: {f.source_url}"
                    files_list.append(file_info)
                epa_sections.append(f"### Extracted Files ({len(epa.extracted_files)} files)\n\n" + "\n\n".join(files_list))
            
            # Timeline Events - attack sequence understanding
            if epa.timeline_events:
                # Group by severity for AI
                critical_events = [e for e in epa.timeline_events if e.severity in ('critical', 'high')]
                timeline_list = []
                for event in (critical_events[:20] if critical_events else epa.timeline_events[:30]):
                    event_info = f"    [{event.severity.upper()}] {event.event_type}: {event.description}"
                    if event.source_ip and event.dest_ip:
                        event_info += f" ({event.source_ip} -> {event.dest_ip})"
                    timeline_list.append(event_info)
                epa_sections.append(f"### Security Timeline ({len(epa.timeline_events)} events, {len(critical_events)} high-severity)\n\n" + "\n".join(timeline_list))
            
            # QUIC Connections - modern encrypted traffic
            if epa.quic_connections:
                quic_list = [f"    {conn.get('client_ip', 'unknown')} -> {conn.get('server_ip', 'unknown')}:{conn.get('server_port', 443)}" for conn in epa.quic_connections[:10]]
                epa_sections.append(f"### QUIC/HTTP3 Connections ({len(epa.quic_connections)} detected)\n\n" + "\n".join(quic_list))
            
            # TCP Streams - reconstructed conversations
            if epa.tcp_streams:
                stream_list = []
                for stream in epa.tcp_streams[:10]:
                    stream_info = f"    {stream.client_ip}:{stream.client_port} <-> {stream.server_ip}:{stream.server_port} ({stream.protocol})"
                    stream_info += f"\n      Client sent: {len(stream.client_data)} bytes, Server sent: {len(stream.server_data)} bytes"
                    stream_list.append(stream_info)
                epa_sections.append(f"### TCP Streams Reconstructed ({len(epa.tcp_streams)} streams)\n\n" + "\n\n".join(stream_list))
            
            if epa_sections:
                enhanced_protocol_data = "\n\n## ENHANCED PROTOCOL ANALYSIS\n\n" + "\n\n".join(epa_sections)

        # Build additional context section if provided
        additional_context_section = ""
        if additional_context and additional_context.strip():
            additional_context_section = f"""
{additional_context}

**Important**: Consider the document analysis and user notes above when analyzing this traffic capture. 
Look for correlations between the documented application behavior/requirements and what is observed in the traffic.
"""

        prompt = f"""Analyze this network traffic capture and provide a comprehensive security assessment. Report ONLY what you can actually see in the data.

## CAPTURE SUMMARY

File: {analysis_result.filename}
Total Packets: {analysis_result.summary.total_packets:,}
Duration: {analysis_result.summary.duration_seconds:.1f} seconds

## PROTOCOLS OBSERVED
{json.dumps(analysis_result.summary.protocols, indent=2)}

## HOSTS BY TRAFFIC VOLUME
{json.dumps(analysis_result.summary.top_talkers[:20], indent=2)}

## DNS QUERIES ({len(analysis_result.summary.dns_queries)} unique domains)
{json.dumps(dns_sample, indent=2)}

## HTTP HOSTS CONTACTED ({len(analysis_result.summary.http_hosts)} unique)
{json.dumps(http_sample, indent=2)}

## AUTOMATED SCANNER FINDINGS
{findings_text if findings_text else "None detected."}

## CONVERSATIONS
{json.dumps(analysis_result.conversations[:25], indent=2)}
{attack_surface_data}
{enhanced_protocol_data}
{additional_context_section}
---

Provide your analysis as JSON matching this EXACT structure:

{{
  "risk_level": "<Critical|High|Medium|Low based on actual findings>",
  "risk_score": <0-100 number based on severity of findings>,
  "executive_summary": "<2-3 paragraph comprehensive summary of what this capture shows, key security observations, and overall risk assessment>",
  
  "what_happened": {{
    "narrative": "<Detailed narrative explaining what activity is visible in this capture - what the application/user was doing, what services were contacted, the flow of communication>",
    "communication_flow": "<Description of the communication pattern - client-server interactions, request-response patterns, etc.>",
    "timeline": [
      {{
        "timestamp_range": "<time range or 'Throughout capture'>",
        "description": "<what happened during this period>",
        "hosts_involved": ["<IP addresses involved>"],
        "significance": "<why this matters>"
      }}
    ]
  }},
  
  "key_findings": [
    {{
      "title": "<Short title for the finding>",
      "severity": "<Critical|High|Medium|Low|Info>",
      "what_we_found": "<Detailed description of what was found and why it matters>",
      "technical_evidence": "<Specific evidence from the capture - IPs, ports, protocols, packet data>",
      "potential_impact": "<What could an attacker do with this information?>",
      "recommended_action": "<What should be done about this>"
    }}
  ],
  
  "traffic_analysis": {{
    "narrative_summary": "<Overview of the traffic patterns observed>",
    "overall_assessment": "<One line assessment of traffic security>",
    "protocol_breakdown_explained": "<Explanation of what protocols were used and why>",
    "encryption_assessment": "<Analysis of encrypted vs cleartext traffic>",
    "data_flow_analysis": "<Description of data movement between hosts>",
    "suspicious_patterns": [
      {{
        "pattern_name": "<Name of the pattern>",
        "description": "<What was observed>",
        "evidence": "<Specific evidence>",
        "severity": "<High|Medium|Low>"
      }}
    ],
    "protocols_of_concern": [
      {{
        "protocol": "<Protocol name>",
        "concern": "<Why it's concerning>",
        "affected_hosts": ["<IPs using this protocol>"]
      }}
    ]
  }},
  
  "hosts_analysis": [
    {{
      "ip_address": "<IP address>",
      "likely_role": "<Client|Server|Router|etc.>",
      "hostname": "<hostname if known>",
      "behavior_summary": "<What this host was doing>",
      "services_identified": ["<services running/used>"],
      "connections_made": <number>,
      "data_transferred": "<approximate data volume>",
      "risk_assessment": "<Risk level and explanation>",
      "concerns": ["<any security concerns for this host>"]
    }}
  ],
  
  "dns_analysis": {{
    "narrative_summary": "<Overview of DNS activity>",
    "overall_assessment": "<One line DNS security assessment>",
    "legitimate_activity": "<Description of normal DNS lookups>",
    "dga_analysis": "<Analysis for domain generation algorithm patterns>",
    "tunneling_analysis": "<Analysis for DNS tunneling indicators>",
    "suspicious_domains": [
      {{
        "domain": "<domain name>",
        "why_suspicious": "<reason for concern>",
        "threat_category": "<DGA|Tunneling|Malicious|Unknown|etc.>",
        "recommended_action": "<what to do>"
      }}
    ]
  }},
  
  "credential_exposure": {{
    "severity": "<Critical|High|Medium|Low|None>",
    "summary": "<Overview of credential exposure findings>",
    "exposed_credentials": [
      {{
        "type": "<Password|API Key|Token|Cookie|etc.>",
        "service": "<what service>",
        "source_ip": "<source IP>",
        "dest_ip": "<destination IP>",
        "risk": "<explanation of risk>"
      }}
    ],
    "immediate_actions": ["<urgent actions needed>"]
  }},
  
  "attack_indicators": {{
    "overall_assessment": "<Summary of attack indicator analysis>",
    "reconnaissance": {{
      "detected": <true/false>,
      "explanation": "<evidence or why not detected>"
    }},
    "lateral_movement": {{
      "detected": <true/false>,
      "explanation": "<evidence or why not detected>"
    }},
    "data_exfiltration": {{
      "detected": <true/false>,
      "explanation": "<evidence or why not detected>"
    }},
    "command_and_control": {{
      "detected": <true/false>,
      "explanation": "<evidence or why not detected>"
    }}
  }},
  
  "indicators_of_compromise": [
    {{
      "type": "<IP|Domain|Hash|URL|etc.>",
      "value": "<the actual indicator>",
      "threat_level": "<Critical|High|Medium|Low>",
      "context": "<where/how it was found>",
      "recommended_action": "<what to do>"
    }}
  ],
  
  "recommendations": [
    {{
      "priority": "<Immediate|High|Medium|Low>",
      "title": "<Short title>",
      "detailed_action": "<Specific steps to take>",
      "rationale": "<Why this is important based on the findings>",
      "expected_outcome": "<What improvement this will bring>"
    }}
  ],
  
  "conclusion": "<Final summary paragraph tying everything together and providing overall assessment>"
}}

RULES:
1. ONLY report what is actually in the data - do not invent findings
2. Use "None found" or empty arrays for sections with no findings
3. Use actual values from the capture, not placeholders
4. Be specific - cite actual IPs, domains, and protocols observed
5. Provide meaningful analysis, not just data regurgitation
6. Every finding must have evidence from the capture

Return ONLY valid JSON."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt
        )
        response_text = response.text.strip()
        
        # Clean up response - remove markdown code blocks if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        # Parse JSON response
        try:
            report = json.loads(response_text)
            return {"structured_report": report}
        except json.JSONDecodeError as je:
            logger.error(f"Failed to parse AI response as JSON: {je}")
            return {
                "raw_analysis": response_text,
                "parse_error": f"Failed to parse structured report: {str(je)}"
            }
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": f"AI analysis failed: {str(e)}"}
