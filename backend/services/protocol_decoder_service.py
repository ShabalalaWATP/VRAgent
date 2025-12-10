"""
Protocol Decoder Service for VRAgent.

Deep protocol analysis for PCAP files including:
- HTTP request/response parsing with header analysis
- FTP command/credential extraction
- SMTP email analysis
- DNS query/response parsing
- Telnet session reconstruction
- Credential extraction from cleartext protocols

All analysis is done locally - no external databases required.
"""

import re
import base64
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from collections import defaultdict
from urllib.parse import parse_qs

from backend.core.logging import get_logger

logger = get_logger(__name__)

# Try to import pyshark
PYSHARK_AVAILABLE = False
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    logger.warning("pyshark not available for protocol decoding")


@dataclass
class ExtractedCredential:
    """An extracted credential from network traffic."""
    credential_type: str  # http_basic, ftp, telnet, smtp, form_data, api_key, etc.
    protocol: str
    source_ip: str
    dest_ip: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    raw_data: Optional[str] = None
    packet_number: int = 0
    timestamp: Optional[str] = None
    context: Optional[str] = None  # URL, command, etc.
    severity: str = "critical"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HTTPTransaction:
    """A complete HTTP request/response pair."""
    request_method: str
    request_uri: str
    request_host: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_preview: Optional[str] = None
    source_ip: str = ""
    dest_ip: str = ""
    source_port: int = 0
    dest_port: int = 0
    timestamp: Optional[str] = None
    cookies: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    has_credentials: bool = False
    security_issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSQuery:
    """A DNS query with response."""
    query_name: str
    query_type: str
    source_ip: str
    dest_ip: str
    answers: List[Dict[str, str]] = field(default_factory=list)
    timestamp: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FTPSession:
    """An FTP session with commands and credentials."""
    source_ip: str
    dest_ip: str
    username: Optional[str] = None
    password: Optional[str] = None
    commands: List[Dict[str, Any]] = field(default_factory=list)
    files_transferred: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SMTPSession:
    """An SMTP email session."""
    source_ip: str
    dest_ip: str
    mail_from: Optional[str] = None
    rcpt_to: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    auth_used: bool = False
    auth_username: Optional[str] = None
    commands: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TelnetSession:
    """A Telnet session with captured data."""
    source_ip: str
    dest_ip: str
    captured_text: str = ""
    possible_username: Optional[str] = None
    possible_password: Optional[str] = None
    commands: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass  
class ProtocolAnalysisResult:
    """Complete protocol analysis results."""
    credentials: List[ExtractedCredential] = field(default_factory=list)
    http_transactions: List[HTTPTransaction] = field(default_factory=list)
    dns_queries: List[DNSQuery] = field(default_factory=list)
    ftp_sessions: List[FTPSession] = field(default_factory=list)
    smtp_sessions: List[SMTPSession] = field(default_factory=list)
    telnet_sessions: List[TelnetSession] = field(default_factory=list)
    
    total_http_requests: int = 0
    total_dns_queries: int = 0
    cleartext_credentials_found: int = 0
    suspicious_dns_queries: int = 0
    unencrypted_sensitive_data: int = 0
    
    protocol_stats: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "credentials": [c.to_dict() for c in self.credentials],
            "http_transactions": [h.to_dict() for h in self.http_transactions[:100]],  # Limit for response size
            "dns_queries": [d.to_dict() for d in self.dns_queries[:200]],
            "ftp_sessions": [f.to_dict() for f in self.ftp_sessions],
            "smtp_sessions": [s.to_dict() for s in self.smtp_sessions],
            "telnet_sessions": [t.to_dict() for t in self.telnet_sessions],
            "total_http_requests": self.total_http_requests,
            "total_dns_queries": self.total_dns_queries,
            "cleartext_credentials_found": self.cleartext_credentials_found,
            "suspicious_dns_queries": self.suspicious_dns_queries,
            "unencrypted_sensitive_data": self.unencrypted_sensitive_data,
            "protocol_stats": self.protocol_stats,
        }


# Suspicious DNS patterns
SUSPICIOUS_DNS_PATTERNS = [
    (r'^[a-z0-9]{30,}\.', "Unusually long subdomain - possible DNS tunneling"),
    (r'^[a-z0-9]{15,}\.[a-z]{2,4}$', "Random-looking domain - possible DGA"),
    (r'\.(xyz|top|win|gq|ml|cf|ga|tk)$', "Suspicious TLD commonly used for malware"),
    (r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', "IP address encoded in domain"),
    (r'^xn--', "Punycode domain - verify legitimacy"),
]

# Sensitive form field names
SENSITIVE_FORM_FIELDS = [
    "password", "passwd", "pwd", "pass", "secret",
    "api_key", "apikey", "api-key", "token", "auth",
    "credit_card", "creditcard", "card_number", "cvv", "cvc",
    "ssn", "social_security", "account_number",
    "private_key", "secret_key", "access_key",
]


def decode_protocols_from_pcap(pcap_path: str, max_packets: int = 50000) -> ProtocolAnalysisResult:
    """
    Deep decode protocols from a PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
        max_packets: Maximum packets to analyze
        
    Returns:
        ProtocolAnalysisResult with extracted data
    """
    if not PYSHARK_AVAILABLE:
        raise RuntimeError("pyshark not installed. Run: pip install pyshark")
    
    result = ProtocolAnalysisResult()
    
    # Track sessions
    ftp_sessions: Dict[tuple, FTPSession] = {}
    smtp_sessions: Dict[tuple, SMTPSession] = {}
    telnet_sessions: Dict[tuple, TelnetSession] = {}
    
    protocol_counts = defaultdict(int)
    
    try:
        cap = pyshark.FileCapture(pcap_path, keep_packets=False)
        
        for i, pkt in enumerate(cap):
            if i >= max_packets:
                break
            
            try:
                # Get basic IP info
                if not hasattr(pkt, 'ip'):
                    continue
                    
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                timestamp = str(pkt.sniff_time) if hasattr(pkt, 'sniff_time') else None
                
                # Process HTTP
                if hasattr(pkt, 'http'):
                    protocol_counts["HTTP"] += 1
                    http_result = _parse_http_pyshark(pkt, src_ip, dst_ip, i, timestamp)
                    if http_result:
                        if isinstance(http_result, HTTPTransaction):
                            result.http_transactions.append(http_result)
                            result.total_http_requests += 1
                        elif isinstance(http_result, list):
                            result.credentials.extend(http_result)
                
                # Process DNS
                if hasattr(pkt, 'dns'):
                    protocol_counts["DNS"] += 1
                    dns_result = _parse_dns_pyshark(pkt, src_ip, dst_ip, i, timestamp)
                    if dns_result:
                        result.dns_queries.append(dns_result)
                        result.total_dns_queries += 1
                        if dns_result.is_suspicious:
                            result.suspicious_dns_queries += 1
                
                # Process FTP
                if hasattr(pkt, 'ftp'):
                    protocol_counts["FTP"] += 1
                    session_key = (src_ip, dst_ip)
                    if session_key not in ftp_sessions:
                        ftp_sessions[session_key] = FTPSession(source_ip=src_ip, dest_ip=dst_ip)
                    cred = _parse_ftp_pyshark(pkt, ftp_sessions[session_key], src_ip, dst_ip, i, timestamp)
                    if cred:
                        result.credentials.append(cred)
                
                # Process SMTP
                if hasattr(pkt, 'smtp'):
                    protocol_counts["SMTP"] += 1
                    session_key = (src_ip, dst_ip)
                    if session_key not in smtp_sessions:
                        smtp_sessions[session_key] = SMTPSession(source_ip=src_ip, dest_ip=dst_ip)
                    cred = _parse_smtp_pyshark(pkt, smtp_sessions[session_key], src_ip, dst_ip, i, timestamp)
                    if cred:
                        result.credentials.append(cred)
                
                # Process Telnet
                if hasattr(pkt, 'telnet'):
                    protocol_counts["Telnet"] += 1
                    session_key = (src_ip, dst_ip)
                    if session_key not in telnet_sessions:
                        telnet_sessions[session_key] = TelnetSession(source_ip=src_ip, dest_ip=dst_ip)
                    cred = _parse_telnet_pyshark(pkt, telnet_sessions[session_key], src_ip, dst_ip, i, timestamp)
                    if cred:
                        result.credentials.append(cred)
                
                # Process TCP payload for generic credential patterns
                if hasattr(pkt, 'tcp') and hasattr(pkt, 'data'):
                    try:
                        payload = bytes.fromhex(pkt.data.data.replace(':', ''))
                        port = int(pkt.tcp.dstport)
                        creds = _extract_generic_credentials(payload, src_ip, dst_ip, port, i, timestamp)
                        result.credentials.extend(creds)
                    except:
                        pass
                        
            except Exception as e:
                logger.debug(f"Error processing packet {i}: {e}")
                continue
        
        cap.close()
        
    except Exception as e:
        logger.error(f"Failed to process PCAP: {e}")
        raise
    
    # Finalize sessions
    result.ftp_sessions = list(ftp_sessions.values())
    result.smtp_sessions = list(smtp_sessions.values())
    result.telnet_sessions = list(telnet_sessions.values())
    
    # Update statistics
    result.cleartext_credentials_found = len(result.credentials)
    result.protocol_stats = dict(protocol_counts)
    result.unencrypted_sensitive_data = (
        len(result.credentials) +
        len([h for h in result.http_transactions if h.has_credentials])
    )
    
    logger.info(f"Protocol analysis complete: {len(result.credentials)} credentials, "
                f"{result.total_http_requests} HTTP transactions, {result.total_dns_queries} DNS queries")
    
    return result


def _parse_http_pyshark(pkt, src_ip: str, dst_ip: str, pkt_num: int, timestamp: Optional[str]) -> Any:
    """Parse HTTP from pyshark packet."""
    credentials = []
    
    try:
        http = pkt.http
        
        # Check if request or response
        if hasattr(http, 'request_method'):
            method = http.request_method
            uri = http.request_uri if hasattr(http, 'request_uri') else "/"
            host = http.host if hasattr(http, 'host') else dst_ip
            
            # Build headers dict
            headers = {}
            for field in http.field_names:
                if field not in ['request_method', 'request_uri', 'request_version']:
                    try:
                        headers[field] = getattr(http, field)
                    except:
                        pass
            
            transaction = HTTPTransaction(
                request_method=method,
                request_uri=uri,
                request_host=host,
                request_headers=headers,
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=int(pkt.tcp.srcport) if hasattr(pkt, 'tcp') else 0,
                dest_port=int(pkt.tcp.dstport) if hasattr(pkt, 'tcp') else 0,
                timestamp=timestamp,
            )
            
            # Check for Authorization header
            if hasattr(http, 'authorization'):
                auth = http.authorization
                if auth.lower().startswith('basic '):
                    try:
                        decoded = base64.b64decode(auth[6:]).decode('utf-8')
                        if ':' in decoded:
                            username, password = decoded.split(':', 1)
                            credentials.append(ExtractedCredential(
                                credential_type="http_basic",
                                protocol="HTTP",
                                source_ip=src_ip,
                                dest_ip=dst_ip,
                                port=int(pkt.tcp.dstport) if hasattr(pkt, 'tcp') else 80,
                                username=username,
                                password=password,
                                packet_number=pkt_num,
                                timestamp=timestamp,
                                context=f"{method} {host}{uri}",
                            ))
                            transaction.has_credentials = True
                    except:
                        pass
                elif auth.lower().startswith('bearer '):
                    credentials.append(ExtractedCredential(
                        credential_type="bearer_token",
                        protocol="HTTP",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=int(pkt.tcp.dstport) if hasattr(pkt, 'tcp') else 80,
                        token=auth[7:],
                        packet_number=pkt_num,
                        timestamp=timestamp,
                        context=f"{method} {host}{uri}",
                        severity="high",
                    ))
                    transaction.has_credentials = True
            
            # Check for cookies with session/auth info
            if hasattr(http, 'cookie'):
                transaction.cookies = [http.cookie]
                cookie_lower = http.cookie.lower()
                if any(s in cookie_lower for s in ['session', 'auth', 'token', 'jwt']):
                    transaction.has_credentials = True
            
            # Check for form data in POST
            if hasattr(http, 'file_data'):
                try:
                    body = http.file_data
                    for field_name in SENSITIVE_FORM_FIELDS:
                        if field_name in body.lower():
                            credentials.append(ExtractedCredential(
                                credential_type="form_data",
                                protocol="HTTP",
                                source_ip=src_ip,
                                dest_ip=dst_ip,
                                port=int(pkt.tcp.dstport) if hasattr(pkt, 'tcp') else 80,
                                raw_data=body[:200],
                                packet_number=pkt_num,
                                timestamp=timestamp,
                                context=f"POST {host}{uri}",
                            ))
                            transaction.has_credentials = True
                            break
                except:
                    pass
            
            if credentials:
                return credentials
            return transaction
            
    except Exception as e:
        logger.debug(f"Error parsing HTTP: {e}")
    
    return None


def _parse_dns_pyshark(pkt, src_ip: str, dst_ip: str, pkt_num: int, timestamp: Optional[str]) -> Optional[DNSQuery]:
    """Parse DNS from pyshark packet."""
    try:
        dns = pkt.dns
        
        # Get query name
        qname = dns.qry_name if hasattr(dns, 'qry_name') else None
        if not qname:
            return None
        
        # Get query type
        qtype = "A"
        if hasattr(dns, 'qry_type'):
            type_map = {'1': 'A', '2': 'NS', '5': 'CNAME', '15': 'MX', '16': 'TXT', '28': 'AAAA'}
            qtype = type_map.get(str(dns.qry_type), str(dns.qry_type))
        
        query = DNSQuery(
            query_name=qname,
            query_type=qtype,
            source_ip=src_ip,
            dest_ip=dst_ip,
            timestamp=timestamp,
        )
        
        # Get answers
        if hasattr(dns, 'a'):
            query.answers.append({"type": "A", "value": dns.a})
        if hasattr(dns, 'aaaa'):
            query.answers.append({"type": "AAAA", "value": dns.aaaa})
        if hasattr(dns, 'cname'):
            query.answers.append({"type": "CNAME", "value": dns.cname})
        
        # Check for suspicious patterns
        for pattern, reason in SUSPICIOUS_DNS_PATTERNS:
            if re.search(pattern, qname.lower()):
                query.is_suspicious = True
                query.suspicion_reason = reason
                break
        
        return query
        
    except Exception as e:
        logger.debug(f"Error parsing DNS: {e}")
    
    return None


def _parse_ftp_pyshark(pkt, session: FTPSession, src_ip: str, dst_ip: str, 
                       pkt_num: int, timestamp: Optional[str]) -> Optional[ExtractedCredential]:
    """Parse FTP from pyshark packet."""
    try:
        ftp = pkt.ftp
        
        if hasattr(ftp, 'request_command'):
            cmd = ftp.request_command.upper()
            arg = ftp.request_arg if hasattr(ftp, 'request_arg') else ""
            
            if cmd == 'USER':
                session.username = arg
                session.commands.append({"cmd": "USER", "value": arg, "pkt": pkt_num})
            elif cmd == 'PASS':
                session.password = arg
                session.commands.append({"cmd": "PASS", "value": "***", "pkt": pkt_num})
                
                return ExtractedCredential(
                    credential_type="ftp",
                    protocol="FTP",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=21,
                    username=session.username,
                    password=session.password,
                    packet_number=pkt_num,
                    timestamp=timestamp,
                    context=f"FTP login to {dst_ip}",
                )
            elif cmd in ['STOR', 'RETR', 'DELE']:
                session.files_transferred.append(arg)
                session.commands.append({"cmd": cmd, "value": arg, "pkt": pkt_num})
                
    except Exception as e:
        logger.debug(f"Error parsing FTP: {e}")
    
    return None


def _parse_smtp_pyshark(pkt, session: SMTPSession, src_ip: str, dst_ip: str,
                        pkt_num: int, timestamp: Optional[str]) -> Optional[ExtractedCredential]:
    """Parse SMTP from pyshark packet."""
    try:
        smtp = pkt.smtp
        
        if hasattr(smtp, 'req_command'):
            cmd = smtp.req_command.upper()
            param = smtp.req_parameter if hasattr(smtp, 'req_parameter') else ""
            
            session.commands.append(f"{cmd} {param}"[:100])
            
            if cmd == 'AUTH':
                session.auth_used = True
                
                if 'PLAIN' in param.upper() and len(param.split()) >= 2:
                    try:
                        encoded = param.split()[-1]
                        decoded = base64.b64decode(encoded).decode('utf-8')
                        creds = decoded.split('\x00')
                        if len(creds) >= 3:
                            session.auth_username = creds[1]
                            return ExtractedCredential(
                                credential_type="smtp_auth",
                                protocol="SMTP",
                                source_ip=src_ip,
                                dest_ip=dst_ip,
                                port=25,
                                username=creds[1],
                                password=creds[2],
                                packet_number=pkt_num,
                                timestamp=timestamp,
                                context="SMTP AUTH PLAIN",
                            )
                    except:
                        pass
                        
            elif cmd == 'MAIL' and 'FROM' in param.upper():
                email = re.search(r'<(.+?)>', param)
                if email:
                    session.mail_from = email.group(1)
            elif cmd == 'RCPT' and 'TO' in param.upper():
                email = re.search(r'<(.+?)>', param)
                if email:
                    session.rcpt_to.append(email.group(1))
                    
    except Exception as e:
        logger.debug(f"Error parsing SMTP: {e}")
    
    return None


def _parse_telnet_pyshark(pkt, session: TelnetSession, src_ip: str, dst_ip: str,
                          pkt_num: int, timestamp: Optional[str]) -> Optional[ExtractedCredential]:
    """Parse Telnet from pyshark packet."""
    try:
        telnet = pkt.telnet
        
        if hasattr(telnet, 'data'):
            text = telnet.data
            text = ''.join(c for c in text if c.isprintable() or c in '\r\n').strip()
            
            if not text:
                return None
            
            session.captured_text += text + " "
            text_lower = text.lower()
            
            if session.possible_username and not session.possible_password:
                if len(text) < 50 and not any(x in text_lower for x in ['login', 'password', 'username']):
                    session.possible_password = text
                    
                    return ExtractedCredential(
                        credential_type="telnet",
                        protocol="Telnet",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=23,
                        username=session.possible_username,
                        password=session.possible_password,
                        packet_number=pkt_num,
                        timestamp=timestamp,
                        context="Telnet login",
                    )
            elif not session.possible_username:
                if len(text) < 50 and text.isprintable() and ' ' not in text:
                    if not any(x in text_lower for x in ['login', 'password', 'welcome', 'last']):
                        session.possible_username = text
            
            if len(text) < 200:
                session.commands.append(text)
                
    except Exception as e:
        logger.debug(f"Error parsing Telnet: {e}")
    
    return None


def _extract_generic_credentials(payload: bytes, src_ip: str, dst_ip: str, 
                                  port: int, pkt_num: int, timestamp: Optional[str]) -> List[ExtractedCredential]:
    """Extract credentials from generic TCP payload using patterns."""
    credentials = []
    
    try:
        text = payload.decode('utf-8', errors='ignore')
    except:
        return credentials
    
    # API Key patterns
    api_key_patterns = [
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "api_key"),
        (r'["\']?apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "api_key"),
        (r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', "access_token"),
        (r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', "auth_token"),
        (r'Bearer\s+([a-zA-Z0-9_\-\.]+)', "bearer_token"),
        (r'Basic\s+([a-zA-Z0-9+/=]+)', "basic_auth"),
    ]
    
    for pattern, cred_type in api_key_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Decode basic auth
            if cred_type == "basic_auth":
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        credentials.append(ExtractedCredential(
                            credential_type="http_basic",
                            protocol="TCP",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            port=port,
                            username=username,
                            password=password,
                            packet_number=pkt_num,
                            timestamp=timestamp,
                        ))
                        continue
                except:
                    pass
            
            credentials.append(ExtractedCredential(
                credential_type=cred_type,
                protocol="TCP",
                source_ip=src_ip,
                dest_ip=dst_ip,
                port=port,
                token=match,
                packet_number=pkt_num,
                timestamp=timestamp,
                severity="high",
            ))
    
    # Password patterns
    password_patterns = [
        r'["\']?password["\']?\s*[:=]\s*["\']?([^"\'\s&]{4,})["\']?',
        r'["\']?passwd["\']?\s*[:=]\s*["\']?([^"\'\s&]{4,})["\']?',
        r'["\']?pwd["\']?\s*[:=]\s*["\']?([^"\'\s&]{4,})["\']?',
    ]
    
    for pattern in password_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if len(match) >= 4 and match not in ['null', 'undefined', 'none', 'true', 'false']:
                credentials.append(ExtractedCredential(
                    credential_type="password",
                    protocol="TCP",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=port,
                    password=match,
                    packet_number=pkt_num,
                    timestamp=timestamp,
                ))
    
    return credentials


def analyze_protocols_with_ai(result: ProtocolAnalysisResult) -> Dict[str, Any]:
    """Use AI to analyze protocol findings."""
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        return {"error": "AI analysis unavailable: GEMINI_API_KEY not configured"}
    
    try:
        from google import genai
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build context
        creds_text = "\n".join(
            f"- [{c.credential_type}] {c.protocol} {c.source_ip} -> {c.dest_ip}:{c.port}"
            + (f" user={c.username}" if c.username else "")
            + (f" context={c.context}" if c.context else "")
            for c in result.credentials[:20]
        )
        
        dns_suspicious = [d for d in result.dns_queries if d.is_suspicious]
        dns_text = "\n".join(
            f"- {d.query_name}: {d.suspicion_reason}"
            for d in dns_suspicious[:10]
        )
        
        prompt = f"""Analyze this network traffic protocol analysis:

## Statistics
- Credentials Found: {result.cleartext_credentials_found}
- HTTP Requests: {result.total_http_requests}
- DNS Queries: {result.total_dns_queries}
- Suspicious DNS: {result.suspicious_dns_queries}
- Protocols: {result.protocol_stats}

## Extracted Credentials
{creds_text if creds_text else "None found"}

## Suspicious DNS Queries
{dns_text if dns_text else "None found"}

Provide a security assessment as JSON:
{{
  "risk_level": "Critical|High|Medium|Low",
  "risk_score": <0-100>,
  "summary": "<brief summary>",
  "credential_exposure": {{
    "severity": "Critical|High|Medium|Low|None",
    "details": "<what was exposed>"
  }},
  "dns_analysis": {{
    "suspicious_activity": true|false,
    "details": "<explanation>"
  }},
  "recommendations": ["<action1>", "<action2>"]
}}

Return ONLY valid JSON."""

        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt
        )
        response_text = response.text.strip()
        
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        response_text = response_text.strip()
        
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            return {"raw_analysis": response_text}
            
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": str(e)}
