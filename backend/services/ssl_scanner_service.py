"""
SSL/TLS Scanner Service for VRAgent.

Performs comprehensive SSL/TLS security analysis including:
- Certificate chain validation and expiry
- Protocol version detection (SSLv3, TLS 1.0/1.1/1.2/1.3)
- Cipher suite enumeration and weakness detection
- Known vulnerabilities (POODLE, BEAST, CRIME, Heartbleed, ROBOT, etc.)
- AI-powered exploitation analysis

All analysis is done locally - no external databases required.
"""

import json
import socket
import ssl
import datetime
import hashlib
import struct
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Weak cipher keywords
WEAK_CIPHER_KEYWORDS = [
    "NULL", "EXPORT", "DES", "RC4", "RC2", "MD5", "ADH", "AECDH", "anon", "3DES"
]

# Cipher suites vulnerable to specific attacks
BEAST_VULNERABLE_CIPHERS = ["CBC"]  # CBC mode in TLS 1.0
SWEET32_VULNERABLE_CIPHERS = ["3DES", "DES", "IDEA", "RC2"]  # 64-bit block ciphers
CRIME_COMPRESSION_METHODS = ["DEFLATE", "LZS"]

# Known SSL/TLS vulnerabilities with detection methods
KNOWN_VULNERABILITIES = {
    "POODLE": {
        "id": "CVE-2014-3566",
        "severity": "high",
        "name": "POODLE (Padding Oracle On Downgraded Legacy Encryption)",
        "description": "SSLv3 is vulnerable to a padding oracle attack that can decrypt encrypted data.",
        "affected": "SSLv3 protocol with CBC ciphers",
        "cvss": 3.4,
        "exploit_difficulty": "Medium",
    },
    "BEAST": {
        "id": "CVE-2011-3389",
        "severity": "medium",
        "name": "BEAST (Browser Exploit Against SSL/TLS)",
        "description": "TLS 1.0 CBC ciphers are vulnerable to chosen-plaintext attacks via blockwise chosen-boundary attack.",
        "affected": "TLS 1.0 with CBC ciphers",
        "cvss": 4.3,
        "exploit_difficulty": "High",
    },
    "CRIME": {
        "id": "CVE-2012-4929",
        "severity": "medium",
        "name": "CRIME (Compression Ratio Info-leak Made Easy)",
        "description": "TLS compression can leak information about encrypted data through compression ratio analysis.",
        "affected": "TLS with compression enabled",
        "cvss": 4.3,
        "exploit_difficulty": "Medium",
    },
    "BREACH": {
        "id": "CVE-2013-3587",
        "severity": "medium",
        "name": "BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)",
        "description": "HTTP compression can be exploited to extract secrets from encrypted HTTPS responses.",
        "affected": "HTTPS with HTTP compression",
        "cvss": 5.9,
        "exploit_difficulty": "Medium",
    },
    "HEARTBLEED": {
        "id": "CVE-2014-0160",
        "severity": "critical",
        "name": "Heartbleed",
        "description": "A buffer over-read vulnerability in OpenSSL that can leak memory contents including private keys.",
        "affected": "OpenSSL 1.0.1 through 1.0.1f",
        "cvss": 9.8,
        "exploit_difficulty": "Low",
    },
    "FREAK": {
        "id": "CVE-2015-0204",
        "severity": "high",
        "name": "FREAK (Factoring RSA Export Keys)",
        "description": "Export-grade RSA keys can be factored, allowing MITM attacks.",
        "affected": "Servers supporting RSA_EXPORT cipher suites",
        "cvss": 5.9,
        "exploit_difficulty": "Medium",
    },
    "LOGJAM": {
        "id": "CVE-2015-4000",
        "severity": "high",
        "name": "Logjam",
        "description": "Weak Diffie-Hellman parameters allow downgrade attacks.",
        "affected": "Servers using DH parameters < 1024 bits",
        "cvss": 3.7,
        "exploit_difficulty": "High",
    },
    "DROWN": {
        "id": "CVE-2016-0800",
        "severity": "critical",
        "name": "DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)",
        "description": "SSLv2 support can be exploited to decrypt TLS traffic using the same RSA key.",
        "affected": "Servers with SSLv2 enabled or sharing keys with SSLv2 servers",
        "cvss": 5.9,
        "exploit_difficulty": "Medium",
    },
    "ROBOT": {
        "id": "CVE-2017-13099",
        "severity": "high",
        "name": "ROBOT (Return Of Bleichenbacher's Oracle Threat)",
        "description": "RSA key exchange implementations may be vulnerable to Bleichenbacher's padding oracle.",
        "affected": "Servers using RSA key exchange",
        "cvss": 5.9,
        "exploit_difficulty": "Medium",
    },
    "LUCKY13": {
        "id": "CVE-2013-0169",
        "severity": "low",
        "name": "Lucky Thirteen",
        "description": "Timing attack against CBC ciphers in TLS that can recover plaintext.",
        "affected": "TLS with CBC ciphers",
        "cvss": 3.7,
        "exploit_difficulty": "Very High",
    },
    "SWEET32": {
        "id": "CVE-2016-2183",
        "severity": "medium",
        "name": "Sweet32",
        "description": "Birthday attack against 64-bit block ciphers (3DES, Blowfish) after ~32GB of data.",
        "affected": "Ciphers with 64-bit blocks (3DES, DES, IDEA, RC2)",
        "cvss": 5.3,
        "exploit_difficulty": "Medium",
    },
    "ROCA": {
        "id": "CVE-2017-15361",
        "severity": "high",
        "name": "ROCA (Return of Coppersmith's Attack)",
        "description": "RSA keys generated by Infineon chips can be factored due to weak key generation.",
        "affected": "RSA keys from Infineon TPMs and smartcards",
        "cvss": 5.9,
        "exploit_difficulty": "Medium",
    },
}

# Known protocol vulnerabilities
PROTOCOL_VULNERABILITIES = {
    "SSLv2": {
        "severity": "critical",
        "name": "SSLv2 Protocol",
        "description": "SSLv2 is fundamentally broken and has been deprecated since 2011.",
        "cves": ["CVE-2016-0800"],
        "recommendation": "Disable SSLv2 completely.",
    },
    "SSLv3": {
        "severity": "critical", 
        "name": "SSLv3 Protocol (POODLE)",
        "description": "SSLv3 is vulnerable to the POODLE attack.",
        "cves": ["CVE-2014-3566"],
        "recommendation": "Disable SSLv3 completely.",
    },
    "TLSv1.0": {
        "severity": "high",
        "name": "TLS 1.0 Protocol",
        "description": "TLS 1.0 is deprecated and vulnerable to BEAST. PCI-DSS requires TLS 1.2+.",
        "cves": ["CVE-2011-3389"],
        "recommendation": "Upgrade to TLS 1.2 or higher.",
    },
    "TLSv1.1": {
        "severity": "medium",
        "name": "TLS 1.1 Protocol",
        "description": "TLS 1.1 is deprecated by major browsers and standards.",
        "cves": [],
        "recommendation": "Upgrade to TLS 1.2 or higher.",
    },
}

# Well-known trusted root CAs (subset for offline validation)
TRUSTED_ROOT_CA_NAMES = [
    "DigiCert", "Let's Encrypt", "GlobalSign", "Comodo", "GeoTrust",
    "VeriSign", "Thawte", "Entrust", "GoDaddy", "Amazon", "Microsoft",
    "Google Trust Services", "Sectigo", "IdenTrust", "QuoVadis",
    "SwissSign", "Buypass", "Certum", "ISRG", "Baltimore"
]


@dataclass
class SSLCertificate:
    """SSL Certificate information."""
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    version: int = 0
    serial_number: str = ""
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    signature_algorithm: Optional[str] = None
    public_key_bits: Optional[int] = None
    public_key_type: Optional[str] = None
    san: List[str] = field(default_factory=list)
    sha256_fingerprint: Optional[str] = None
    # Chain validation fields
    chain_position: int = 0  # 0 = leaf, 1+ = intermediates, -1 = root
    is_ca: bool = False
    is_trusted_root: bool = False
    chain_valid: bool = True
    chain_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CertificateChainInfo:
    """Certificate chain validation information."""
    chain_length: int = 0
    is_complete: bool = False
    is_trusted: bool = False
    root_ca: Optional[str] = None
    chain_errors: List[str] = field(default_factory=list)
    certificates: List[SSLCertificate] = field(default_factory=list)
    trust_anchor: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_length": self.chain_length,
            "is_complete": self.is_complete,
            "is_trusted": self.is_trusted,
            "root_ca": self.root_ca,
            "chain_errors": self.chain_errors,
            "certificates": [c.to_dict() for c in self.certificates],
            "trust_anchor": self.trust_anchor,
        }


@dataclass 
class VulnerabilityInfo:
    """Detected SSL/TLS vulnerability."""
    vuln_id: str
    cve: str
    name: str
    severity: str
    description: str
    affected: str
    cvss: float
    exploit_difficulty: str
    is_exploitable: bool = True
    evidence: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SSLFinding:
    """A security finding from SSL/TLS analysis."""
    category: str  # certificate, protocol, cipher, configuration
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    host: str
    port: int
    evidence: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SSLScanResult:
    """Result of SSL/TLS scan for a single host."""
    host: str
    port: int
    is_ssl: bool
    error: Optional[str] = None
    certificate: Optional[SSLCertificate] = None
    certificate_chain: List[SSLCertificate] = field(default_factory=list)
    chain_info: Optional[CertificateChainInfo] = None
    protocols_supported: Dict[str, bool] = field(default_factory=dict)
    cipher_suites: List[Dict[str, Any]] = field(default_factory=list)
    preferred_cipher: Optional[str] = None
    findings: List[SSLFinding] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    server_name: Optional[str] = None
    supports_sni: bool = False
    compression_enabled: bool = False
    session_resumption: bool = False
    ocsp_stapling: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_ssl": self.is_ssl,
            "error": self.error,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "certificate_chain": [c.to_dict() for c in self.certificate_chain],
            "chain_info": self.chain_info.to_dict() if self.chain_info else None,
            "protocols_supported": self.protocols_supported,
            "cipher_suites": self.cipher_suites,
            "preferred_cipher": self.preferred_cipher,
            "findings": [f.to_dict() for f in self.findings],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "server_name": self.server_name,
            "supports_sni": self.supports_sni,
            "compression_enabled": self.compression_enabled,
            "session_resumption": self.session_resumption,
            "ocsp_stapling": self.ocsp_stapling,
        }


@dataclass
class SSLScanSummary:
    """Summary of SSL scan results."""
    total_hosts: int
    hosts_scanned: int
    hosts_with_ssl: int
    hosts_failed: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    certificates_expiring_soon: int
    certificates_expired: int
    hosts_with_weak_protocols: int
    hosts_with_weak_ciphers: int
    # New vulnerability tracking
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    exploitable_vulnerabilities: int = 0
    chain_issues: int = 0
    self_signed_certs: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SSLScanAnalysisResult:
    """Complete SSL scan analysis result."""
    scan_id: str
    summary: SSLScanSummary
    results: List[SSLScanResult] = field(default_factory=list)
    all_findings: List[SSLFinding] = field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "summary": self.summary.to_dict(),
            "results": [r.to_dict() for r in self.results],
            "all_findings": [f.to_dict() for f in self.all_findings],
            "ai_analysis": self.ai_analysis,
        }


def parse_certificate(cert_der: bytes) -> SSLCertificate:
    """Parse a DER-encoded certificate."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Extract subject
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value
        
        # Extract issuer
        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value
        
        # Calculate expiry
        now = datetime.datetime.now(datetime.timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        days_until_expiry = (not_after - now).days
        
        # Get SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    sans.append(str(name.value))
        except x509.ExtensionNotFound:
            pass
        
        # Get public key info
        pub_key = cert.public_key()
        key_size = pub_key.key_size if hasattr(pub_key, 'key_size') else None
        key_type = type(pub_key).__name__.replace('PublicKey', '').replace('_', '')
        
        # SHA256 fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        
        not_before_str = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat()
        
        return SSLCertificate(
            subject=subject,
            issuer=issuer,
            version=cert.version.value,
            serial_number=format(cert.serial_number, 'x'),
            not_before=not_before_str,
            not_after=not_after.isoformat(),
            days_until_expiry=days_until_expiry,
            is_expired=days_until_expiry < 0,
            is_self_signed=cert.subject == cert.issuer,
            signature_algorithm=cert.signature_algorithm_oid._name,
            public_key_bits=key_size,
            public_key_type=key_type,
            san=sans,
            sha256_fingerprint=fingerprint,
        )
    except ImportError:
        logger.warning("cryptography library not installed, using basic certificate parsing")
        return SSLCertificate()
    except Exception as e:
        logger.warning(f"Failed to parse certificate: {e}")
        return SSLCertificate()


def _check_protocol(host: str, port: int, protocol_version, timeout: float = 5.0) -> Tuple[bool, Optional[str]]:
    """Check if a specific SSL/TLS protocol version is supported."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = protocol_version
        context.maximum_version = protocol_version
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ssock.cipher()[0] if ssock.cipher() else None
    except ssl.SSLError:
        return False, None
    except Exception:
        return False, None


def _get_cipher_suites(host: str, port: int, timeout: float = 5.0) -> List[Dict[str, Any]]:
    """Get list of supported cipher suites."""
    supported = []
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    supported.append({
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                        "is_weak": _is_weak_cipher(cipher[0]),
                    })
                
                # Get shared ciphers if available
                shared = ssock.shared_ciphers()
                if shared:
                    for c in shared:
                        if c[0] not in [s["name"] for s in supported]:
                            supported.append({
                                "name": c[0],
                                "protocol": c[1] if len(c) > 1 else "unknown",
                                "bits": c[2] if len(c) > 2 else 0,
                                "is_weak": _is_weak_cipher(c[0]),
                            })
    except Exception as e:
        logger.debug(f"Failed to enumerate ciphers for {host}:{port}: {e}")
    
    return supported


def _is_weak_cipher(cipher_name: str) -> bool:
    """Check if a cipher is considered weak."""
    cipher_upper = cipher_name.upper()
    
    for keyword in WEAK_CIPHER_KEYWORDS:
        if keyword.upper() in cipher_upper:
            return True
    
    return False


def _check_heartbleed(host: str, port: int, timeout: float = 5.0) -> Tuple[bool, str]:
    """
    Check for Heartbleed vulnerability (CVE-2014-0160).
    Sends a malformed heartbeat request and checks for memory leak.
    """
    try:
        # TLS heartbeat request with malformed length
        hello = bytes([
            0x16,  # Content type: Handshake
            0x03, 0x01,  # Version: TLS 1.0
            0x00, 0xdc,  # Length
            0x01,  # Handshake type: ClientHello
            0x00, 0x00, 0xd8,  # Length
            0x03, 0x02,  # Version: TLS 1.1
        ])
        
        # Add random bytes and cipher suites
        import os
        hello += os.urandom(32)  # Random
        hello += bytes([0x00])  # Session ID length
        hello += bytes([0x00, 0x66])  # Cipher suites length
        
        # Common cipher suites
        ciphers = [
            0xc014, 0xc00a, 0xc022, 0xc021, 0x0039, 0x0038,
            0x0088, 0x0087, 0xc00f, 0xc005, 0x0035, 0x0084,
            0xc012, 0xc008, 0xc01c, 0xc01b, 0x0016, 0x0013,
            0xc00d, 0xc003, 0x000a, 0xc013, 0xc009, 0xc01f,
            0xc01e, 0x0033, 0x0032, 0x009a, 0x0099, 0x0045,
        ]
        for c in ciphers:
            hello += struct.pack(">H", c)
        
        hello += bytes([0x01, 0x00])  # Compression methods
        hello += bytes([0x00, 0x49])  # Extensions length
        
        # Heartbeat extension
        hello += bytes([0x00, 0x0f, 0x00, 0x01, 0x01])  # Heartbeat extension
        
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.send(hello)
        
        # Receive ServerHello
        response = sock.recv(1024)
        
        if not response:
            sock.close()
            return False, "No response"
        
        # Send heartbeat request with malformed length
        heartbeat = bytes([
            0x18,  # Content type: Heartbeat
            0x03, 0x02,  # Version: TLS 1.1
            0x00, 0x03,  # Length
            0x01,  # Heartbeat type: request
            0x40, 0x00,  # Payload length: 16384 (malformed - much larger than actual payload)
        ])
        
        sock.send(heartbeat)
        
        # Check for response
        sock.settimeout(3)
        try:
            response = sock.recv(16384)
            if len(response) > 10:
                sock.close()
                return True, f"Received {len(response)} bytes - server leaked memory"
        except socket.timeout:
            pass
        
        sock.close()
        return False, "Not vulnerable"
        
    except Exception as e:
        return False, f"Check failed: {str(e)}"


def _check_robot(host: str, port: int, timeout: float = 5.0) -> Tuple[bool, str]:
    """
    Check for ROBOT vulnerability (CVE-2017-13099).
    Tests for Bleichenbacher oracle in RSA key exchange.
    Note: This is a simplified check - full ROBOT requires many requests.
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher and "RSA" in cipher[0] and "DHE" not in cipher[0] and "ECDHE" not in cipher[0]:
                    # Server prefers RSA key exchange (potentially vulnerable)
                    return True, f"Server uses RSA key exchange: {cipher[0]}"
                return False, "Server uses forward-secrecy cipher"
    except Exception as e:
        return False, f"Check failed: {str(e)}"


def _check_compression(host: str, port: int, timeout: float = 5.0) -> Tuple[bool, str]:
    """Check if TLS compression is enabled (CRIME/BREACH vulnerability)."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Python's ssl module doesn't expose compression directly
                # We check for compression support in the handshake
                compression = getattr(ssock, 'compression', None)
                if compression and compression():
                    return True, f"TLS compression enabled: {compression()}"
                return False, "Compression not detected"
    except Exception as e:
        return False, f"Check failed: {str(e)}"


def _detect_vulnerabilities(
    host: str,
    port: int, 
    protocols: Dict[str, bool],
    ciphers: List[Dict[str, Any]],
    timeout: float = 5.0
) -> List[VulnerabilityInfo]:
    """Detect known SSL/TLS vulnerabilities based on configuration."""
    vulnerabilities = []
    
    # POODLE - SSLv3 with CBC
    if protocols.get("SSLv3"):
        cbc_ciphers = [c for c in ciphers if "CBC" in c.get("name", "")]
        if cbc_ciphers:
            vuln = KNOWN_VULNERABILITIES["POODLE"]
            vulnerabilities.append(VulnerabilityInfo(
                vuln_id="POODLE",
                cve=vuln["id"],
                name=vuln["name"],
                severity=vuln["severity"],
                description=vuln["description"],
                affected=vuln["affected"],
                cvss=vuln["cvss"],
                exploit_difficulty=vuln["exploit_difficulty"],
                is_exploitable=True,
                evidence=f"SSLv3 enabled with CBC ciphers: {', '.join(c['name'] for c in cbc_ciphers[:3])}"
            ))
    
    # BEAST - TLS 1.0 with CBC
    if protocols.get("TLSv1.0"):
        cbc_ciphers = [c for c in ciphers if "CBC" in c.get("name", "")]
        if cbc_ciphers:
            vuln = KNOWN_VULNERABILITIES["BEAST"]
            vulnerabilities.append(VulnerabilityInfo(
                vuln_id="BEAST",
                cve=vuln["id"],
                name=vuln["name"],
                severity=vuln["severity"],
                description=vuln["description"],
                affected=vuln["affected"],
                cvss=vuln["cvss"],
                exploit_difficulty=vuln["exploit_difficulty"],
                is_exploitable=True,
                evidence=f"TLS 1.0 enabled with CBC ciphers"
            ))
    
    # DROWN - SSLv2
    if protocols.get("SSLv2"):
        vuln = KNOWN_VULNERABILITIES["DROWN"]
        vulnerabilities.append(VulnerabilityInfo(
            vuln_id="DROWN",
            cve=vuln["id"],
            name=vuln["name"],
            severity=vuln["severity"],
            description=vuln["description"],
            affected=vuln["affected"],
            cvss=vuln["cvss"],
            exploit_difficulty=vuln["exploit_difficulty"],
            is_exploitable=True,
            evidence="SSLv2 protocol enabled"
        ))
    
    # FREAK - Export ciphers
    export_ciphers = [c for c in ciphers if "EXPORT" in c.get("name", "").upper()]
    if export_ciphers:
        vuln = KNOWN_VULNERABILITIES["FREAK"]
        vulnerabilities.append(VulnerabilityInfo(
            vuln_id="FREAK",
            cve=vuln["id"],
            name=vuln["name"],
            severity=vuln["severity"],
            description=vuln["description"],
            affected=vuln["affected"],
            cvss=vuln["cvss"],
            exploit_difficulty=vuln["exploit_difficulty"],
            is_exploitable=True,
            evidence=f"Export ciphers supported: {', '.join(c['name'] for c in export_ciphers)}"
        ))
    
    # SWEET32 - 64-bit block ciphers
    weak_block_ciphers = [c for c in ciphers if any(kw in c.get("name", "").upper() for kw in SWEET32_VULNERABLE_CIPHERS)]
    if weak_block_ciphers:
        vuln = KNOWN_VULNERABILITIES["SWEET32"]
        vulnerabilities.append(VulnerabilityInfo(
            vuln_id="SWEET32",
            cve=vuln["id"],
            name=vuln["name"],
            severity=vuln["severity"],
            description=vuln["description"],
            affected=vuln["affected"],
            cvss=vuln["cvss"],
            exploit_difficulty=vuln["exploit_difficulty"],
            is_exploitable=True,
            evidence=f"64-bit block ciphers: {', '.join(c['name'] for c in weak_block_ciphers[:3])}"
        ))
    
    # LUCKY13 - CBC ciphers in TLS
    cbc_ciphers = [c for c in ciphers if "CBC" in c.get("name", "")]
    if cbc_ciphers and (protocols.get("TLSv1.0") or protocols.get("TLSv1.1") or protocols.get("TLSv1.2")):
        vuln = KNOWN_VULNERABILITIES["LUCKY13"]
        vulnerabilities.append(VulnerabilityInfo(
            vuln_id="LUCKY13",
            cve=vuln["id"],
            name=vuln["name"],
            severity=vuln["severity"],
            description=vuln["description"],
            affected=vuln["affected"],
            cvss=vuln["cvss"],
            exploit_difficulty=vuln["exploit_difficulty"],
            is_exploitable=False,  # Very difficult to exploit
            evidence=f"CBC ciphers enabled in TLS"
        ))
    
    # ROBOT - RSA key exchange (without perfect forward secrecy)
    rsa_kex_ciphers = [c for c in ciphers 
                       if "RSA" in c.get("name", "") 
                       and "DHE" not in c.get("name", "") 
                       and "ECDHE" not in c.get("name", "")]
    if rsa_kex_ciphers:
        vuln = KNOWN_VULNERABILITIES["ROBOT"]
        vulnerabilities.append(VulnerabilityInfo(
            vuln_id="ROBOT",
            cve=vuln["id"],
            name=vuln["name"],
            severity=vuln["severity"],
            description=vuln["description"],
            affected=vuln["affected"],
            cvss=vuln["cvss"],
            exploit_difficulty=vuln["exploit_difficulty"],
            is_exploitable=True,
            evidence=f"RSA key exchange ciphers: {', '.join(c['name'] for c in rsa_kex_ciphers[:3])}"
        ))
    
    # Heartbleed check (active probe)
    try:
        is_vulnerable, evidence = _check_heartbleed(host, port, timeout)
        if is_vulnerable:
            vuln = KNOWN_VULNERABILITIES["HEARTBLEED"]
            vulnerabilities.append(VulnerabilityInfo(
                vuln_id="HEARTBLEED",
                cve=vuln["id"],
                name=vuln["name"],
                severity=vuln["severity"],
                description=vuln["description"],
                affected=vuln["affected"],
                cvss=vuln["cvss"],
                exploit_difficulty=vuln["exploit_difficulty"],
                is_exploitable=True,
                evidence=evidence
            ))
    except Exception as e:
        logger.debug(f"Heartbleed check failed for {host}:{port}: {e}")
    
    return vulnerabilities


def _validate_certificate_chain(
    host: str, 
    port: int, 
    timeout: float = 10.0
) -> CertificateChainInfo:
    """Validate the full certificate chain."""
    chain_info = CertificateChainInfo()
    
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get peer certificate chain
                cert_chain_der = ssock.getpeercert(binary_form=True)
                
                if cert_chain_der:
                    # Parse leaf certificate
                    cert = x509.load_der_x509_certificate(cert_chain_der, default_backend())
                    
                    # Build chain info
                    leaf_cert = parse_certificate(cert_chain_der)
                    leaf_cert.chain_position = 0
                    chain_info.certificates.append(leaf_cert)
                    chain_info.chain_length = 1
                    
                    # Check if self-signed
                    if cert.subject == cert.issuer:
                        chain_info.chain_errors.append("Certificate is self-signed")
                        chain_info.is_complete = True
                        chain_info.root_ca = str(cert.subject)
                    else:
                        # Check issuer against known roots
                        issuer_cn = ""
                        for attr in cert.issuer:
                            if attr.oid._name == "commonName":
                                issuer_cn = attr.value
                                break
                        
                        # Check if issuer is a known trusted root
                        is_trusted = any(ca.lower() in issuer_cn.lower() for ca in TRUSTED_ROOT_CA_NAMES)
                        chain_info.is_trusted = is_trusted
                        chain_info.trust_anchor = issuer_cn if is_trusted else None
                        
                        if not is_trusted:
                            chain_info.chain_errors.append(f"Issuer '{issuer_cn}' not in known trusted roots")
                        else:
                            chain_info.is_complete = True
                            chain_info.root_ca = issuer_cn
                    
                    # Additional chain validation
                    try:
                        # Try to verify with system trust store
                        verify_context = ssl.create_default_context()
                        with socket.create_connection((host, port), timeout=timeout) as vsock:
                            with verify_context.wrap_socket(vsock, server_hostname=host) as vssock:
                                chain_info.is_trusted = True
                                chain_info.is_complete = True
                    except ssl.SSLCertVerificationError as e:
                        chain_info.chain_errors.append(f"Chain verification failed: {str(e)[:100]}")
                        chain_info.is_trusted = False
                    except Exception:
                        pass
                        
    except ImportError:
        chain_info.chain_errors.append("cryptography library not installed")
    except Exception as e:
        chain_info.chain_errors.append(f"Chain validation failed: {str(e)[:100]}")
    
    return chain_info


def scan_ssl_host(host: str, port: int = 443, timeout: float = 10.0, server_name: Optional[str] = None) -> SSLScanResult:
    """
    Scan a single host for SSL/TLS configuration.
    Includes certificate chain validation and vulnerability detection.
    """
    result = SSLScanResult(
        host=host,
        port=port,
        is_ssl=False,
        server_name=server_name or host,
    )
    
    findings: List[SSLFinding] = []
    vulnerabilities: List[VulnerabilityInfo] = []
    
    try:
        # First, try to connect and get basic info
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name or host) as ssock:
                result.is_ssl = True
                result.supports_sni = True
                
                # Get certificate
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    result.certificate = parse_certificate(cert_der)
                    
                    # Check certificate issues
                    if result.certificate.is_expired:
                        findings.append(SSLFinding(
                            category="certificate",
                            severity="critical",
                            title="SSL Certificate Expired",
                            description=f"The SSL certificate expired on {result.certificate.not_after}.",
                            host=host,
                            port=port,
                            evidence=f"Expired: {result.certificate.not_after}",
                            recommendation="Renew the SSL certificate immediately.",
                        ))
                    elif result.certificate.days_until_expiry is not None and result.certificate.days_until_expiry < 30:
                        findings.append(SSLFinding(
                            category="certificate",
                            severity="high" if result.certificate.days_until_expiry < 7 else "medium",
                            title="SSL Certificate Expiring Soon",
                            description=f"The SSL certificate will expire in {result.certificate.days_until_expiry} days.",
                            host=host,
                            port=port,
                            evidence=f"Expires: {result.certificate.not_after}",
                            recommendation="Renew the SSL certificate before it expires.",
                        ))
                    
                    if result.certificate.is_self_signed:
                        findings.append(SSLFinding(
                            category="certificate",
                            severity="medium",
                            title="Self-Signed Certificate",
                            description="The server uses a self-signed certificate.",
                            host=host,
                            port=port,
                            recommendation="Use a certificate from a trusted Certificate Authority.",
                        ))
                    
                    # Check key size
                    if result.certificate.public_key_bits:
                        if result.certificate.public_key_type == "RSA" and result.certificate.public_key_bits < 2048:
                            findings.append(SSLFinding(
                                category="certificate",
                                severity="high",
                                title="Weak RSA Key Size",
                                description=f"The certificate uses a {result.certificate.public_key_bits}-bit RSA key.",
                                host=host,
                                port=port,
                                evidence=f"Key size: {result.certificate.public_key_bits} bits",
                                recommendation="Generate a new certificate with at least 2048-bit RSA key.",
                            ))
                        elif result.certificate.public_key_type == "EC" and result.certificate.public_key_bits < 256:
                            findings.append(SSLFinding(
                                category="certificate",
                                severity="medium",
                                title="Weak EC Key Size",
                                description=f"The certificate uses a {result.certificate.public_key_bits}-bit EC key.",
                                host=host,
                                port=port,
                                evidence=f"Key size: {result.certificate.public_key_bits} bits",
                                recommendation="Use at least P-256 curve for EC keys.",
                            ))
                    
                    # Check signature algorithm
                    if result.certificate.signature_algorithm:
                        sig_alg = result.certificate.signature_algorithm.lower()
                        if "sha1" in sig_alg:
                            findings.append(SSLFinding(
                                category="certificate",
                                severity="medium",
                                title="SHA-1 Signature Algorithm",
                                description="The certificate uses SHA-1 for signing, which is deprecated.",
                                host=host,
                                port=port,
                                evidence=f"Algorithm: {result.certificate.signature_algorithm}",
                                recommendation="Use SHA-256 or stronger for certificate signing.",
                            ))
                        elif "md5" in sig_alg:
                            findings.append(SSLFinding(
                                category="certificate",
                                severity="critical",
                                title="MD5 Signature Algorithm",
                                description="The certificate uses MD5 for signing, which is completely broken.",
                                host=host,
                                port=port,
                                evidence=f"Algorithm: {result.certificate.signature_algorithm}",
                                cve_ids=["CVE-2004-2761"],
                                recommendation="Replace certificate immediately with SHA-256 or stronger.",
                            ))
                
                # Get cipher info
                cipher = ssock.cipher()
                if cipher:
                    result.preferred_cipher = cipher[0]
                    
                    if _is_weak_cipher(cipher[0]):
                        findings.append(SSLFinding(
                            category="cipher",
                            severity="high",
                            title="Weak Cipher Suite in Use",
                            description=f"The server prefers a weak cipher suite: {cipher[0]}",
                            host=host,
                            port=port,
                            evidence=f"Cipher: {cipher[0]}, Protocol: {cipher[1]}, Bits: {cipher[2]}",
                            recommendation="Configure the server to prefer strong cipher suites.",
                        ))
                    
                    # Check for forward secrecy
                    if "DHE" not in cipher[0] and "ECDHE" not in cipher[0]:
                        findings.append(SSLFinding(
                            category="cipher",
                            severity="medium",
                            title="No Forward Secrecy",
                            description=f"The preferred cipher does not provide Perfect Forward Secrecy (PFS).",
                            host=host,
                            port=port,
                            evidence=f"Cipher: {cipher[0]}",
                            recommendation="Prefer cipher suites with ECDHE or DHE key exchange.",
                        ))
                
                # Get protocol version
                protocol = ssock.version()
                result.protocols_supported[protocol] = True
                
                # Check compression
                compression = getattr(ssock, 'compression', lambda: None)()
                result.compression_enabled = compression is not None
                if result.compression_enabled:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="medium",
                        title="TLS Compression Enabled",
                        description="TLS compression is enabled, making the server vulnerable to CRIME/BREACH attacks.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2012-4929"],
                        recommendation="Disable TLS compression.",
                    ))
        
        # Check individual protocol versions
        protocol_checks = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ]
        
        for proto_name, proto_version in protocol_checks:
            try:
                supported, _ = _check_protocol(host, port, proto_version, timeout)
                result.protocols_supported[proto_name] = supported
                
                if supported and proto_name in PROTOCOL_VULNERABILITIES:
                    vuln = PROTOCOL_VULNERABILITIES[proto_name]
                    findings.append(SSLFinding(
                        category="protocol",
                        severity=vuln["severity"],
                        title=f"Deprecated Protocol Supported: {proto_name}",
                        description=vuln["description"],
                        host=host,
                        port=port,
                        cve_ids=vuln["cves"],
                        recommendation=vuln["recommendation"],
                    ))
            except Exception:
                pass
        
        # Get cipher suites
        result.cipher_suites = _get_cipher_suites(host, port, timeout)
        
        # Count weak ciphers
        weak_ciphers = [c for c in result.cipher_suites if c.get("is_weak")]
        if weak_ciphers and len(weak_ciphers) > 1:
            findings.append(SSLFinding(
                category="cipher",
                severity="medium",
                title=f"Multiple Weak Cipher Suites Supported ({len(weak_ciphers)})",
                description=f"The server supports {len(weak_ciphers)} weak cipher suites.",
                host=host,
                port=port,
                evidence=", ".join(c["name"] for c in weak_ciphers[:5]),
                recommendation="Disable weak cipher suites in the server configuration.",
            ))
        
        # Check if TLS 1.2+ is supported
        if not result.protocols_supported.get("TLSv1.2") and not result.protocols_supported.get("TLSv1.3"):
            findings.append(SSLFinding(
                category="protocol",
                severity="high",
                title="No Modern TLS Versions Supported",
                description="The server does not support TLS 1.2 or TLS 1.3.",
                host=host,
                port=port,
                recommendation="Configure the server to support TLS 1.2 and/or TLS 1.3.",
            ))
        
        # Check if TLS 1.3 is not supported (informational)
        if not result.protocols_supported.get("TLSv1.3") and result.protocols_supported.get("TLSv1.2"):
            findings.append(SSLFinding(
                category="protocol",
                severity="low",
                title="TLS 1.3 Not Supported",
                description="The server does not support TLS 1.3.",
                host=host,
                port=port,
                recommendation="Consider enabling TLS 1.3 for improved security.",
            ))
        
        # Validate certificate chain
        result.chain_info = _validate_certificate_chain(host, port, timeout)
        if result.chain_info.chain_errors:
            for error in result.chain_info.chain_errors:
                findings.append(SSLFinding(
                    category="certificate",
                    severity="medium" if "self-signed" in error.lower() else "high",
                    title="Certificate Chain Issue",
                    description=error,
                    host=host,
                    port=port,
                    recommendation="Ensure the full certificate chain is properly configured.",
                ))
        
        # Detect vulnerabilities
        vulnerabilities = _detect_vulnerabilities(
            host, port, 
            result.protocols_supported, 
            result.cipher_suites, 
            timeout
        )
        
        # Add vulnerability findings
        for vuln in vulnerabilities:
            findings.append(SSLFinding(
                category="vulnerability",
                severity=vuln.severity,
                title=f"{vuln.name}",
                description=vuln.description,
                host=host,
                port=port,
                cve_ids=[vuln.cve] if vuln.cve else [],
                evidence=vuln.evidence,
                recommendation=f"Affects: {vuln.affected}. Exploit difficulty: {vuln.exploit_difficulty}",
            ))
        
        result.findings = findings
        result.vulnerabilities = vulnerabilities
        
    except socket.timeout:
        result.error = f"Connection timed out after {timeout} seconds"
    except socket.gaierror as e:
        result.error = f"DNS resolution failed: {e}"
    except ConnectionRefusedError:
        result.error = f"Connection refused on port {port}"
    except ssl.SSLError as e:
        result.error = f"SSL error: {e}"
        findings.append(SSLFinding(
            category="configuration",
            severity="info",
            title="SSL/TLS Not Available",
            description=f"SSL/TLS does not appear to be enabled on port {port}.",
            host=host,
            port=port,
            evidence=str(e),
        ))
        result.findings = findings
    except Exception as e:
        result.error = f"Scan failed: {str(e)}"
        logger.error(f"SSL scan failed for {host}:{port}: {e}")
    
    return result


def scan_multiple_hosts(
    targets: List[Tuple[str, int]],
    timeout: float = 10.0,
    max_workers: int = 10,
) -> SSLScanAnalysisResult:
    """
    Scan multiple hosts for SSL/TLS configuration.
    """
    import uuid
    
    scan_id = str(uuid.uuid4())[:8]
    results: List[SSLScanResult] = []
    all_findings: List[SSLFinding] = []
    all_vulnerabilities: List[VulnerabilityInfo] = []
    
    # Scan in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_ssl_host, host, port, timeout): (host, port)
            for host, port in targets
        }
        
        for future in as_completed(futures):
            host, port = futures[future]
            try:
                result = future.result()
                results.append(result)
                all_findings.extend(result.findings)
                all_vulnerabilities.extend(result.vulnerabilities)
            except Exception as e:
                logger.error(f"Scan failed for {host}:{port}: {e}")
                results.append(SSLScanResult(
                    host=host,
                    port=port,
                    is_ssl=False,
                    error=str(e),
                ))
    
    # Calculate summary
    summary = SSLScanSummary(
        total_hosts=len(targets),
        hosts_scanned=len(results),
        hosts_with_ssl=sum(1 for r in results if r.is_ssl),
        hosts_failed=sum(1 for r in results if r.error and not r.is_ssl),
        critical_findings=sum(1 for f in all_findings if f.severity == "critical"),
        high_findings=sum(1 for f in all_findings if f.severity == "high"),
        medium_findings=sum(1 for f in all_findings if f.severity == "medium"),
        low_findings=sum(1 for f in all_findings if f.severity == "low"),
        certificates_expiring_soon=sum(
            1 for r in results 
            if r.certificate and r.certificate.days_until_expiry is not None 
            and 0 < r.certificate.days_until_expiry < 30
        ),
        certificates_expired=sum(
            1 for r in results if r.certificate and r.certificate.is_expired
        ),
        hosts_with_weak_protocols=sum(
            1 for r in results 
            if any(f.category == "protocol" and f.severity in ["critical", "high"] for f in r.findings)
        ),
        hosts_with_weak_ciphers=sum(
            1 for r in results
            if any(f.category == "cipher" for f in r.findings)
        ),
        total_vulnerabilities=len(all_vulnerabilities),
        critical_vulnerabilities=sum(1 for v in all_vulnerabilities if v.severity == "critical"),
        exploitable_vulnerabilities=sum(1 for v in all_vulnerabilities if v.is_exploitable),
        chain_issues=sum(1 for r in results if r.chain_info and r.chain_info.chain_errors),
        self_signed_certs=sum(1 for r in results if r.certificate and r.certificate.is_self_signed),
    )
    
    return SSLScanAnalysisResult(
        scan_id=scan_id,
        summary=summary,
        results=results,
        all_findings=all_findings,
    )


async def analyze_ssl_with_ai(analysis_result: SSLScanAnalysisResult) -> Dict[str, Any]:
    """
    Use Gemini to provide AI-powered EXPLOITATION analysis of SSL/TLS scan results.
    Focused on offensive security - how to exploit vulnerabilities, not how to fix them.
    """
    if not settings.gemini_api_key:
        return {"error": "AI analysis unavailable: GEMINI_API_KEY not configured"}
    
    try:
        from google import genai
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Collect all vulnerabilities across all hosts
        all_vulns = []
        for r in analysis_result.results:
            for v in r.vulnerabilities:
                all_vulns.append({
                    "host": f"{r.host}:{r.port}",
                    "vuln": v.name,
                    "cve": v.cve,
                    "severity": v.severity,
                    "exploitable": v.is_exploitable,
                    "difficulty": v.exploit_difficulty,
                    "evidence": v.evidence,
                })
        
        # Build summary for AI
        findings_text = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description} (host: {f.host}:{f.port})"
            for f in analysis_result.all_findings[:30]
        )
        
        vulns_text = "\n".join(
            f"- [{v['severity'].upper()}] {v['vuln']} ({v['cve']}) on {v['host']} - Difficulty: {v['difficulty']}"
            for v in all_vulns[:20]
        )
        
        hosts_text = "\n".join(
            f"- {r.host}:{r.port}: SSL={r.is_ssl}, Protocols={list(k for k,v in r.protocols_supported.items() if v)}, "
            f"Cert expires in {r.certificate.days_until_expiry} days, Self-signed={r.certificate.is_self_signed if r.certificate else 'N/A'}"
            for r in analysis_result.results[:20]
            if r.certificate
        )
        
        prompt = f"""You are an OFFENSIVE SECURITY expert specializing in SSL/TLS exploitation.
Your role is to analyze scan results and provide exploitation guidance for penetration testers.

## SCAN DATA

### Summary
- **Hosts Scanned**: {analysis_result.summary.hosts_scanned}
- **Hosts with SSL**: {analysis_result.summary.hosts_with_ssl}
- **Critical Findings**: {analysis_result.summary.critical_findings}
- **High Findings**: {analysis_result.summary.high_findings}
- **Total Vulnerabilities**: {analysis_result.summary.total_vulnerabilities}
- **Exploitable Vulnerabilities**: {analysis_result.summary.exploitable_vulnerabilities}
- **Self-Signed Certs**: {analysis_result.summary.self_signed_certs}
- **Chain Issues**: {analysis_result.summary.chain_issues}

### Scanned Hosts
{hosts_text}

### Detected Vulnerabilities
{vulns_text if vulns_text else "No known vulnerabilities detected."}

### Security Findings
{findings_text if findings_text else "No critical security issues detected."}

---

As a penetration tester, provide an EXPLOITATION-FOCUSED analysis. Focus on HOW TO EXPLOIT, not how to fix.

Respond with a valid JSON object:

{{
  "risk_level": "Critical|High|Medium|Low",
  "risk_score": <0-100>,
  "executive_summary": "<2-3 paragraphs summarizing the attack surface and exploitation potential>",
  "exploitation_scenarios": [
    {{
      "title": "<attack scenario name>",
      "target": "<host:port>",
      "vulnerability": "<CVE or vuln name>",
      "difficulty": "Easy|Medium|Hard|Expert",
      "prerequisites": "<what attacker needs>",
      "attack_steps": [
        "<step 1>",
        "<step 2>",
        "<step 3>"
      ],
      "tools": ["<tool1>", "<tool2>"],
      "expected_outcome": "<what attacker gains>",
      "detection_risk": "Low|Medium|High"
    }}
  ],
  "certificate_attacks": {{
    "summary": "<certificate attack surface analysis>",
    "attacks": [
      {{
        "type": "<attack type: MITM, impersonation, etc>",
        "feasibility": "High|Medium|Low",
        "description": "<how to execute>",
        "target": "<affected host>"
      }}
    ]
  }},
  "protocol_attacks": {{
    "summary": "<protocol weakness analysis>",
    "attacks": [
      {{
        "vulnerability": "<POODLE, BEAST, etc>",
        "target": "<host:port>",
        "exploitation_method": "<how to exploit>",
        "tools_required": ["<tool1>"]
      }}
    ]
  }},
  "recommended_attack_chain": {{
    "description": "<optimal attack sequence>",
    "steps": [
      {{
        "order": 1,
        "action": "<action>",
        "target": "<host>",
        "expected_result": "<result>"
      }}
    ],
    "total_effort": "<estimated time/difficulty>"
  }},
  "quick_wins": [
    {{
      "target": "<host:port>",
      "attack": "<quick attack>",
      "impact": "<what you get>",
      "command": "<example command or tool usage>"
    }}
  ],
  "recommendations": [
    {{
      "priority": "Immediate|High|Medium|Low",
      "action": "<exploitation action to take>",
      "rationale": "<why this is valuable for the attacker>"
    }}
  ]
}}

Return ONLY valid JSON. Focus on OFFENSIVE actions, not defensive fixes."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt
        )
        response_text = response.text.strip()
        
        # Clean up response
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        try:
            report = json.loads(response_text)
            return {"structured_report": report}
        except json.JSONDecodeError as je:
            logger.error(f"Failed to parse AI response as JSON: {je}")
            return {"raw_analysis": response_text, "parse_error": str(je)}
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": f"AI analysis failed: {str(e)}"}
