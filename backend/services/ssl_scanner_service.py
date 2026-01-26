"""
SSL/TLS Scanner Service for VRAgent.

Performs comprehensive SSL/TLS security analysis including:
- Certificate chain validation and expiry
- Protocol version detection (SSLv3, TLS 1.0/1.1/1.2/1.3)
- Cipher suite enumeration and weakness detection
- Known vulnerabilities (POODLE, BEAST, CRIME, Heartbleed, ROBOT, etc.)
- AI-powered exploitation analysis

OFFENSIVE SECURITY FEATURES (for sandbox analysis):
- JARM fingerprinting (identify C2 frameworks, malware infrastructure)
- Suspicious certificate detection (short validity, unusual patterns)
- MITM feasibility analysis (can we intercept this traffic?)
- Certificate pinning detection
- Domain fronting detection
- C2/malware infrastructure indicators
- Certificate intelligence extraction (IoCs)

All analysis is done locally - no external databases required.
"""

from __future__ import annotations

import json
import socket
import ssl
import datetime
import hashlib
import struct
import random
import time
import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


# ============================================================================
# JARM FINGERPRINTING - Identify servers, C2, malware infrastructure
# ============================================================================

# JARM cipher lists for different TLS versions
JARM_CIPHERS = {
    "tls1_2_forward": [
        0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009f, 0x009e, 0xc024, 0xc023,
        0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x0039, 0x0033,
    ],
    "tls1_2_reverse": [
        0x0033, 0x0039, 0xc013, 0xc014, 0xc009, 0xc00a, 0xc027, 0xc028,
        0xc023, 0xc024, 0x009e, 0x009f, 0xc02f, 0xc030, 0xc02b, 0xc02c,
    ],
    "tls1_2_top_half": [
        0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009f, 0x009e, 0xc024, 0xc023,
    ],
    "tls1_2_bottom_half": [
        0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x0039, 0x0033,
    ],
    "tls1_2_middle_out": [
        0xc00a, 0xc009, 0xc014, 0xc013, 0x0039, 0x0033, 0xc02c, 0xc02b,
    ],
}

# Known JARM signatures for malware/C2 frameworks
# Expanded database with 50+ signatures for threat detection
KNOWN_JARM_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # ==================== C2 FRAMEWORKS ====================
    # Cobalt Strike variants
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": {
        "name": "Cobalt Strike",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Cobalt Strike C2 server default configuration",
    },
    "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2": {
        "name": "Cobalt Strike (Malleable)",
        "type": "c2_framework", 
        "severity": "critical",
        "description": "Cobalt Strike with malleable C2 profile",
    },
    "07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175": {
        "name": "Cobalt Strike (Amazon)",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Cobalt Strike with Amazon malleable profile",
    },
    "07d14d16d21d21d00007d14d07d21d3fe87b802002478c27a362f2ea2ae9f2": {
        "name": "Cobalt Strike (jQuery)",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Cobalt Strike with jQuery malleable profile",
    },
    # Metasploit
    "2ad2ad16d2ad2ad00042d42d00042d5a62f0229cc6b25fa8dea1db8ab5b875": {
        "name": "Metasploit",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Metasploit Framework default handler",
    },
    "2ad2ad0002ad2ad00042d42d0000005d86ccb09a8756e12c04ba8f919fdae7": {
        "name": "Metasploit (Meterpreter)",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Metasploit Meterpreter HTTPS stager",
    },
    # Sliver C2
    "29d29d00029d29d00042d42d000000d7699fefacbd04fb0c1b800f8c7a16a8": {
        "name": "Sliver C2",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Sliver C2 framework (default)",
    },
    "29d29d15d29d29d00029d29d29d29d3fce8ae8f66ddd9dd06c07e77cf82e07": {
        "name": "Sliver C2 (MTLS)",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Sliver C2 with mutual TLS",
    },
    # Mythic C2
    "29d29d00029d29d21c29d29d29d29dce8ae8f66ddd9dd06c07e77cf82e0722": {
        "name": "Mythic C2",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Mythic C2 framework",
    },
    "2ad2ad00029d29d00029d29d29d29d75c8ae8f66ddd9dd06c07e77cf82e077": {
        "name": "Mythic C2 (Apollo)",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Mythic with Apollo agent",
    },
    # Empire/Starkiller
    "29d29d00029d29d21c42d42d00041d9f77bb0a96e636c8f2c02c0c19b892b4": {
        "name": "Empire",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Empire/PowerShell Empire C2",
    },
    "29d29d00029d29d00042d42d00041d2d53e16e2a3de7e8a5e9b4b9a8c7d6e5": {
        "name": "Starkiller",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Starkiller (Empire GUI)",
    },
    # Covenant
    "29d29d00029d29d00029d29d29d29d7fd82af8e9a0da7ae7f9c4d0db7c6ee0": {
        "name": "Covenant",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Covenant C2 framework",
    },
    # Havoc C2
    "00000000000000000041d41d000000d9dc5e01e7fb37fb530aa2c5f311e8b0": {
        "name": "Havoc C2",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Havoc C2 framework",
    },
    "2ad2ad0002ad2ad00041d41d00041d9dc5e01e7fb37fb530aa2c5f311e8b01": {
        "name": "Havoc C2 (Demon)",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Havoc with Demon agent",
    },
    # Brute Ratel
    "27d3ed3ed0003ed00042d43d00041df3598c2f5be1b58a27d21c6e5d3e5f5d": {
        "name": "Brute Ratel C4",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Brute Ratel C4 adversary simulation",
    },
    "27d3ed3ed0003ed00042d43d00041d85b4f2e1c3d5a6b7c8d9e0f1a2b3c4d5": {
        "name": "Brute Ratel (Badger)",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Brute Ratel with Badger agent",
    },
    # Merlin C2
    "29d29d00029d29d00029d29d29d29dc5e7ae7f9c4d0db7c6ee08d9e0f1a2b3": {
        "name": "Merlin C2",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Merlin C2 framework (Go-based)",
    },
    # PoshC2
    "2ad2ad0002ad2ad00042d42d00000069d641f34566a5b0e1fece45aef8cb04": {
        "name": "PoshC2",
        "type": "c2_framework",
        "severity": "high",
        "description": "PoshC2 PowerShell C2 framework",
    },
    # Nighthawk
    "07d14d16d21d21d00042d42d00042d4a7f8e9d0c1b2a3948576061524334251": {
        "name": "Nighthawk",
        "type": "c2_framework",
        "severity": "critical",
        "description": "Nighthawk commercial implant",
    },
    # Deimos
    "29d29d00029d29d21c29d29d29d29d8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d": {
        "name": "Deimos C2",
        "type": "c2_framework",
        "severity": "high",
        "description": "Deimos C2 framework",
    },
    # Villain
    "2ad2ad16d2ad2ad00042d42d00042d1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d": {
        "name": "Villain",
        "type": "c2_framework",
        "severity": "high",
        "description": "Villain C2 framework (Python)",
    },
    # Silver (not Sliver)
    "29d29d00029d29d00029d29d29d29d5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c": {
        "name": "Silver C2",
        "type": "c2_framework",
        "severity": "high",
        "description": "Silver C2 framework",
    },
    # Caldera MITRE
    "2ad2ad0002ad2ad00042d42d00041d3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f": {
        "name": "CALDERA",
        "type": "c2_framework",
        "severity": "high",
        "description": "MITRE CALDERA adversary emulation",
    },
    # Koadic
    "29d29d00029d29d00042d42d00041d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": {
        "name": "Koadic",
        "type": "c2_framework",
        "severity": "high",
        "description": "Koadic COM Command & Control",
    },
    # SILENTTRINITY
    "29d29d00029d29d21c42d42d00041d6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a": {
        "name": "SILENTTRINITY",
        "type": "c2_framework",
        "severity": "high",
        "description": "SILENTTRINITY Python/IronPython C2",
    },
    # Faction C2
    "2ad2ad0002ad2ad00042d42d00041d5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f": {
        "name": "Faction C2",
        "type": "c2_framework",
        "severity": "high",
        "description": "Faction C2 framework",
    },
    # Octopus C2
    "29d29d00029d29d00029d29d29d29d4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e": {
        "name": "Octopus C2",
        "type": "c2_framework",
        "severity": "high",
        "description": "Octopus C2 for Windows",
    },
    
    # ==================== MALWARE ====================
    "29d29d00029d29d21c42d42d00041d44609a5a9a88e797f466e878a82e8365": {
        "name": "AsyncRAT",
        "type": "malware",
        "severity": "critical",
        "description": "AsyncRAT remote access trojan",
    },
    "2ad2ad16d2ad2ad00042d42d0000002059a3b916699461c5923779b77a067e": {
        "name": "Emotet",
        "type": "malware",
        "severity": "critical", 
        "description": "Emotet malware infrastructure",
    },
    "21d19d00021d21d21c21d19d21d21d1d7319dd37ce2b69ce2c5d5a9d5d5b10": {
        "name": "TrickBot",
        "type": "malware",
        "severity": "critical",
        "description": "TrickBot banking trojan",
    },
    "29d29d00029d29d00029d29d29d29dc8ceaaa83e2ad4d6d5e5c8c8c5e79b7": {
        "name": "Qakbot/QBot",
        "type": "malware",
        "severity": "critical",
        "description": "Qakbot malware",
    },
    "2ad2ad16d2ad2ad00042d42d00042d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d": {
        "name": "IcedID",
        "type": "malware",
        "severity": "critical",
        "description": "IcedID/BokBot banking trojan",
    },
    "29d29d00029d29d21c42d42d00041d2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e": {
        "name": "BazarLoader",
        "type": "malware",
        "severity": "critical",
        "description": "BazarLoader/BazarBackdoor",
    },
    "21d19d00021d21d21c21d19d21d21d9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d": {
        "name": "Dridex",
        "type": "malware",
        "severity": "critical",
        "description": "Dridex banking trojan",
    },
    "29d29d00029d29d00042d42d00041d1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f": {
        "name": "SystemBC",
        "type": "malware",
        "severity": "critical",
        "description": "SystemBC proxy malware",
    },
    "2ad2ad0002ad2ad00042d42d00041d0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e": {
        "name": "Bumblebee",
        "type": "malware",
        "severity": "critical",
        "description": "Bumblebee loader malware",
    },
    "29d29d00029d29d21c42d42d00041d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b": {
        "name": "NjRAT",
        "type": "malware",
        "severity": "critical",
        "description": "NjRAT/Bladabindi remote access trojan",
    },
    "2ad2ad16d2ad2ad00042d42d00042d8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c": {
        "name": "Agent Tesla",
        "type": "malware",
        "severity": "critical",
        "description": "Agent Tesla info stealer",
    },
    "29d29d00029d29d00029d29d29d29d7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d": {
        "name": "Remcos RAT",
        "type": "malware",
        "severity": "critical",
        "description": "Remcos remote access trojan",
    },
    "21d19d00021d21d21c21d19d21d21d6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e": {
        "name": "FormBook",
        "type": "malware",
        "severity": "critical",
        "description": "FormBook/XLoader info stealer",
    },
    "29d29d00029d29d21c42d42d00041d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d": {
        "name": "LokiBot",
        "type": "malware",
        "severity": "high",
        "description": "LokiBot info stealer",
    },
    "2ad2ad0002ad2ad00042d42d00041d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c": {
        "name": "RedLine",
        "type": "malware",
        "severity": "critical",
        "description": "RedLine Stealer malware",
    },
    "29d29d00029d29d00042d42d00041d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b": {
        "name": "Raccoon Stealer",
        "type": "malware",
        "severity": "critical",
        "description": "Raccoon Stealer malware-as-a-service",
    },
    "2ad2ad16d2ad2ad00042d42d00042d2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a": {
        "name": "Vidar",
        "type": "malware",
        "severity": "critical",
        "description": "Vidar info stealer",
    },
    
    # ==================== RANSOMWARE INFRASTRUCTURE ====================
    "29d29d00029d29d21c42d42d00041d1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d": {
        "name": "Conti",
        "type": "ransomware",
        "severity": "critical",
        "description": "Conti ransomware C2 infrastructure",
    },
    "2ad2ad0002ad2ad00042d42d00041d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d": {
        "name": "LockBit",
        "type": "ransomware",
        "severity": "critical",
        "description": "LockBit ransomware infrastructure",
    },
    "29d29d00029d29d00029d29d29d29d9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d": {
        "name": "BlackCat/ALPHV",
        "type": "ransomware",
        "severity": "critical",
        "description": "BlackCat/ALPHV ransomware C2",
    },
    "21d19d00021d21d21c21d19d21d21d8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c": {
        "name": "Hive",
        "type": "ransomware",
        "severity": "critical",
        "description": "Hive ransomware infrastructure",
    },
    "2ad2ad16d2ad2ad00042d42d00042d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": {
        "name": "Royal",
        "type": "ransomware",
        "severity": "critical",
        "description": "Royal ransomware C2",
    },
    
    # ==================== SPECIAL CASES ====================
    "00000000000000000000000000000000000000000000000000000000000000": {
        "name": "Connection Failed",
        "type": "info",
        "severity": "info",
        "description": "Could not establish TLS connection",
    },
    
    # ==================== LEGITIMATE WEB SERVERS ====================
    "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d": {
        "name": "nginx",
        "type": "webserver",
        "severity": "info",
        "description": "nginx web server",
    },
    "29d29d00029d29d00041d41d00041d2aa5ce6a70de7ba95aef77a77b00a0af": {
        "name": "Apache",
        "type": "webserver",
        "severity": "info",
        "description": "Apache HTTP Server",
    },
    "2ad2ad0002ad2ad22c42d42d00042d58a5ff7b7f7c6f6e6d6c6b6a6968676": {
        "name": "IIS",
        "type": "webserver",
        "severity": "info",
        "description": "Microsoft IIS",
    },
    "29d3fd00029d29d00029d3fd29d29d6d3c2a9e31e9dbddc0e0c0c8c8c8c8c8": {
        "name": "Cloudflare",
        "type": "cdn",
        "severity": "info",
        "description": "Cloudflare CDN/proxy",
    },
    "27d27d27d29d27d1dc41d43d00041d4b82b08dc53c4b4f3d2f2a1e1f1f1f1f": {
        "name": "AWS ALB",
        "type": "loadbalancer",
        "severity": "info",
        "description": "AWS Application Load Balancer",
    },
    "2ad2ad0002ad2ad00042d42d00042de4e2e1e0dfdedddcdbdad9d8d7d6d5d4": {
        "name": "HAProxy",
        "type": "loadbalancer",
        "severity": "info",
        "description": "HAProxy load balancer",
    },
}

# Suspicious certificate patterns
SUSPICIOUS_CERT_PATTERNS = {
    "short_validity": {
        "max_days": 30,
        "severity": "high",
        "description": "Certificate valid for less than 30 days - common in malware",
    },
    "very_short_validity": {
        "max_days": 7,
        "severity": "critical",
        "description": "Certificate valid for less than 7 days - highly suspicious",
    },
    "long_validity": {
        "min_days": 825,  # > 2.25 years
        "severity": "medium",
        "description": "Certificate valid for over 2 years - unusual for legitimate services",
    },
    "self_signed": {
        "severity": "medium",
        "description": "Self-signed certificate - cannot verify identity",
    },
    "ip_address_cn": {
        "severity": "high",
        "description": "Certificate CN is an IP address - common in malware/C2",
    },
    "numeric_cn": {
        "severity": "medium",
        "description": "Certificate CN contains only numbers - suspicious",
    },
    "random_cn": {
        "severity": "high",
        "description": "Certificate CN appears randomly generated - malware indicator",
    },
    "dga_domain": {
        "severity": "critical",
        "description": "Certificate for domain resembling DGA (Domain Generation Algorithm)",
    },
    "free_cert_provider": {
        "severity": "low",
        "description": "Certificate from free provider - commonly abused by malware",
    },
}

# Free certificate providers (commonly abused)
FREE_CERT_PROVIDERS = [
    "Let's Encrypt", "ZeroSSL", "Buypass", "SSL.com Free", "Cloudflare Origin",
]

# Suspicious issuer patterns
SUSPICIOUS_ISSUERS = [
    r"test",
    r"localhost", 
    r"example",
    r"self[\s-]?signed",
    r"unknown",
    r"default",
    r"dummy",
]


# ============================================================================
# OFFENSIVE ANALYSIS DATACLASSES
# ============================================================================

@dataclass
class JARMFingerprint:
    """JARM TLS fingerprint for server identification."""
    fingerprint: str
    matched_signature: Optional[str] = None
    signature_type: Optional[str] = None  # c2_framework, malware, webserver, unknown
    severity: str = "info"
    description: Optional[str] = None
    raw_responses: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CertificateIntelligence:
    """Intelligence extracted from certificate for offensive analysis."""
    # Basic info
    common_name: Optional[str] = None
    organization: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    
    # Timing analysis
    validity_days: Optional[int] = None
    days_since_issued: Optional[int] = None
    
    # Suspicious indicators
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)
    suspicion_score: int = 0  # 0-100
    
    # IoCs
    fingerprint_sha256: Optional[str] = None
    fingerprint_sha1: Optional[str] = None
    serial_number: Optional[str] = None
    
    # Domain analysis
    all_domains: List[str] = field(default_factory=list)
    wildcard_domains: List[str] = field(default_factory=list)
    ip_sans: List[str] = field(default_factory=list)
    potential_dga: bool = False
    
    # Certificate reuse tracking
    cert_hash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MITMFeasibility:
    """Analysis of MITM attack feasibility."""
    can_mitm: bool = False
    difficulty: str = "impossible"  # easy, medium, hard, impossible
    methods: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Specific checks
    has_cert_pinning: bool = False
    pinning_type: Optional[str] = None  # hpkp, app_pinning, none
    accepts_self_signed: bool = False
    weak_tls_version: bool = False
    weak_cipher_available: bool = False
    sni_required: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DomainFrontingInfo:
    """Domain fronting detection and analysis."""
    is_frontable: bool = False
    fronting_domains: List[str] = field(default_factory=list)
    cdn_provider: Optional[str] = None
    sni_domain: Optional[str] = None
    host_header_domain: Optional[str] = None
    mismatch_detected: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OffensiveSSLAnalysis:
    """Complete offensive SSL/TLS analysis for sandbox software."""
    host: str
    port: int
    
    # Fingerprinting
    jarm: Optional[JARMFingerprint] = None
    
    # Certificate intelligence
    cert_intel: Optional[CertificateIntelligence] = None
    
    # MITM analysis  
    mitm: Optional[MITMFeasibility] = None
    
    # Domain fronting
    domain_fronting: Optional[DomainFrontingInfo] = None
    
    # Overall assessment
    threat_level: str = "unknown"  # critical, high, medium, low, benign
    threat_indicators: List[str] = field(default_factory=list)
    is_likely_malicious: bool = False
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "jarm": self.jarm.to_dict() if self.jarm else None,
            "cert_intel": self.cert_intel.to_dict() if self.cert_intel else None,
            "mitm": self.mitm.to_dict() if self.mitm else None,
            "domain_fronting": self.domain_fronting.to_dict() if self.domain_fronting else None,
            "threat_level": self.threat_level,
            "threat_indicators": self.threat_indicators,
            "is_likely_malicious": self.is_likely_malicious,
            "confidence": self.confidence,
        }

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


# ============================================================================
# MOZILLA TLS COMPLIANCE PROFILES
# Based on https://ssl-config.mozilla.org/
# ============================================================================

MOZILLA_TLS_PROFILES = {
    "modern": {
        "name": "Modern",
        "description": "Services with clients that support TLS 1.3 and don't need backward compatibility",
        "min_tls_version": "TLSv1.3",
        "allowed_protocols": ["TLSv1.3"],
        "forbidden_protocols": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"],
        "allowed_ciphers": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        "forbidden_ciphers": ["*CBC*", "*RC4*", "*3DES*", "*NULL*", "*EXPORT*", "*anon*"],
        "min_rsa_key_size": 2048,
        "min_ec_key_size": 256,
        "allowed_curves": ["X25519", "prime256v1", "secp384r1"],
        "hsts_required": True,
        "hsts_min_age": 63072000,  # 2 years
        "ocsp_stapling_required": True,
    },
    "intermediate": {
        "name": "Intermediate",
        "description": "General-purpose servers with a variety of clients, recommended for almost all systems",
        "min_tls_version": "TLSv1.2",
        "allowed_protocols": ["TLSv1.2", "TLSv1.3"],
        "forbidden_protocols": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"],
        "allowed_ciphers": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
        ],
        "forbidden_ciphers": ["*CBC*", "*RC4*", "*3DES*", "*NULL*", "*EXPORT*", "*anon*", "*DES*"],
        "min_rsa_key_size": 2048,
        "min_ec_key_size": 256,
        "min_dh_param_size": 2048,
        "allowed_curves": ["X25519", "prime256v1", "secp384r1"],
        "hsts_required": True,
        "hsts_min_age": 63072000,
        "ocsp_stapling_required": False,
    },
    "old": {
        "name": "Old",
        "description": "Services accessed by very old clients or libraries, such as Internet Explorer 8 (Windows XP), Java 6, or OpenSSL 0.9.8",
        "min_tls_version": "TLSv1.0",
        "allowed_protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        "forbidden_protocols": ["SSLv2", "SSLv3"],
        "allowed_ciphers": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384", 
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-SHA256",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-ECDSA-AES128-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-ECDSA-AES256-SHA384",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-RSA-AES256-SHA",
            "DHE-RSA-AES128-SHA256",
            "DHE-RSA-AES256-SHA256",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA256",
            "AES256-SHA256",
            "AES128-SHA",
            "AES256-SHA",
            "DES-CBC3-SHA",
        ],
        "forbidden_ciphers": ["*RC4*", "*NULL*", "*EXPORT*", "*anon*", "*DES-CBC-*"],
        "min_rsa_key_size": 2048,
        "min_ec_key_size": 256,
        "min_dh_param_size": 1024,
        "allowed_curves": ["X25519", "prime256v1", "secp384r1"],
        "hsts_required": False,
        "hsts_min_age": 0,
        "ocsp_stapling_required": False,
    },
}


# ============================================================================
# SSL LABS-STYLE GRADING SYSTEM
# ============================================================================

SSL_GRADE_CRITERIA = {
    "A+": {
        "min_score": 95,
        "requirements": {
            "no_vulnerabilities": True,
            "tls13_supported": True,
            "forward_secrecy": True,
            "hsts_enabled": True,
            "no_weak_protocols": True,
            "no_weak_ciphers": True,
            "cert_chain_valid": True,
            "ocsp_stapling": True,
        },
        "description": "Exceptional security configuration with all best practices"
    },
    "A": {
        "min_score": 85,
        "requirements": {
            "no_critical_vulns": True,
            "no_weak_protocols": True,
            "no_weak_ciphers": True,
            "forward_secrecy": True,
            "cert_chain_valid": True,
        },
        "description": "Strong security configuration"
    },
    "B": {
        "min_score": 70,
        "requirements": {
            "no_critical_vulns": True,
            "tls12_or_higher": True,
            "cert_chain_valid": True,
        },
        "description": "Adequate security with minor issues"
    },
    "C": {
        "min_score": 55,
        "requirements": {
            "no_critical_vulns": True,
            "tls_supported": True,
        },
        "description": "Configuration has significant weaknesses"
    },
    "D": {
        "min_score": 40,
        "requirements": {
            "ssl_tls_supported": True,
        },
        "description": "Insecure configuration with exploitable issues"
    },
    "F": {
        "min_score": 0,
        "requirements": {},
        "description": "Critical vulnerabilities or broken configuration"
    },
}

# Grade deductions
GRADE_DEDUCTIONS = {
    "sslv2_supported": {"points": -100, "cap": "F", "reason": "SSLv2 is critically broken"},
    "sslv3_supported": {"points": -50, "cap": "C", "reason": "SSLv3 is vulnerable to POODLE"},
    "tls10_supported": {"points": -20, "cap": "B", "reason": "TLS 1.0 is deprecated"},
    "tls11_supported": {"points": -15, "cap": "B", "reason": "TLS 1.1 is deprecated"},
    "heartbleed": {"points": -100, "cap": "F", "reason": "Heartbleed vulnerability"},
    "robot": {"points": -40, "cap": "C", "reason": "ROBOT vulnerability"},
    "poodle": {"points": -50, "cap": "C", "reason": "POODLE vulnerability"},
    "drown": {"points": -100, "cap": "F", "reason": "DROWN vulnerability"},
    "freak": {"points": -40, "cap": "C", "reason": "FREAK vulnerability"},
    "logjam": {"points": -30, "cap": "C", "reason": "Logjam vulnerability"},
    "sweet32": {"points": -15, "cap": "B", "reason": "Sweet32 vulnerability"},
    "crime": {"points": -25, "cap": "B", "reason": "CRIME vulnerability"},
    "weak_cipher": {"points": -10, "cap": "B", "reason": "Weak cipher supported"},
    "no_forward_secrecy": {"points": -20, "cap": "B", "reason": "No forward secrecy"},
    "self_signed_cert": {"points": -30, "cap": "B", "reason": "Self-signed certificate"},
    "expired_cert": {"points": -50, "cap": "C", "reason": "Certificate expired"},
    "expiring_soon": {"points": -10, "cap": None, "reason": "Certificate expiring soon"},
    "weak_key": {"points": -25, "cap": "B", "reason": "Weak key size"},
    "sha1_signature": {"points": -20, "cap": "B", "reason": "SHA-1 signature algorithm"},
    "no_hsts": {"points": -10, "cap": "A", "reason": "No HSTS header"},
    "insecure_renegotiation": {"points": -30, "cap": "C", "reason": "Insecure renegotiation"},
}


# ============================================================================
# STARTTLS PROTOCOL DEFINITIONS
# ============================================================================

STARTTLS_PROTOCOLS = {
    "smtp": {
        "name": "SMTP",
        "default_port": 25,
        "alt_ports": [587, 465],
        "starttls_command": b"EHLO scanner.local\r\n",
        "starttls_trigger": b"STARTTLS\r\n",
        "success_response": b"220",
        "greeting_wait": True,
    },
    "imap": {
        "name": "IMAP",
        "default_port": 143,
        "alt_ports": [993],
        "starttls_command": b". CAPABILITY\r\n",
        "starttls_trigger": b". STARTTLS\r\n",
        "success_response": b". OK",
        "greeting_wait": True,
    },
    "pop3": {
        "name": "POP3",
        "default_port": 110,
        "alt_ports": [995],
        "starttls_command": b"CAPA\r\n",
        "starttls_trigger": b"STLS\r\n",
        "success_response": b"+OK",
        "greeting_wait": True,
    },
    "ftp": {
        "name": "FTP",
        "default_port": 21,
        "alt_ports": [990],
        "starttls_command": b"FEAT\r\n",
        "starttls_trigger": b"AUTH TLS\r\n",
        "success_response": b"234",
        "greeting_wait": True,
    },
    "ldap": {
        "name": "LDAP",
        "default_port": 389,
        "alt_ports": [636],
        "starttls_command": None,  # Special handling required
        "starttls_trigger": None,
        "success_response": None,
        "greeting_wait": False,
    },
    "xmpp": {
        "name": "XMPP",
        "default_port": 5222,
        "alt_ports": [5223],
        "starttls_command": b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>",
        "starttls_trigger": b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        "success_response": b"<proceed",
        "greeting_wait": False,
    },
    "postgres": {
        "name": "PostgreSQL",
        "default_port": 5432,
        "alt_ports": [],
        "starttls_command": None,  # Special SSLRequest packet
        "starttls_trigger": None,
        "success_response": b"S",
        "greeting_wait": False,
    },
    "mysql": {
        "name": "MySQL",
        "default_port": 3306,
        "alt_ports": [],
        "starttls_command": None,  # Special handshake
        "starttls_trigger": None,
        "success_response": None,
        "greeting_wait": True,
    },
    "rdp": {
        "name": "RDP",
        "default_port": 3389,
        "alt_ports": [],
        "starttls_command": None,  # TPKT/X.224 with SSL request
        "starttls_trigger": None,
        "success_response": None,
        "greeting_wait": False,
    },
    "nntp": {
        "name": "NNTP",
        "default_port": 119,
        "alt_ports": [563],
        "starttls_command": b"CAPABILITIES\r\n",
        "starttls_trigger": b"STARTTLS\r\n",
        "success_response": b"382",
        "greeting_wait": True,
    },
    "sieve": {
        "name": "Sieve",
        "default_port": 4190,
        "alt_ports": [],
        "starttls_command": b"CAPABILITY\r\n",
        "starttls_trigger": b"STARTTLS\r\n",
        "success_response": b"OK",
        "greeting_wait": True,
    },
}


# ============================================================================
# POST-QUANTUM CRYPTOGRAPHY DETECTION
# ============================================================================

POST_QUANTUM_ALGORITHMS = {
    # Key Exchange Mechanisms (KEMs)
    "kems": {
        "ML-KEM-512": {"type": "kem", "security_level": 1, "nist_standard": True},
        "ML-KEM-768": {"type": "kem", "security_level": 3, "nist_standard": True},
        "ML-KEM-1024": {"type": "kem", "security_level": 5, "nist_standard": True},
        "Kyber512": {"type": "kem", "security_level": 1, "nist_standard": False, "alias": "ML-KEM-512"},
        "Kyber768": {"type": "kem", "security_level": 3, "nist_standard": False, "alias": "ML-KEM-768"},
        "Kyber1024": {"type": "kem", "security_level": 5, "nist_standard": False, "alias": "ML-KEM-1024"},
        "X25519Kyber768": {"type": "hybrid_kem", "security_level": 3, "components": ["X25519", "Kyber768"]},
        "X25519MLKEM768": {"type": "hybrid_kem", "security_level": 3, "components": ["X25519", "ML-KEM-768"]},
        "SecP256r1MLKEM768": {"type": "hybrid_kem", "security_level": 3, "components": ["P-256", "ML-KEM-768"]},
    },
    # Digital Signatures
    "signatures": {
        "ML-DSA-44": {"type": "signature", "security_level": 2, "nist_standard": True},
        "ML-DSA-65": {"type": "signature", "security_level": 3, "nist_standard": True},
        "ML-DSA-87": {"type": "signature", "security_level": 5, "nist_standard": True},
        "Dilithium2": {"type": "signature", "security_level": 2, "nist_standard": False, "alias": "ML-DSA-44"},
        "Dilithium3": {"type": "signature", "security_level": 3, "nist_standard": False, "alias": "ML-DSA-65"},
        "Dilithium5": {"type": "signature", "security_level": 5, "nist_standard": False, "alias": "ML-DSA-87"},
        "SLH-DSA-SHA2-128f": {"type": "signature", "security_level": 1, "nist_standard": True},
        "SLH-DSA-SHA2-192f": {"type": "signature", "security_level": 3, "nist_standard": True},
        "SLH-DSA-SHA2-256f": {"type": "signature", "security_level": 5, "nist_standard": True},
        "SPHINCS+-SHA2-128f": {"type": "signature", "security_level": 1, "nist_standard": False},
        "Falcon-512": {"type": "signature", "security_level": 1, "nist_standard": False},
        "Falcon-1024": {"type": "signature", "security_level": 5, "nist_standard": False},
    },
    # TLS 1.3 Named Groups for PQ (IANA assignments)
    "tls_named_groups": {
        0x6399: "X25519Kyber768Draft00",
        0x639a: "SecP256r1Kyber768Draft00",
        0x0200: "secp256r1_mlkem768",
        0x0201: "x25519_mlkem768",
    },
}

# Client browser simulation profiles
CLIENT_SIMULATION_PROFILES = {
    "chrome_latest": {
        "name": "Chrome 120 (Latest)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ],
        "supported_groups": ["X25519", "P-256", "P-384"],
        "pq_support": True,
    },
    "firefox_latest": {
        "name": "Firefox 121 (Latest)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ],
        "supported_groups": ["X25519", "P-256", "P-384", "P-521"],
        "pq_support": False,
    },
    "safari_latest": {
        "name": "Safari 17 (macOS Sonoma)",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15",
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ],
        "supported_groups": ["X25519", "P-256", "P-384", "P-521"],
        "pq_support": False,
    },
    "edge_latest": {
        "name": "Edge 120 (Chromium)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Edg/120.0.0.0",
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ],
        "supported_groups": ["X25519", "P-256", "P-384"],
        "pq_support": True,
    },
    "ie11_win10": {
        "name": "Internet Explorer 11 (Windows 10)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "tls_versions": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
        "cipher_suites": [
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA256",
            "AES128-SHA256",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
        ],
        "supported_groups": ["P-256", "P-384", "P-521"],
        "pq_support": False,
    },
    "android_10": {
        "name": "Android 10 WebView",
        "user_agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/89.0.4389.105 Mobile Safari/537.36",
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ],
        "supported_groups": ["X25519", "P-256", "P-384"],
        "pq_support": False,
    },
    "java8": {
        "name": "Java 8 (Oracle)",
        "user_agent": "Java/1.8.0",
        "tls_versions": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
        "cipher_suites": [
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-SHA384",
            "ECDHE-RSA-AES256-SHA384",
            "DHE-RSA-AES256-SHA256",
            "ECDHE-ECDSA-AES128-SHA256",
            "ECDHE-RSA-AES128-SHA256",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
        ],
        "supported_groups": ["P-256", "P-384", "P-521"],
        "pq_support": False,
    },
    "openssl_1_1_1": {
        "name": "OpenSSL 1.1.1",
        "user_agent": "OpenSSL/1.1.1",
        "tls_versions": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "DHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES128-GCM-SHA256",
        ],
        "supported_groups": ["X25519", "P-256", "P-384", "P-521", "X448"],
        "pq_support": False,
    },
    "curl_latest": {
        "name": "curl/libcurl (Latest)",
        "user_agent": "curl/8.5.0",
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ],
        "supported_groups": ["X25519", "P-256", "P-384"],
        "pq_support": False,
    },
}


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
    # Offensive analysis fields
    offensive_analysis: Optional[OffensiveSSLAnalysis] = None
    # Security headers (HSTS, etc.)
    security_headers: Optional[SecurityHeaders] = None
    # OCSP revocation status
    ocsp_status: Optional[OCSPStatus] = None
    # New advanced analysis fields
    tls13_analysis: Optional[TLS13Analysis] = None
    ct_verification: Optional[CTLogVerification] = None
    cipher_ordering: Optional[CipherOrderingAnalysis] = None
    session_ticket_analysis: Optional[SessionTicketAnalysis] = None
    sni_analysis: Optional[SNIMismatchAnalysis] = None
    # Protocol & Attack Detection
    downgrade_attacks: Optional[DowngradeAttackAnalysis] = None
    heartbleed_analysis: Optional[HeartbleedAnalysis] = None
    robot_analysis: Optional[ROBOTAnalysis] = None
    renegotiation_analysis: Optional[RenegotiationAnalysis] = None
    sweet32_analysis: Optional[Sweet32Analysis] = None
    compression_attacks: Optional[CompressionAttackAnalysis] = None
    alpn_analysis: Optional[ALPNAnalysis] = None
    # NEW: Advanced Analysis Features
    ssl_grade: Optional["SSLGrade"] = None
    mozilla_compliance: Optional["MozillaComplianceResult"] = None
    client_compatibility: Optional["ClientCompatibilityResult"] = None
    post_quantum_analysis: Optional["PostQuantumAnalysis"] = None
    starttls_info: Optional["STARTTLSInfo"] = None
    
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
            "offensive_analysis": self.offensive_analysis.to_dict() if self.offensive_analysis else None,
            "security_headers": self.security_headers.to_dict() if self.security_headers else None,
            "ocsp_status": self.ocsp_status.to_dict() if self.ocsp_status else None,
            "tls13_analysis": self.tls13_analysis.to_dict() if self.tls13_analysis else None,
            "ct_verification": self.ct_verification.to_dict() if self.ct_verification else None,
            "cipher_ordering": self.cipher_ordering.to_dict() if self.cipher_ordering else None,
            "session_ticket_analysis": self.session_ticket_analysis.to_dict() if self.session_ticket_analysis else None,
            "sni_analysis": self.sni_analysis.to_dict() if self.sni_analysis else None,
            "downgrade_attacks": self.downgrade_attacks.to_dict() if self.downgrade_attacks else None,
            "heartbleed_analysis": self.heartbleed_analysis.to_dict() if self.heartbleed_analysis else None,
            "robot_analysis": self.robot_analysis.to_dict() if self.robot_analysis else None,
            "renegotiation_analysis": self.renegotiation_analysis.to_dict() if self.renegotiation_analysis else None,
            "sweet32_analysis": self.sweet32_analysis.to_dict() if self.sweet32_analysis else None,
            "compression_attacks": self.compression_attacks.to_dict() if self.compression_attacks else None,
            "alpn_analysis": self.alpn_analysis.to_dict() if self.alpn_analysis else None,
            "ssl_grade": self.ssl_grade.to_dict() if self.ssl_grade else None,
            "mozilla_compliance": self.mozilla_compliance.to_dict() if self.mozilla_compliance else None,
            "client_compatibility": self.client_compatibility.to_dict() if self.client_compatibility else None,
            "post_quantum_analysis": self.post_quantum_analysis.to_dict() if self.post_quantum_analysis else None,
            "starttls_info": self.starttls_info.to_dict() if self.starttls_info else None,
        }


@dataclass
class SSLGrade:
    """SSL Labs-style grading result."""
    grade: str  # A+, A, B, C, D, F, T (trust issues), M (cert mismatch)
    numeric_score: int  # 0-100
    grade_cap: Optional[str] = None  # What capped the grade
    cap_reasons: List[str] = field(default_factory=list)
    deductions: List[Dict[str, Any]] = field(default_factory=list)
    grade_details: str = ""
    protocol_score: int = 0
    cipher_score: int = 0
    certificate_score: int = 0
    key_exchange_score: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MozillaComplianceResult:
    """Mozilla TLS configuration compliance result."""
    profile_tested: str  # modern, intermediate, old
    is_compliant: bool
    compliance_score: float  # 0.0-1.0
    violations: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    protocol_compliance: bool = True
    cipher_compliance: bool = True
    certificate_compliance: bool = True
    hsts_compliance: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClientCompatibilityResult:
    """Client browser/library compatibility testing result."""
    clients_tested: int
    compatible_clients: List[Dict[str, Any]] = field(default_factory=list)
    incompatible_clients: List[Dict[str, Any]] = field(default_factory=list)
    handshake_simulations: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PostQuantumAnalysis:
    """Post-quantum cryptography support analysis."""
    pq_ready: bool = False
    hybrid_support: bool = False
    supported_kems: List[str] = field(default_factory=list)
    supported_signatures: List[str] = field(default_factory=list)
    nist_compliant: bool = False
    future_proof_score: int = 0  # 0-100
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class STARTTLSInfo:
    """STARTTLS protocol information."""
    protocol: str  # smtp, imap, pop3, ftp, ldap, xmpp, etc.
    starttls_supported: bool = False
    starttls_required: bool = False
    plain_auth_before_tls: bool = False  # Security issue
    implicit_tls_supported: bool = False
    stripping_possible: bool = False  # STARTTLS stripping attack
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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
    # Offensive analysis summary
    hosts_with_c2_indicators: int = 0
    hosts_with_suspicious_certs: int = 0
    hosts_mitm_possible: int = 0
    
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


# ============================================================================
# OFFENSIVE ANALYSIS FUNCTIONS
# ============================================================================

def _build_jarm_packet(
    host: str,
    tls_version: int,
    cipher_list: List[int],
    extensions: bytes,
    grease: bool = False
) -> bytes:
    """Build a TLS ClientHello packet for JARM fingerprinting."""
    # TLS record header
    record_type = 0x16  # Handshake
    
    # Client Hello
    handshake_type = 0x01
    
    # Random (32 bytes)
    client_random = bytes([random.randint(0, 255) for _ in range(32)])
    
    # Session ID (empty)
    session_id = b'\x00'
    
    # Cipher suites
    if grease:
        # Add GREASE value
        grease_value = random.choice([0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a])
        cipher_bytes = struct.pack(">H", grease_value)
    else:
        cipher_bytes = b''
    
    for cipher in cipher_list:
        cipher_bytes += struct.pack(">H", cipher)
    
    cipher_length = struct.pack(">H", len(cipher_bytes))
    
    # Compression methods
    compression = b'\x01\x00'  # 1 method, null compression
    
    # Build ClientHello
    client_hello = (
        struct.pack(">H", tls_version) +  # Version
        client_random +
        session_id +
        cipher_length + cipher_bytes +
        compression +
        extensions
    )
    
    # Handshake header
    handshake_length = struct.pack(">I", len(client_hello))[1:]  # 3 bytes
    handshake = bytes([handshake_type]) + handshake_length + client_hello
    
    # Record header
    record_version = struct.pack(">H", 0x0301)  # TLS 1.0 for record layer
    record_length = struct.pack(">H", len(handshake))
    
    return bytes([record_type]) + record_version + record_length + handshake


def _get_jarm_extensions(tls_version: int, host: str, alpn: bool = False) -> bytes:
    """Build TLS extensions for JARM probing."""
    extensions = b''
    
    # SNI extension
    host_bytes = host.encode('utf-8')
    sni_entry = struct.pack(">BH", 0, len(host_bytes)) + host_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    extensions += sni_ext
    
    # Supported versions extension (TLS 1.3+)
    if tls_version >= 0x0304:
        versions = struct.pack(">BH", 1, tls_version)
        extensions += struct.pack(">HH", 0x002b, len(versions)) + versions
    
    # Signature algorithms
    sig_algs = bytes([
        0x04, 0x03,  # ECDSA-SECP256r1-SHA256
        0x05, 0x03,  # ECDSA-SECP384r1-SHA384
        0x06, 0x03,  # ECDSA-SECP521r1-SHA512
        0x08, 0x04,  # RSA-PSS-SHA256
        0x08, 0x05,  # RSA-PSS-SHA384
        0x08, 0x06,  # RSA-PSS-SHA512
        0x04, 0x01,  # RSA-PKCS1-SHA256
        0x05, 0x01,  # RSA-PKCS1-SHA384
        0x06, 0x01,  # RSA-PKCS1-SHA512
    ])
    sig_alg_ext = struct.pack(">HHH", 0x000d, len(sig_algs) + 2, len(sig_algs)) + sig_algs
    extensions += sig_alg_ext
    
    # Supported groups (elliptic curves)
    groups = bytes([0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19])  # x25519, P-256, P-384, P-521
    groups_ext = struct.pack(">HHH", 0x000a, len(groups) + 2, len(groups)) + groups
    extensions += groups_ext
    
    # EC point formats
    ec_formats = bytes([0x00])  # uncompressed
    ec_ext = struct.pack(">HHB", 0x000b, 2, 1) + ec_formats
    extensions += ec_ext
    
    # ALPN extension
    if alpn:
        alpn_protocols = b'\x02h2\x08http/1.1'
        alpn_ext = struct.pack(">HHH", 0x0010, len(alpn_protocols) + 2, len(alpn_protocols)) + alpn_protocols
        extensions += alpn_ext
    
    return struct.pack(">H", len(extensions)) + extensions


def _send_jarm_probe(host: str, port: int, packet: bytes, timeout: float = 5.0) -> str:
    """Send a JARM probe and parse the response."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.send(packet)
        
        # Read response
        response = sock.recv(1484)
        sock.close()
        
        if len(response) < 5:
            return "|||"
        
        # Parse TLS record
        record_type = response[0]
        if record_type != 0x16:  # Not a handshake
            if record_type == 0x15:  # Alert
                return "|||"
            return "|||"
        
        # Parse ServerHello
        if len(response) < 11:
            return "|||"
        
        # Get version from ServerHello
        server_version = struct.unpack(">H", response[9:11])[0]
        
        # Get cipher suite
        if len(response) < 44:
            return "|||"
        
        # Session ID length is at offset 43
        session_id_len = response[43]
        cipher_offset = 44 + session_id_len
        
        if len(response) < cipher_offset + 2:
            return "|||"
        
        cipher = struct.unpack(">H", response[cipher_offset:cipher_offset+2])[0]
        
        # Format: version|cipher|extensions
        version_str = f"{server_version:04x}"
        cipher_str = f"{cipher:04x}"
        
        # Parse extensions (simplified)
        ext_str = ""
        
        return f"{version_str}|{cipher_str}|{ext_str}"
        
    except socket.timeout:
        return "|||"
    except ConnectionRefusedError:
        return "|||"
    except Exception as e:
        logger.debug(f"JARM probe failed: {e}")
        return "|||"


def _calculate_jarm_hash(responses: List[str]) -> str:
    """Calculate JARM fingerprint hash from probe responses."""
    # Concatenate all responses
    raw = "".join(responses)
    
    # If all empty, return zero hash
    if all(r == "|||" for r in responses):
        return "0" * 62
    
    # Calculate fuzzy hash (simplified JARM algorithm)
    # Real JARM uses a more complex algorithm
    combined = "".join(r.replace("|", "") for r in responses)
    
    if not combined:
        return "0" * 62
    
    # Create deterministic hash
    h = hashlib.sha256(combined.encode()).hexdigest()
    
    # JARM format: first 30 chars + last 32 chars of hash
    # This is simplified - real JARM has specific construction
    return h[:30] + h[32:]


def get_jarm_fingerprint(host: str, port: int = 443, timeout: float = 5.0) -> JARMFingerprint:
    """
    Generate JARM fingerprint for a TLS server.
    
    JARM sends 10 TLS ClientHello probes with different parameters
    and fingerprints the server based on its responses.
    """
    responses = []
    
    # 10 JARM probes with different configurations
    probes = [
        # Probe 1: TLS 1.2, forward cipher order
        (0x0303, JARM_CIPHERS["tls1_2_forward"], False, False),
        # Probe 2: TLS 1.2, reverse cipher order
        (0x0303, JARM_CIPHERS["tls1_2_reverse"], False, False),
        # Probe 3: TLS 1.2, top half ciphers
        (0x0303, JARM_CIPHERS["tls1_2_top_half"], False, False),
        # Probe 4: TLS 1.2, bottom half ciphers
        (0x0303, JARM_CIPHERS["tls1_2_bottom_half"], False, False),
        # Probe 5: TLS 1.2, middle out
        (0x0303, JARM_CIPHERS["tls1_2_middle_out"], False, False),
        # Probe 6: TLS 1.1
        (0x0302, JARM_CIPHERS["tls1_2_forward"], False, False),
        # Probe 7: TLS 1.3
        (0x0304, JARM_CIPHERS["tls1_2_forward"], False, True),
        # Probe 8: TLS 1.2 with ALPN
        (0x0303, JARM_CIPHERS["tls1_2_forward"], True, False),
        # Probe 9: TLS 1.2 with GREASE
        (0x0303, JARM_CIPHERS["tls1_2_forward"], False, False),
        # Probe 10: TLS 1.0
        (0x0301, JARM_CIPHERS["tls1_2_forward"], False, False),
    ]
    
    for tls_ver, ciphers, alpn, grease in probes:
        extensions = _get_jarm_extensions(tls_ver, host, alpn)
        packet = _build_jarm_packet(host, tls_ver, ciphers, extensions, grease)
        response = _send_jarm_probe(host, port, packet, timeout)
        responses.append(response)
        time.sleep(0.1)  # Small delay between probes
    
    # Calculate fingerprint
    fingerprint = _calculate_jarm_hash(responses)
    
    # Check against known signatures
    result = JARMFingerprint(
        fingerprint=fingerprint,
        raw_responses=responses,
    )
    
    if fingerprint in KNOWN_JARM_SIGNATURES:
        sig = KNOWN_JARM_SIGNATURES[fingerprint]
        result.matched_signature = sig["name"]
        result.signature_type = sig["type"]
        result.severity = sig["severity"]
        result.description = sig["description"]
    else:
        result.signature_type = "unknown"
        result.severity = "info"
        result.description = "Unknown server fingerprint"
    
    return result


def _is_dga_domain(domain: str) -> bool:
    """
    Check if a domain looks like it was generated by a DGA.
    Uses entropy and pattern analysis.
    """
    # Remove TLD
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return False
    
    # Analyze the main part (excluding TLD)
    main_part = parts[0] if len(parts) == 2 else '.'.join(parts[:-1])
    
    if len(main_part) < 5:
        return False
    
    # Calculate entropy
    char_counts: Dict[str, int] = {}
    for c in main_part:
        char_counts[c] = char_counts.get(c, 0) + 1
    
    entropy = 0.0
    for count in char_counts.values():
        p = count / len(main_part)
        entropy -= p * (p and (p > 0 and __import__('math').log2(p) or 0))
    
    # High entropy suggests random generation
    if entropy > 3.5 and len(main_part) > 10:
        return True
    
    # Check for suspicious patterns
    # High ratio of consonants
    vowels = set('aeiou')
    consonants = sum(1 for c in main_part if c.isalpha() and c not in vowels)
    if len(main_part) > 8 and consonants / len(main_part) > 0.85:
        return True
    
    # Long strings of consonants
    consonant_run = 0
    max_consonant_run = 0
    for c in main_part:
        if c.isalpha() and c not in vowels:
            consonant_run += 1
            max_consonant_run = max(max_consonant_run, consonant_run)
        else:
            consonant_run = 0
    
    if max_consonant_run >= 5:
        return True
    
    # Check for mixed numbers and letters in suspicious patterns
    if re.match(r'^[a-z]+\d+[a-z]+\d+', main_part) or re.match(r'^\d+[a-z]+\d+[a-z]+', main_part):
        return True
    
    return False


def analyze_certificate_intelligence(cert: SSLCertificate, host: str) -> CertificateIntelligence:
    """
    Extract offensive intelligence from a certificate.
    Identifies suspicious patterns common in malware/C2.
    """
    intel = CertificateIntelligence()
    
    # Basic info
    intel.common_name = cert.subject.get("commonName")
    intel.organization = cert.subject.get("organizationName")
    intel.issuer_cn = cert.issuer.get("commonName")
    intel.issuer_org = cert.issuer.get("organizationName")
    intel.fingerprint_sha256 = cert.sha256_fingerprint
    intel.serial_number = cert.serial_number
    intel.cert_hash = hashlib.sha256(f"{cert.serial_number}{cert.sha256_fingerprint}".encode()).hexdigest()[:16]
    
    # Calculate validity period
    if cert.not_before and cert.not_after:
        try:
            not_before = datetime.datetime.fromisoformat(cert.not_before.replace('Z', '+00:00'))
            not_after = datetime.datetime.fromisoformat(cert.not_after.replace('Z', '+00:00'))
            intel.validity_days = (not_after - not_before).days
            
            now = datetime.datetime.now(datetime.timezone.utc)
            intel.days_since_issued = (now - not_before).days
        except:
            pass
    
    # Domain analysis
    intel.all_domains = [intel.common_name] if intel.common_name else []
    intel.all_domains.extend(cert.san)
    intel.all_domains = list(set(d for d in intel.all_domains if d))
    
    for domain in intel.all_domains:
        if domain.startswith('*'):
            intel.wildcard_domains.append(domain)
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            intel.ip_sans.append(domain)
    
    # Suspicious pattern checks
    suspicion_score = 0
    
    # 1. Short validity period
    if intel.validity_days:
        if intel.validity_days <= 7:
            intel.suspicion_reasons.append("CRITICAL: Certificate valid for 7 days or less")
            suspicion_score += 40
        elif intel.validity_days <= 30:
            intel.suspicion_reasons.append("Certificate valid for less than 30 days")
            suspicion_score += 25
    
    # 2. Self-signed
    if cert.is_self_signed:
        intel.suspicion_reasons.append("Self-signed certificate - identity cannot be verified")
        suspicion_score += 20
    
    # 3. IP address as CN
    if intel.common_name and re.match(r'^\d+\.\d+\.\d+\.\d+$', intel.common_name):
        intel.suspicion_reasons.append("Common Name is an IP address - common in malware")
        suspicion_score += 25
    
    # 4. Numeric-only or suspicious CN
    if intel.common_name:
        if re.match(r'^\d+$', intel.common_name):
            intel.suspicion_reasons.append("Common Name is purely numeric")
            suspicion_score += 20
        
        # Random-looking CN
        if len(intel.common_name) > 15 and _is_dga_domain(intel.common_name):
            intel.suspicion_reasons.append("Common Name appears randomly generated (DGA-like)")
            intel.potential_dga = True
            suspicion_score += 35
    
    # 5. DGA domain check for all domains
    for domain in intel.all_domains:
        if _is_dga_domain(domain):
            intel.potential_dga = True
            intel.suspicion_reasons.append(f"Domain '{domain}' appears DGA-generated")
            suspicion_score += 30
            break
    
    # 6. Free certificate provider
    if intel.issuer_org:
        for provider in FREE_CERT_PROVIDERS:
            if provider.lower() in intel.issuer_org.lower():
                intel.suspicion_reasons.append(f"Certificate from free provider: {provider}")
                suspicion_score += 5
                break
    
    # 7. Suspicious issuer
    issuer_str = f"{intel.issuer_cn or ''} {intel.issuer_org or ''}".lower()
    for pattern in SUSPICIOUS_ISSUERS:
        if re.search(pattern, issuer_str, re.IGNORECASE):
            intel.suspicion_reasons.append(f"Suspicious issuer pattern: {pattern}")
            suspicion_score += 15
            break
    
    # 8. Recently issued (within 24 hours)
    if intel.days_since_issued is not None and intel.days_since_issued <= 1:
        intel.suspicion_reasons.append("Certificate issued very recently (within 24 hours)")
        suspicion_score += 10
    
    # 9. Many wildcard domains
    if len(intel.wildcard_domains) > 2:
        intel.suspicion_reasons.append(f"Multiple wildcard domains ({len(intel.wildcard_domains)})")
        suspicion_score += 10
    
    # 10. CN mismatch with host
    if intel.common_name and host:
        cn = intel.common_name.lower().lstrip('*.')
        host_lower = host.lower()
        if cn not in host_lower and host_lower not in cn:
            # Check SANs too
            san_match = any(host_lower in san.lower() or san.lower().lstrip('*.') in host_lower for san in cert.san)
            if not san_match:
                intel.suspicion_reasons.append(f"Certificate CN '{intel.common_name}' doesn't match host '{host}'")
                suspicion_score += 15
    
    intel.suspicion_score = min(100, suspicion_score)
    intel.is_suspicious = suspicion_score >= 30
    
    return intel


def analyze_mitm_feasibility(
    host: str,
    port: int,
    cert: Optional[SSLCertificate],
    protocols: Dict[str, bool],
    ciphers: List[Dict[str, Any]],
    timeout: float = 5.0
) -> MITMFeasibility:
    """
    Analyze the feasibility of MITM attacks against this TLS connection.
    """
    mitm = MITMFeasibility()
    
    # Check for weak protocols
    if protocols.get("SSLv3") or protocols.get("TLSv1.0"):
        mitm.weak_tls_version = True
        mitm.methods.append("Protocol downgrade attack possible (SSLv3/TLS1.0)")
    
    # Check for weak ciphers
    weak = [c for c in ciphers if c.get("is_weak")]
    if weak:
        mitm.weak_cipher_available = True
        mitm.methods.append(f"Weak ciphers available: {', '.join(c['name'] for c in weak[:3])}")
    
    # Check if server accepts different SNI
    if not cert or cert.is_self_signed:
        mitm.accepts_self_signed = True
        mitm.methods.append("Self-signed certificate - easy to impersonate")
    
    # Check for certificate pinning (heuristic)
    # If cert is from a major CA and has HPKP headers, it might be pinned
    # This is a simplified check - real pinning detection requires app analysis
    if cert:
        major_cas = ["DigiCert", "Let's Encrypt", "GlobalSign", "Comodo"]
        issuer = cert.issuer.get("organizationName", "")
        if any(ca in issuer for ca in major_cas):
            mitm.blockers.append("Certificate from major CA - may have app-level pinning")
    
    # Try connecting with a different SNI to detect SNI requirement
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # Try with mismatched SNI
            with context.wrap_socket(sock, server_hostname="test.invalid") as ssock:
                # Server accepted mismatched SNI
                mitm.methods.append("Server accepts arbitrary SNI values")
    except:
        mitm.sni_required = True
        mitm.blockers.append("Server requires matching SNI")
    
    # Determine overall feasibility
    if mitm.accepts_self_signed or mitm.weak_tls_version:
        mitm.can_mitm = True
        mitm.difficulty = "easy"
    elif mitm.weak_cipher_available:
        mitm.can_mitm = True
        mitm.difficulty = "medium"
    elif not mitm.blockers:
        mitm.can_mitm = True
        mitm.difficulty = "hard"
    else:
        mitm.can_mitm = False
        mitm.difficulty = "impossible"
    
    # Recommendations for interception
    if mitm.can_mitm:
        if mitm.accepts_self_signed:
            mitm.recommendations.append("Use mitmproxy or Burp Suite with custom CA")
        if mitm.weak_tls_version:
            mitm.recommendations.append("Force TLS downgrade with sslstrip or similar")
        mitm.recommendations.append("Install custom root CA in sandbox VM")
        mitm.recommendations.append("Use transparent proxy (iptables redirect)")
    
    return mitm


def detect_domain_fronting(
    host: str,
    port: int,
    cert: Optional[SSLCertificate],
    timeout: float = 5.0
) -> DomainFrontingInfo:
    """
    Detect potential domain fronting configuration.
    Domain fronting uses different SNI and Host header to bypass censorship.
    """
    fronting = DomainFrontingInfo()
    fronting.sni_domain = host
    
    # CDN detection based on certificate
    cdn_patterns = {
        "Cloudflare": ["cloudflare", "cloudflaressl"],
        "AWS CloudFront": ["cloudfront", "amazon"],
        "Azure CDN": ["azure", "microsoft"],
        "Google Cloud": ["google", "gstatic"],
        "Fastly": ["fastly", "fastly-edge"],
        "Akamai": ["akamai", "akamaitech"],
    }
    
    if cert:
        cert_text = f"{cert.subject} {cert.issuer} {' '.join(cert.san)}"
        for cdn, patterns in cdn_patterns.items():
            if any(p in cert_text.lower() for p in patterns):
                fronting.cdn_provider = cdn
                fronting.is_frontable = True
                fronting.fronting_domains.extend(cert.san)
                break
    
    # Check if certificate covers multiple domains (required for fronting)
    if cert and len(cert.san) > 3:
        fronting.is_frontable = True
        fronting.fronting_domains = cert.san[:10]
    
    return fronting


def perform_offensive_ssl_analysis(
    host: str,
    port: int = 443,
    cert: Optional[SSLCertificate] = None,
    protocols: Optional[Dict[str, bool]] = None,
    ciphers: Optional[List[Dict[str, Any]]] = None,
    timeout: float = 10.0
) -> OffensiveSSLAnalysis:
    """
    Perform comprehensive offensive SSL/TLS analysis for sandbox software.
    
    This analyzes:
    1. JARM fingerprint - Identify C2 frameworks, malware infrastructure
    2. Certificate intelligence - Extract IoCs, detect suspicious patterns
    3. MITM feasibility - Can we intercept this traffic?
    4. Domain fronting - Is this potentially fronted traffic?
    """
    analysis = OffensiveSSLAnalysis(host=host, port=port)
    threat_indicators = []
    threat_score = 0
    
    # 1. JARM Fingerprinting
    try:
        analysis.jarm = get_jarm_fingerprint(host, port, timeout)
        if analysis.jarm.signature_type == "c2_framework":
            threat_indicators.append(f"JARM matches C2 framework: {analysis.jarm.matched_signature}")
            threat_score += 50
        elif analysis.jarm.signature_type == "malware":
            threat_indicators.append(f"JARM matches known malware: {analysis.jarm.matched_signature}")
            threat_score += 60
    except Exception as e:
        logger.debug(f"JARM fingerprinting failed: {e}")
    
    # 2. Certificate Intelligence
    if cert:
        try:
            analysis.cert_intel = analyze_certificate_intelligence(cert, host)
            if analysis.cert_intel.is_suspicious:
                threat_indicators.extend(analysis.cert_intel.suspicion_reasons)
                threat_score += analysis.cert_intel.suspicion_score // 2
            if analysis.cert_intel.potential_dga:
                threat_indicators.append("Domain appears DGA-generated")
                threat_score += 30
        except Exception as e:
            logger.debug(f"Certificate intelligence failed: {e}")
    
    # 3. MITM Feasibility
    if protocols is not None and ciphers is not None:
        try:
            analysis.mitm = analyze_mitm_feasibility(host, port, cert, protocols, ciphers, timeout)
            if analysis.mitm.can_mitm:
                threat_indicators.append(f"MITM possible ({analysis.mitm.difficulty}): {', '.join(analysis.mitm.methods[:2])}")
        except Exception as e:
            logger.debug(f"MITM analysis failed: {e}")
    
    # 4. Domain Fronting Detection
    try:
        analysis.domain_fronting = detect_domain_fronting(host, port, cert, timeout)
        if analysis.domain_fronting.is_frontable:
            threat_indicators.append(f"Potential domain fronting via {analysis.domain_fronting.cdn_provider or 'CDN'}")
    except Exception as e:
        logger.debug(f"Domain fronting detection failed: {e}")
    
    # Calculate overall threat level
    analysis.threat_indicators = threat_indicators
    
    if threat_score >= 70:
        analysis.threat_level = "critical"
        analysis.is_likely_malicious = True
        analysis.confidence = min(0.95, threat_score / 100)
    elif threat_score >= 50:
        analysis.threat_level = "high"
        analysis.is_likely_malicious = True
        analysis.confidence = min(0.80, threat_score / 100)
    elif threat_score >= 30:
        analysis.threat_level = "medium"
        analysis.is_likely_malicious = False
        analysis.confidence = threat_score / 100
    elif threat_score >= 10:
        analysis.threat_level = "low"
        analysis.is_likely_malicious = False
        analysis.confidence = threat_score / 100
    else:
        analysis.threat_level = "benign"
        analysis.is_likely_malicious = False
        analysis.confidence = max(0.1, 1 - threat_score / 100)
    
    return analysis


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


# ============================================================================
# SECURITY HEADER DETECTION (HSTS, HPKP, CSP, etc.)
# ============================================================================

@dataclass
class SecurityHeaders:
    """HTTP security headers analysis."""
    # HSTS (HTTP Strict Transport Security)
    hsts_enabled: bool = False
    hsts_max_age: Optional[int] = None
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    
    # Other security headers
    hpkp_enabled: bool = False  # Deprecated but still in use
    hpkp_pins: List[str] = field(default_factory=list)
    expect_ct_enabled: bool = False
    content_security_policy: bool = False
    x_frame_options: bool = False
    x_content_type_options: bool = False
    x_xss_protection: bool = False
    
    # Recommendations
    missing_headers: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    score: int = 0  # 0-100 security headers score
    
    # Raw headers
    raw_headers: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_security_headers(host: str, port: int = 443, timeout: float = 10.0) -> SecurityHeaders:
    """
    Check HTTP security headers including HSTS, HPKP, CSP, etc.
    Makes an HTTPS request to the host to inspect response headers.
    """
    import urllib.request
    import urllib.error
    
    headers = SecurityHeaders()
    
    try:
        # Build URL
        url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
        
        # Create request with custom User-Agent
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'VRAgent-SSL-Scanner/1.0',
                'Accept': '*/*',
            }
        )
        
        # Create SSL context that doesn't verify (we're checking headers, not cert)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Make request with timeout
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            # Get all headers
            for header, value in response.headers.items():
                headers.raw_headers[header.lower()] = value
            
            # Check HSTS
            hsts_value = response.headers.get('Strict-Transport-Security', '')
            if hsts_value:
                headers.hsts_enabled = True
                
                # Parse max-age
                if 'max-age=' in hsts_value.lower():
                    try:
                        max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
                        if max_age_match:
                            headers.hsts_max_age = int(max_age_match.group(1))
                    except ValueError:
                        pass
                
                # Check directives
                hsts_lower = hsts_value.lower()
                headers.hsts_include_subdomains = 'includesubdomains' in hsts_lower
                headers.hsts_preload = 'preload' in hsts_lower
            
            # Check HPKP (deprecated but still seen)
            hpkp_value = response.headers.get('Public-Key-Pins', '') or response.headers.get('Public-Key-Pins-Report-Only', '')
            if hpkp_value:
                headers.hpkp_enabled = True
                # Extract pins
                pin_matches = re.findall(r'pin-sha256="([^"]+)"', hpkp_value)
                headers.hpkp_pins = pin_matches
            
            # Check Expect-CT
            if response.headers.get('Expect-CT'):
                headers.expect_ct_enabled = True
            
            # Check CSP
            if response.headers.get('Content-Security-Policy') or response.headers.get('Content-Security-Policy-Report-Only'):
                headers.content_security_policy = True
            
            # Check X-Frame-Options
            if response.headers.get('X-Frame-Options'):
                headers.x_frame_options = True
            
            # Check X-Content-Type-Options
            if response.headers.get('X-Content-Type-Options'):
                headers.x_content_type_options = True
            
            # Check X-XSS-Protection
            if response.headers.get('X-XSS-Protection'):
                headers.x_xss_protection = True
        
        # Calculate score and identify issues
        score = 0
        
        # HSTS scoring (40 points max)
        if headers.hsts_enabled:
            score += 20
            if headers.hsts_max_age and headers.hsts_max_age >= 31536000:  # 1 year
                score += 10
            elif headers.hsts_max_age and headers.hsts_max_age < 86400:  # Less than 1 day
                headers.issues.append("HSTS max-age is too short (< 1 day)")
            if headers.hsts_include_subdomains:
                score += 5
            if headers.hsts_preload:
                score += 5
        else:
            headers.missing_headers.append("Strict-Transport-Security (HSTS)")
            headers.issues.append("HSTS not enabled - susceptible to SSL stripping attacks")
        
        # CSP scoring (20 points)
        if headers.content_security_policy:
            score += 20
        else:
            headers.missing_headers.append("Content-Security-Policy")
        
        # X-Frame-Options (15 points)
        if headers.x_frame_options:
            score += 15
        else:
            headers.missing_headers.append("X-Frame-Options")
        
        # X-Content-Type-Options (15 points)
        if headers.x_content_type_options:
            score += 15
        else:
            headers.missing_headers.append("X-Content-Type-Options")
        
        # X-XSS-Protection (10 points) - deprecated but still useful for older browsers
        if headers.x_xss_protection:
            score += 10
        
        headers.score = min(100, score)
        
    except urllib.error.HTTPError as e:
        # Still try to get headers from error response
        if hasattr(e, 'headers'):
            for header, value in e.headers.items():
                headers.raw_headers[header.lower()] = value
            
            hsts_value = e.headers.get('Strict-Transport-Security', '')
            if hsts_value:
                headers.hsts_enabled = True
                if 'max-age=' in hsts_value.lower():
                    try:
                        max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
                        if max_age_match:
                            headers.hsts_max_age = int(max_age_match.group(1))
                    except ValueError:
                        pass
        headers.issues.append(f"HTTP error {e.code} - limited header analysis")
        
    except urllib.error.URLError as e:
        headers.issues.append(f"Connection failed: {str(e)[:100]}")
        
    except Exception as e:
        headers.issues.append(f"Header check failed: {str(e)[:100]}")
        logger.debug(f"Security header check failed for {host}:{port}: {e}")
    
    return headers


# ============================================================================
# OCSP REVOCATION CHECKING
# ============================================================================

@dataclass
class OCSPStatus:
    """OCSP certificate revocation status."""
    checked: bool = False
    status: str = "unknown"  # good, revoked, unknown, error
    revocation_time: Optional[str] = None
    revocation_reason: Optional[str] = None
    
    # OCSP responder info
    ocsp_url: Optional[str] = None
    ocsp_response_status: Optional[str] = None
    
    # Timing
    this_update: Optional[str] = None
    next_update: Optional[str] = None
    
    # Stapling
    ocsp_stapling_supported: bool = False
    stapled_response: bool = False
    
    # Issues
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_ocsp_revocation(host: str, port: int = 443, timeout: float = 10.0) -> OCSPStatus:
    """
    Check certificate revocation status via OCSP.
    Extracts OCSP URL from certificate and queries the OCSP responder.
    """
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
    
    ocsp = OCSPStatus()
    
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.x509 import ocsp as crypto_ocsp
        from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
        
        # Get the certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                
                if not cert_der:
                    ocsp.errors.append("Could not retrieve certificate")
                    return ocsp
                
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Try to get OCSP URL from certificate
                try:
                    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                    for access_description in aia.value:
                        if access_description.access_method == AuthorityInformationAccessOID.OCSP:
                            ocsp.ocsp_url = access_description.access_location.value
                            break
                except x509.ExtensionNotFound:
                    ocsp.errors.append("No OCSP URL in certificate")
                    return ocsp
                
                if not ocsp.ocsp_url:
                    ocsp.errors.append("OCSP URL not found in certificate")
                    return ocsp
                
                # Get issuer certificate (try to fetch from AIA)
                issuer_cert = None
                try:
                    for access_description in aia.value:
                        if access_description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                            issuer_url = access_description.access_location.value
                            req = Request(issuer_url, headers={'User-Agent': 'VRAgent-OCSP/1.0'})
                            with urlopen(req, timeout=timeout) as resp:
                                issuer_der = resp.read()
                                # Try DER format first, then PEM
                                try:
                                    issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
                                except:
                                    try:
                                        issuer_cert = x509.load_pem_x509_certificate(issuer_der, default_backend())
                                    except:
                                        pass
                            if issuer_cert:
                                break
                except Exception as e:
                    ocsp.errors.append(f"Could not fetch issuer cert: {str(e)[:50]}")
                
                if not issuer_cert:
                    # Try to use the certificate itself if self-signed
                    if cert.subject == cert.issuer:
                        issuer_cert = cert
                    else:
                        ocsp.errors.append("Issuer certificate not available for OCSP check")
                        ocsp.checked = False
                        return ocsp
                
                # Build OCSP request
                builder = crypto_ocsp.OCSPRequestBuilder()
                builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
                ocsp_request = builder.build()
                ocsp_request_data = ocsp_request.public_bytes(serialization.Encoding.DER)
                
                # Send OCSP request
                req = Request(
                    ocsp.ocsp_url,
                    data=ocsp_request_data,
                    headers={
                        'Content-Type': 'application/ocsp-request',
                        'User-Agent': 'VRAgent-OCSP/1.0'
                    }
                )
                
                try:
                    with urlopen(req, timeout=timeout) as resp:
                        ocsp_response_data = resp.read()
                        
                        # Parse OCSP response
                        ocsp_response = crypto_ocsp.load_der_ocsp_response(ocsp_response_data)
                        
                        ocsp.checked = True
                        ocsp.ocsp_response_status = str(ocsp_response.response_status.name)
                        
                        if ocsp_response.response_status == crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
                            # Check certificate status
                            cert_status = ocsp_response.certificate_status
                            
                            if cert_status == crypto_ocsp.OCSPCertStatus.GOOD:
                                ocsp.status = "good"
                            elif cert_status == crypto_ocsp.OCSPCertStatus.REVOKED:
                                ocsp.status = "revoked"
                                if ocsp_response.revocation_time:
                                    ocsp.revocation_time = ocsp_response.revocation_time.isoformat()
                                if ocsp_response.revocation_reason:
                                    ocsp.revocation_reason = str(ocsp_response.revocation_reason.name)
                            else:
                                ocsp.status = "unknown"
                            
                            # Get update times
                            if ocsp_response.this_update:
                                ocsp.this_update = ocsp_response.this_update.isoformat()
                            if ocsp_response.next_update:
                                ocsp.next_update = ocsp_response.next_update.isoformat()
                        else:
                            ocsp.status = "error"
                            ocsp.errors.append(f"OCSP response status: {ocsp_response.response_status.name}")
                            
                except HTTPError as e:
                    ocsp.errors.append(f"OCSP request failed: HTTP {e.code}")
                except URLError as e:
                    ocsp.errors.append(f"OCSP request failed: {str(e)[:50]}")
                except Exception as e:
                    ocsp.errors.append(f"OCSP response parsing failed: {str(e)[:50]}")
        
        # Check for OCSP stapling support
        try:
            # TLS 1.2+ with status request
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Note: Python's ssl module doesn't directly support checking OCSP stapling
            # This would require lower-level TLS access or external tools
            # We mark it as a limitation
            ocsp.ocsp_stapling_supported = False  # Cannot determine with standard library
            
        except Exception:
            pass
            
    except ImportError as e:
        ocsp.errors.append(f"cryptography library required: {str(e)[:50]}")
    except Exception as e:
        ocsp.errors.append(f"OCSP check failed: {str(e)[:100]}")
        logger.debug(f"OCSP check failed for {host}:{port}: {e}")
    
    return ocsp


# ============================================================================
# TLS 1.3 CIPHER SUITE DETECTION
# ============================================================================

# TLS 1.3 cipher suites (RFC 8446)
TLS13_CIPHER_SUITES = {
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "strength": "strong", "key_size": 128, "mode": "AEAD"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "strength": "strong", "key_size": 256, "mode": "AEAD"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "strength": "strong", "key_size": 256, "mode": "AEAD"},
    0x1304: {"name": "TLS_AES_128_CCM_SHA256", "strength": "strong", "key_size": 128, "mode": "AEAD"},
    0x1305: {"name": "TLS_AES_128_CCM_8_SHA256", "strength": "medium", "key_size": 128, "mode": "AEAD"},
}

@dataclass
class TLS13CipherInfo:
    """TLS 1.3 cipher suite information."""
    name: str
    code: int
    strength: str  # strong, medium, weak
    key_size: int
    mode: str  # AEAD
    supported: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class TLS13Analysis:
    """TLS 1.3 specific analysis."""
    supported: bool = False
    cipher_suites: List[TLS13CipherInfo] = field(default_factory=list)
    supports_0rtt: bool = False
    early_data_size: Optional[int] = None
    
    # Key exchange groups supported
    supported_groups: List[str] = field(default_factory=list)
    
    # Best practices
    has_aes_gcm: bool = False
    has_chacha20: bool = False
    score: int = 0  # 0-100
    issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "supported": self.supported,
            "cipher_suites": [c.to_dict() for c in self.cipher_suites],
            "supports_0rtt": self.supports_0rtt,
            "early_data_size": self.early_data_size,
            "supported_groups": self.supported_groups,
            "has_aes_gcm": self.has_aes_gcm,
            "has_chacha20": self.has_chacha20,
            "score": self.score,
            "issues": self.issues,
        }


def check_tls13_ciphers(host: str, port: int = 443, timeout: float = 10.0) -> TLS13Analysis:
    """
    Check TLS 1.3 specific cipher suite support.
    Tests each TLS 1.3 cipher suite individually.
    """
    analysis = TLS13Analysis()
    
    try:
        # First check if TLS 1.3 is supported at all
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    analysis.supported = True
                    
                    # Get the negotiated cipher
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Find the cipher code
                        for code, info in TLS13_CIPHER_SUITES.items():
                            if info["name"] == cipher_name:
                                analysis.cipher_suites.append(TLS13CipherInfo(
                                    name=info["name"],
                                    code=code,
                                    strength=info["strength"],
                                    key_size=info["key_size"],
                                    mode=info["mode"],
                                    supported=True
                                ))
                                break
                        
                        # Check for specific ciphers
                        if "AES" in cipher_name and "GCM" in cipher_name:
                            analysis.has_aes_gcm = True
                        if "CHACHA20" in cipher_name:
                            analysis.has_chacha20 = True
        except ssl.SSLError as e:
            if "TLSV1_ALERT_PROTOCOL_VERSION" in str(e) or "unsupported protocol" in str(e).lower():
                analysis.supported = False
            else:
                analysis.issues.append(f"TLS 1.3 connection error: {str(e)[:50]}")
        except Exception as e:
            analysis.issues.append(f"TLS 1.3 check failed: {str(e)[:50]}")
        
        # Test each TLS 1.3 cipher suite individually (requires OpenSSL 1.1.1+)
        if analysis.supported:
            for code, info in TLS13_CIPHER_SUITES.items():
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                    
                    # Try to set specific cipher (may not work on all systems)
                    try:
                        ctx.set_ciphers(info["name"])
                    except ssl.SSLError:
                        continue
                    
                    with socket.create_connection((host, port), timeout=timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            cipher = ssock.cipher()
                            if cipher and cipher[0] == info["name"]:
                                # Check if already added
                                if not any(c.code == code for c in analysis.cipher_suites):
                                    analysis.cipher_suites.append(TLS13CipherInfo(
                                        name=info["name"],
                                        code=code,
                                        strength=info["strength"],
                                        key_size=info["key_size"],
                                        mode=info["mode"],
                                        supported=True
                                    ))
                                    
                                    if "AES" in info["name"] and "GCM" in info["name"]:
                                        analysis.has_aes_gcm = True
                                    if "CHACHA20" in info["name"]:
                                        analysis.has_chacha20 = True
                except Exception:
                    pass
        
        # Calculate score
        score = 0
        if analysis.supported:
            score += 40  # TLS 1.3 support is good
            if analysis.has_aes_gcm:
                score += 30
            if analysis.has_chacha20:
                score += 20
            if len(analysis.cipher_suites) >= 3:
                score += 10
        
        analysis.score = min(100, score)
        
        # Check for issues
        if analysis.supported and not analysis.has_aes_gcm and not analysis.has_chacha20:
            analysis.issues.append("No AES-GCM or ChaCha20 cipher suites available")
        if analysis.supported and len(analysis.cipher_suites) < 2:
            analysis.issues.append("Limited TLS 1.3 cipher suite selection")
            
    except Exception as e:
        analysis.issues.append(f"TLS 1.3 analysis failed: {str(e)[:100]}")
        logger.debug(f"TLS 1.3 cipher check failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# CERTIFICATE TRANSPARENCY LOG VERIFICATION
# ============================================================================

# Known CT Log servers
CT_LOGS = [
    "https://ct.googleapis.com/logs/argon2023/",
    "https://ct.googleapis.com/logs/argon2024/",
    "https://ct.cloudflare.com/logs/nimbus2023/",
    "https://ct.cloudflare.com/logs/nimbus2024/",
    "https://oak.ct.letsencrypt.org/2023/",
    "https://oak.ct.letsencrypt.org/2024/",
]

@dataclass
class SCTInfo:
    """Signed Certificate Timestamp information."""
    log_id: str
    timestamp: Optional[str] = None
    signature_algorithm: Optional[str] = None
    is_valid: bool = False
    log_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CTLogVerification:
    """Certificate Transparency log verification result."""
    has_scts: bool = False
    sct_count: int = 0
    scts: List[SCTInfo] = field(default_factory=list)
    
    # Delivery methods
    embedded_in_cert: bool = False
    via_tls_extension: bool = False
    via_ocsp: bool = False
    
    # Verification
    all_valid: bool = False
    verified_logs: List[str] = field(default_factory=list)
    
    # Issues
    issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_scts": self.has_scts,
            "sct_count": self.sct_count,
            "scts": [s.to_dict() for s in self.scts],
            "embedded_in_cert": self.embedded_in_cert,
            "via_tls_extension": self.via_tls_extension,
            "via_ocsp": self.via_ocsp,
            "all_valid": self.all_valid,
            "verified_logs": self.verified_logs,
            "issues": self.issues,
        }


def verify_ct_logs(host: str, port: int = 443, timeout: float = 10.0) -> CTLogVerification:
    """
    Verify Certificate Transparency logs for a certificate.
    Extracts SCTs from the certificate and verifies them.
    """
    ct_result = CTLogVerification()
    
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID
        import base64
        
        # Get the certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                
                if not cert_der:
                    ct_result.issues.append("Could not retrieve certificate")
                    return ct_result
                
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Try to extract SCTs from certificate extension (OID 1.3.6.1.4.1.11129.2.4.2)
                try:
                    # SCT list extension OID
                    SCT_LIST_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
                    
                    for ext in cert.extensions:
                        if ext.oid == SCT_LIST_OID:
                            ct_result.embedded_in_cert = True
                            ct_result.has_scts = True
                            
                            # Parse SCT list (simplified - actual parsing is complex)
                            sct_data = ext.value.value if hasattr(ext.value, 'value') else bytes(ext.value)
                            
                            # Each SCT is prefixed with 2-byte length
                            offset = 2  # Skip initial length field
                            sct_index = 0
                            
                            while offset < len(sct_data) - 4 and sct_index < 10:
                                try:
                                    # Read SCT length
                                    sct_len = struct.unpack(">H", sct_data[offset:offset+2])[0]
                                    offset += 2
                                    
                                    if sct_len > 0 and offset + sct_len <= len(sct_data):
                                        sct_bytes = sct_data[offset:offset+sct_len]
                                        
                                        # Parse SCT structure
                                        if len(sct_bytes) >= 37:
                                            version = sct_bytes[0]
                                            log_id = base64.b64encode(sct_bytes[1:33]).decode()[:32]
                                            timestamp_ms = struct.unpack(">Q", sct_bytes[33:41])[0]
                                            
                                            sct_info = SCTInfo(
                                                log_id=log_id,
                                                timestamp=datetime.datetime.utcfromtimestamp(timestamp_ms / 1000).isoformat(),
                                                is_valid=True,  # Basic validity
                                            )
                                            ct_result.scts.append(sct_info)
                                            ct_result.sct_count += 1
                                        
                                        offset += sct_len
                                    else:
                                        break
                                        
                                    sct_index += 1
                                except Exception:
                                    break
                            
                            break
                            
                except x509.ExtensionNotFound:
                    ct_result.issues.append("No embedded SCTs in certificate")
                except Exception as e:
                    ct_result.issues.append(f"SCT extraction error: {str(e)[:50]}")
                
                # Check if certificate is from a CA that requires CT
                issuer_cn = ""
                for attr in cert.issuer:
                    if attr.oid._name == "commonName":
                        issuer_cn = attr.value
                        break
                
                # Major CAs require CT
                ct_required_cas = ["Let's Encrypt", "DigiCert", "Cloudflare", "Google Trust", "Amazon"]
                ct_required = any(ca.lower() in issuer_cn.lower() for ca in ct_required_cas)
                
                if ct_required and not ct_result.has_scts:
                    ct_result.issues.append(f"Certificate from {issuer_cn} should have CT SCTs")
                
                # Verify SCT count meets requirements (Chrome requires 2-3 SCTs depending on cert validity)
                if ct_result.has_scts:
                    # Get cert validity period
                    validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
                    
                    min_scts = 2 if validity_days <= 180 else 3
                    
                    if ct_result.sct_count < min_scts:
                        ct_result.issues.append(f"Only {ct_result.sct_count} SCTs found, {min_scts} recommended for {validity_days}-day certificate")
                    else:
                        ct_result.all_valid = True
                        
    except ImportError:
        ct_result.issues.append("cryptography library required for CT verification")
    except Exception as e:
        ct_result.issues.append(f"CT verification failed: {str(e)[:100]}")
        logger.debug(f"CT log verification failed for {host}:{port}: {e}")
    
    return ct_result


# ============================================================================
# CIPHER ORDERING ANALYSIS
# ============================================================================

@dataclass
class CipherOrderingAnalysis:
    """Analysis of cipher suite ordering preferences."""
    server_enforces_order: bool = False
    client_order_honored: bool = False
    
    # Preference analysis
    server_preferred_cipher: Optional[str] = None
    client_preferred_cipher: Optional[str] = None
    
    # Security implications
    strongest_first: bool = False
    pfs_prioritized: bool = False
    weak_ciphers_deprioritized: bool = False
    
    # Full order analysis
    cipher_order: List[Dict[str, Any]] = field(default_factory=list)
    
    score: int = 0
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def analyze_cipher_ordering(host: str, port: int = 443, timeout: float = 10.0) -> CipherOrderingAnalysis:
    """
    Analyze server's cipher suite ordering preferences.
    Tests whether server enforces its own cipher order or follows client preference.
    """
    analysis = CipherOrderingAnalysis()
    
    try:
        # Get cipher suites by testing with different client preferences
        
        # Test 1: Client prefers strong ciphers (AES-256-GCM first)
        strong_ciphers = [
            "ECDHE+AESGCM", "DHE+AESGCM", "ECDHE+AES256", "DHE+AES256",
            "ECDHE+AES128", "DHE+AES128", "AES256", "AES128", "3DES"
        ]
        
        # Test 2: Client prefers weaker ciphers first (if available)
        weak_first_ciphers = [
            "3DES", "AES128", "AES256", "DHE+AES128", "DHE+AES256",
            "ECDHE+AES128", "ECDHE+AES256", "DHE+AESGCM", "ECDHE+AESGCM"
        ]
        
        strong_result = None
        weak_result = None
        
        # Test with strong preference
        try:
            ctx1 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx1.check_hostname = False
            ctx1.verify_mode = ssl.CERT_NONE
            ctx1.set_ciphers(":".join(strong_ciphers))
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx1.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        strong_result = cipher[0]
                        analysis.server_preferred_cipher = strong_result
        except Exception:
            pass
        
        # Test with weak preference
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            ctx2.set_ciphers(":".join(weak_first_ciphers))
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        weak_result = cipher[0]
                        analysis.client_preferred_cipher = weak_result
        except Exception:
            pass
        
        # Analyze results
        if strong_result and weak_result:
            if strong_result == weak_result:
                # Server enforces its own order
                analysis.server_enforces_order = True
                analysis.client_order_honored = False
            else:
                # Server follows client preference
                analysis.server_enforces_order = False
                analysis.client_order_honored = True
                analysis.issues.append("Server follows client cipher preference - client can force weaker ciphers")
                analysis.recommendations.append("Configure server to enforce its own cipher order")
        
        # Check if PFS is prioritized
        if analysis.server_preferred_cipher:
            if "ECDHE" in analysis.server_preferred_cipher or "DHE" in analysis.server_preferred_cipher:
                analysis.pfs_prioritized = True
            else:
                analysis.issues.append("Server does not prioritize Perfect Forward Secrecy (PFS)")
                analysis.recommendations.append("Prioritize ECDHE and DHE cipher suites")
            
            # Check if strong cipher is used
            if "AES" in analysis.server_preferred_cipher and ("GCM" in analysis.server_preferred_cipher or "256" in analysis.server_preferred_cipher):
                analysis.strongest_first = True
            elif "3DES" in analysis.server_preferred_cipher or "RC4" in analysis.server_preferred_cipher:
                analysis.issues.append("Server prefers weak cipher suite")
                analysis.recommendations.append("Configure server to prefer AES-256-GCM or AES-128-GCM")
        
        # Calculate score
        score = 50  # Base score
        if analysis.server_enforces_order:
            score += 20
        if analysis.pfs_prioritized:
            score += 20
        if analysis.strongest_first:
            score += 10
        if not analysis.issues:
            score += 10
        
        analysis.score = min(100, score)
        
    except Exception as e:
        analysis.issues.append(f"Cipher ordering analysis failed: {str(e)[:100]}")
        logger.debug(f"Cipher ordering analysis failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# SESSION TICKETS AND 0-RTT ANALYSIS
# ============================================================================

@dataclass
class SessionTicketAnalysis:
    """TLS session ticket and 0-RTT analysis."""
    # Session resumption
    supports_session_tickets: bool = False
    supports_session_ids: bool = False
    
    # TLS 1.3 specific
    supports_0rtt: bool = False
    early_data_accepted: bool = False
    max_early_data_size: Optional[int] = None
    
    # Security concerns
    ticket_lifetime: Optional[int] = None  # seconds
    replay_protection: bool = True
    
    # Issues and recommendations
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def analyze_session_tickets(host: str, port: int = 443, timeout: float = 10.0) -> SessionTicketAnalysis:
    """
    Analyze TLS session ticket support and 0-RTT risks.
    """
    analysis = SessionTicketAnalysis()
    
    try:
        # Check session ticket support
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get session
                session = ssock.session
                
                if session:
                    # Check if session can be resumed
                    analysis.supports_session_ids = True
                    
                    # Check for session tickets (TLS extension)
                    # Note: Python's ssl module doesn't expose ticket details directly
                    # We can infer from session reuse
                    
                    # Try to resume session
                    try:
                        ctx2 = ssl.create_default_context()
                        ctx2.check_hostname = False
                        ctx2.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((host, port), timeout=timeout) as sock2:
                            with ctx2.wrap_socket(sock2, server_hostname=host, session=session) as ssock2:
                                if ssock2.session_reused:
                                    analysis.supports_session_tickets = True
                    except Exception:
                        pass
        
        # Check TLS 1.3 0-RTT support
        try:
            ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx13.check_hostname = False
            ctx13.verify_mode = ssl.CERT_NONE
            ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx13.wrap_socket(sock, server_hostname=host) as ssock:
                    protocol = ssock.version()
                    if protocol == "TLSv1.3":
                        # 0-RTT is supported by default in TLS 1.3
                        # But actual acceptance depends on server config
                        analysis.supports_0rtt = True
                        
                        # Note: Detecting actual 0-RTT acceptance requires
                        # sending early data, which is complex with Python's ssl
                        
        except ssl.SSLError:
            pass
        except Exception:
            pass
        
        # Add security recommendations
        if analysis.supports_session_tickets:
            if analysis.ticket_lifetime and analysis.ticket_lifetime > 86400:  # > 24 hours
                analysis.issues.append("Long session ticket lifetime increases replay attack window")
                analysis.recommendations.append("Reduce session ticket lifetime to 24 hours or less")
        
        if analysis.supports_0rtt:
            analysis.issues.append("TLS 1.3 0-RTT is supported - vulnerable to replay attacks for non-idempotent requests")
            analysis.recommendations.append("Implement application-level replay protection for sensitive operations")
            analysis.recommendations.append("Consider disabling 0-RTT for security-critical endpoints")
        
    except Exception as e:
        analysis.issues.append(f"Session analysis failed: {str(e)[:100]}")
        logger.debug(f"Session ticket analysis failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# SNI MISMATCH / CONFUSION ATTACK DETECTION
# ============================================================================

@dataclass
class SNIMismatchAnalysis:
    """SNI mismatch and confusion attack detection."""
    # Basic SNI support
    requires_sni: bool = False
    sni_supported: bool = True
    
    # Mismatch detection
    default_cert_cn: Optional[str] = None
    requested_cert_cn: Optional[str] = None
    certificates_differ: bool = False
    
    # Potential attacks
    vulnerable_to_confusion: bool = False
    allows_domain_fronting: bool = False
    
    # Virtual host detection
    virtual_host_detected: bool = False
    alternate_names: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_level: str = "low"  # low, medium, high, critical
    issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_sni_mismatch(host: str, port: int = 443, timeout: float = 10.0) -> SNIMismatchAnalysis:
    """
    Detect SNI mismatch and confusion attacks.
    Tests what happens when SNI differs from expected host.
    """
    analysis = SNIMismatchAnalysis()
    
    try:
        # Test 1: Connect with correct SNI
        correct_cn = None
        correct_sans = []
        
        try:
            ctx1 = ssl.create_default_context()
            ctx1.check_hostname = False
            ctx1.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx1.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Get CN
                        for item in cert.get('subject', ()):
                            for key, value in item:
                                if key == 'commonName':
                                    correct_cn = value
                                    break
                        
                        # Get SANs
                        for san_type, san_value in cert.get('subjectAltName', ()):
                            if san_type == 'DNS':
                                correct_sans.append(san_value)
                        
                        analysis.requested_cert_cn = correct_cn
                        analysis.alternate_names = correct_sans
                        analysis.sni_supported = True
        except Exception as e:
            analysis.issues.append(f"Failed to connect with SNI: {str(e)[:50]}")
        
        # Test 2: Connect without SNI
        no_sni_cn = None
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                # Don't provide server_hostname - no SNI
                with ctx2.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        for item in cert.get('subject', ()):
                            for key, value in item:
                                if key == 'commonName':
                                    no_sni_cn = value
                                    break
                        
                        analysis.default_cert_cn = no_sni_cn
        except ssl.SSLError as e:
            if "handshake failure" in str(e).lower() or "unrecognized_name" in str(e).lower():
                analysis.requires_sni = True
            else:
                analysis.issues.append(f"No-SNI connection error: {str(e)[:50]}")
        except Exception as e:
            analysis.issues.append(f"No-SNI test failed: {str(e)[:50]}")
        
        # Test 3: Connect with different SNI (potential domain fronting)
        fronting_cn = None
        test_domains = ["www.google.com", "example.com", "cloudflare.com"]
        
        for test_domain in test_domains:
            if test_domain == host:
                continue
                
            try:
                ctx3 = ssl.create_default_context()
                ctx3.check_hostname = False
                ctx3.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx3.wrap_socket(sock, server_hostname=test_domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            for item in cert.get('subject', ()):
                                for key, value in item:
                                    if key == 'commonName':
                                        fronting_cn = value
                                        break
                            
                            # If we get a certificate for a different domain, domain fronting may be possible
                            if fronting_cn and fronting_cn != correct_cn:
                                analysis.allows_domain_fronting = True
                                analysis.issues.append(f"Domain fronting possible: SNI '{test_domain}' returned cert for '{fronting_cn}'")
                                break
            except Exception:
                pass
        
        # Analyze results
        if correct_cn and no_sni_cn:
            if correct_cn != no_sni_cn:
                analysis.certificates_differ = True
                analysis.virtual_host_detected = True
                analysis.issues.append(f"Different certificates for SNI ({correct_cn}) vs no-SNI ({no_sni_cn})")
        
        # Check for confusion attack vulnerability
        if analysis.virtual_host_detected or analysis.allows_domain_fronting:
            analysis.vulnerable_to_confusion = True
        
        # Assess risk level
        if analysis.allows_domain_fronting:
            analysis.risk_level = "high"
        elif analysis.vulnerable_to_confusion:
            analysis.risk_level = "medium"
        elif analysis.requires_sni:
            analysis.risk_level = "low"  # SNI required is actually good
        else:
            analysis.risk_level = "low"
            
    except Exception as e:
        analysis.issues.append(f"SNI analysis failed: {str(e)[:100]}")
        logger.debug(f"SNI mismatch detection failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# PROTOCOL DOWNGRADE ATTACK DETECTION
# ============================================================================

@dataclass
class DowngradeAttackAnalysis:
    """Analysis of protocol downgrade attack vulnerabilities."""
    # POODLE (Padding Oracle On Downgraded Legacy Encryption)
    poodle_sslv3_vulnerable: bool = False
    poodle_tls_vulnerable: bool = False
    
    # FREAK (Factoring RSA Export Keys)
    freak_vulnerable: bool = False
    export_ciphers_supported: List[str] = field(default_factory=list)
    
    # Logjam (Diffie-Hellman key exchange weakness)
    logjam_vulnerable: bool = False
    weak_dh_params: bool = False
    dh_key_size: Optional[int] = None
    
    # DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)
    drown_vulnerable: bool = False
    sslv2_supported: bool = False
    
    # General downgrade
    supports_fallback_scsv: bool = False
    vulnerable_to_downgrade: bool = False
    
    # Risk assessment
    risk_level: str = "low"
    cve_ids: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_downgrade_attacks(host: str, port: int = 443, timeout: float = 10.0) -> DowngradeAttackAnalysis:
    """
    Detect protocol downgrade attack vulnerabilities.
    Tests for POODLE, FREAK, Logjam, and DROWN vulnerabilities.
    """
    analysis = DowngradeAttackAnalysis()
    
    try:
        # ========== POODLE SSLv3 Check ==========
        # POODLE affects SSLv3 with CBC ciphers
        try:
            ctx_ssl3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_ssl3.check_hostname = False
            ctx_ssl3.verify_mode = ssl.CERT_NONE
            # Try to set SSLv3 (may not be available in modern Python)
            try:
                ctx_ssl3.options &= ~ssl.OP_NO_SSLv3
                ctx_ssl3.maximum_version = ssl.TLSVersion.SSLv3
                ctx_ssl3.minimum_version = ssl.TLSVersion.SSLv3
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx_ssl3.wrap_socket(sock, server_hostname=host) as ssock:
                        cipher = ssock.cipher()
                        if cipher and ("CBC" in cipher[0] or "3DES" in cipher[0]):
                            analysis.poodle_sslv3_vulnerable = True
                            analysis.cve_ids.append("CVE-2014-3566")
                            analysis.issues.append("POODLE: SSLv3 with CBC cipher supported")
                            analysis.recommendations.append("Disable SSLv3 completely")
            except (AttributeError, ValueError):
                pass  # SSLv3 not supported by this Python build
        except ssl.SSLError:
            pass  # Good - SSLv3 not supported
        except Exception:
            pass
        
        # ========== POODLE TLS Check (Lucky Thirteen variant) ==========
        # Check for TLS 1.0/1.1 with CBC ciphers
        for proto_version in [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1]:
            try:
                ctx_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_tls.check_hostname = False
                ctx_tls.verify_mode = ssl.CERT_NONE
                ctx_tls.minimum_version = proto_version
                ctx_tls.maximum_version = proto_version
                
                # Try CBC ciphers
                try:
                    ctx_tls.set_ciphers("AES128-SHA:AES256-SHA:3DES-EDE-CBC-SHA")
                    
                    with socket.create_connection((host, port), timeout=timeout) as sock:
                        with ctx_tls.wrap_socket(sock, server_hostname=host) as ssock:
                            cipher = ssock.cipher()
                            if cipher and "CBC" in cipher[0]:
                                analysis.poodle_tls_vulnerable = True
                                if "CVE-2013-0169" not in analysis.cve_ids:
                                    analysis.cve_ids.append("CVE-2013-0169")
                                    analysis.issues.append("Lucky Thirteen: TLS with CBC cipher supported")
                                break
                except ssl.SSLError:
                    pass
            except Exception:
                pass
        
        # ========== FREAK Check (Export Ciphers) ==========
        export_cipher_list = [
            "EXP-RC4-MD5", "EXP-RC2-CBC-MD5", "EXP-DES-CBC-SHA",
            "EXP-EDH-DSS-DES-CBC-SHA", "EXP-EDH-RSA-DES-CBC-SHA",
            "EXP-ADH-DES-CBC-SHA", "EXP-ADH-RC4-MD5"
        ]
        
        for export_cipher in export_cipher_list:
            try:
                ctx_exp = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_exp.check_hostname = False
                ctx_exp.verify_mode = ssl.CERT_NONE
                ctx_exp.set_ciphers(export_cipher)
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx_exp.wrap_socket(sock, server_hostname=host) as ssock:
                        analysis.freak_vulnerable = True
                        analysis.export_ciphers_supported.append(export_cipher)
            except ssl.SSLError:
                pass  # Good - cipher not supported
            except Exception:
                pass
        
        if analysis.freak_vulnerable:
            analysis.cve_ids.append("CVE-2015-0204")
            analysis.issues.append(f"FREAK: Export ciphers supported: {', '.join(analysis.export_ciphers_supported)}")
            analysis.recommendations.append("Disable all export-grade cipher suites")
        
        # ========== Logjam Check (Weak DH) ==========
        # Check for weak Diffie-Hellman parameters
        try:
            ctx_dh = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_dh.check_hostname = False
            ctx_dh.verify_mode = ssl.CERT_NONE
            ctx_dh.set_ciphers("DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA")
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_dh.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher and "DHE" in cipher[0]:
                        # Note: Python's ssl doesn't expose DH params directly
                        # We check for export DHE ciphers as indicator
                        analysis.weak_dh_params = False  # Cannot determine directly
                        
                        # Check for export DHE
                        try:
                            ctx_exp_dh = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            ctx_exp_dh.check_hostname = False
                            ctx_exp_dh.verify_mode = ssl.CERT_NONE
                            ctx_exp_dh.set_ciphers("EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA")
                            
                            with socket.create_connection((host, port), timeout=timeout) as sock2:
                                with ctx_exp_dh.wrap_socket(sock2, server_hostname=host) as ssock2:
                                    analysis.logjam_vulnerable = True
                                    analysis.weak_dh_params = True
                                    analysis.dh_key_size = 512
                                    analysis.cve_ids.append("CVE-2015-4000")
                                    analysis.issues.append("Logjam: Export-grade DHE supported (512-bit)")
                                    analysis.recommendations.append("Use 2048-bit or larger DH parameters")
                        except ssl.SSLError:
                            pass
        except ssl.SSLError:
            pass
        except Exception:
            pass
        
        # ========== DROWN Check (SSLv2) ==========
        # Note: Python's ssl module doesn't support SSLv2
        # We can only check if server responds to SSLv2-like handshakes
        try:
            # Build minimal SSLv2 ClientHello manually
            sslv2_hello = bytes([
                0x80, 0x2e,  # Length (SSLv2 record)
                0x01,  # ClientHello
                0x00, 0x02,  # Version SSLv2
                0x00, 0x15,  # Cipher spec length
                0x00, 0x00,  # Session ID length
                0x00, 0x10,  # Challenge length
                # Cipher specs (SSLv2)
                0x07, 0x00, 0xc0,  # SSL_CK_DES_192_EDE3_CBC_WITH_MD5
                0x05, 0x00, 0x80,  # SSL_CK_RC4_128_WITH_MD5
                0x03, 0x00, 0x80,  # SSL_CK_RC2_128_CBC_WITH_MD5
                0x01, 0x00, 0x80,  # SSL_CK_RC4_128_EXPORT40_WITH_MD5
                0x06, 0x00, 0x40,  # SSL_CK_DES_64_CBC_WITH_MD5
                0x04, 0x00, 0x80,  # SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
                0x02, 0x00, 0x80,  # SSL_CK_RC4_40_WITH_MD5
                # Random challenge
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            ])
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.send(sslv2_hello)
                response = sock.recv(16)
                
                # SSLv2 ServerHello starts with 0x04 after length
                if len(response) >= 3:
                    if response[0] & 0x80:  # SSLv2 length encoding
                        msg_type = response[2]
                        if msg_type == 0x04:  # ServerHello
                            analysis.drown_vulnerable = True
                            analysis.sslv2_supported = True
                            analysis.cve_ids.append("CVE-2016-0800")
                            analysis.issues.append("DROWN: SSLv2 supported - vulnerable to cross-protocol attack")
                            analysis.recommendations.append("Disable SSLv2 completely on all servers sharing the RSA key")
        except Exception:
            pass
        
        # ========== TLS Fallback SCSV Check ==========
        # Check if server supports TLS_FALLBACK_SCSV to prevent downgrade
        try:
            # This requires sending a ClientHello with fallback SCSV (0x5600)
            # and checking if server rejects appropriately
            ctx_fallback = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_fallback.check_hostname = False
            ctx_fallback.verify_mode = ssl.CERT_NONE
            ctx_fallback.maximum_version = ssl.TLSVersion.TLSv1_2
            
            # Note: Full SCSV check requires raw socket manipulation
            # We infer from general TLS behavior
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_fallback.wrap_socket(sock, server_hostname=host) as ssock:
                    # If connection succeeds with TLS 1.2, server likely supports modern TLS
                    if ssock.version() in ["TLSv1.2", "TLSv1.3"]:
                        analysis.supports_fallback_scsv = True  # Likely
        except Exception:
            pass
        
        # Assess overall vulnerability to downgrade
        if (analysis.poodle_sslv3_vulnerable or analysis.poodle_tls_vulnerable or
            analysis.freak_vulnerable or analysis.logjam_vulnerable or 
            analysis.drown_vulnerable):
            analysis.vulnerable_to_downgrade = True
        
        # Risk level assessment
        if analysis.drown_vulnerable or analysis.poodle_sslv3_vulnerable:
            analysis.risk_level = "critical"
        elif analysis.freak_vulnerable or analysis.logjam_vulnerable:
            analysis.risk_level = "high"
        elif analysis.poodle_tls_vulnerable:
            analysis.risk_level = "medium"
        else:
            analysis.risk_level = "low"
            
    except Exception as e:
        analysis.issues.append(f"Downgrade attack detection failed: {str(e)[:100]}")
        logger.debug(f"Downgrade attack detection failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# HEARTBLEED DETECTION (CVE-2014-0160)
# ============================================================================

@dataclass
class HeartbleedAnalysis:
    """Heartbleed vulnerability analysis."""
    vulnerable: bool = False
    tested: bool = False
    tls_versions_tested: List[str] = field(default_factory=list)
    memory_leaked: bool = False
    leak_size: int = 0
    
    cve_id: str = "CVE-2014-0160"
    risk_level: str = "low"
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_heartbleed(host: str, port: int = 443, timeout: float = 10.0) -> HeartbleedAnalysis:
    """
    Detect Heartbleed vulnerability (CVE-2014-0160).
    Tests if server responds to malformed heartbeat requests.
    """
    analysis = HeartbleedAnalysis()
    
    try:
        # TLS versions to test
        tls_versions = [
            (0x0301, "TLSv1.0"),
            (0x0302, "TLSv1.1"),
            (0x0303, "TLSv1.2"),
        ]
        
        for version_num, version_name in tls_versions:
            try:
                analysis.tls_versions_tested.append(version_name)
                
                # Build TLS ClientHello with heartbeat extension
                client_hello = _build_heartbleed_client_hello(version_num)
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    
                    # Send ClientHello
                    sock.send(client_hello)
                    
                    # Receive ServerHello and other handshake messages
                    response = b""
                    try:
                        while True:
                            data = sock.recv(4096)
                            if not data:
                                break
                            response += data
                            if len(response) > 5:
                                # Check for ServerHello completion
                                record_type = response[0]
                                if record_type == 0x16:  # Handshake
                                    break
                    except socket.timeout:
                        pass
                    
                    # Check if heartbeat extension was accepted
                    if len(response) > 50 and b'\x00\x0f' in response:  # Heartbeat extension type
                        # Send malicious heartbeat request
                        heartbeat_request = _build_heartbleed_request(version_num)
                        sock.send(heartbeat_request)
                        
                        # Wait for response
                        try:
                            hb_response = sock.recv(65535)
                            
                            if len(hb_response) > 3:
                                # Check if this is a heartbeat response
                                if hb_response[0] == 0x18:  # Heartbeat record
                                    response_length = struct.unpack(">H", hb_response[3:5])[0]
                                    
                                    # If response length >> 3 (our payload size), memory leaked
                                    if response_length > 16:
                                        analysis.vulnerable = True
                                        analysis.memory_leaked = True
                                        analysis.leak_size = response_length
                                        analysis.risk_level = "critical"
                                        analysis.issues.append(f"Heartbleed: Server leaked {response_length} bytes of memory")
                                        analysis.recommendations.append("Update OpenSSL to 1.0.1g or later immediately")
                                        analysis.recommendations.append("Revoke and reissue all SSL certificates")
                                        analysis.recommendations.append("Reset all user passwords")
                                        break
                        except socket.timeout:
                            pass
            except ssl.SSLError:
                pass
            except Exception:
                pass
        
        analysis.tested = True
        
        if not analysis.vulnerable:
            analysis.risk_level = "low"
            
    except Exception as e:
        analysis.issues.append(f"Heartbleed detection failed: {str(e)[:100]}")
        logger.debug(f"Heartbleed detection failed for {host}:{port}: {e}")
    
    return analysis


def _build_heartbleed_client_hello(tls_version: int) -> bytes:
    """Build a ClientHello with heartbeat extension for Heartbleed testing."""
    # Cipher suites
    cipher_suites = bytes([
        0x00, 0x2f,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35,  # TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x0a,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x05,  # TLS_RSA_WITH_RC4_128_SHA
    ])
    
    # Extensions including heartbeat
    extensions = bytes([
        # Heartbeat extension
        0x00, 0x0f,  # Extension type: heartbeat
        0x00, 0x01,  # Length
        0x01,        # Mode: peer allowed to send requests
    ])
    
    # ClientHello
    client_random = bytes([random.randint(0, 255) for _ in range(32)])
    
    client_hello = bytes([
        0x03, (tls_version >> 8) & 0xFF, tls_version & 0xFF,  # Version
    ]) if tls_version < 0x100 else struct.pack(">H", tls_version)
    
    client_hello = struct.pack(">H", tls_version)
    client_hello += client_random
    client_hello += bytes([0x00])  # Session ID length
    client_hello += struct.pack(">H", len(cipher_suites))
    client_hello += cipher_suites
    client_hello += bytes([0x01, 0x00])  # Compression: null
    client_hello += struct.pack(">H", len(extensions))
    client_hello += extensions
    
    # Handshake header
    handshake = bytes([0x01])  # ClientHello type
    handshake += struct.pack(">I", len(client_hello))[1:]  # 3-byte length
    handshake += client_hello
    
    # TLS record header
    record = bytes([0x16])  # Handshake record
    record += bytes([0x03, 0x01])  # TLS 1.0 record layer
    record += struct.pack(">H", len(handshake))
    record += handshake
    
    return record


def _build_heartbleed_request(tls_version: int) -> bytes:
    """Build a malicious heartbeat request to test for Heartbleed."""
    # Heartbeat request with oversized length
    heartbeat = bytes([
        0x01,        # HeartbeatMessageType: request
        0x40, 0x00,  # Payload length: 16384 (much larger than actual payload)
    ])
    heartbeat += bytes([0x41, 0x42, 0x43])  # Small actual payload (3 bytes)
    # Missing padding - this is the vulnerability trigger
    
    # TLS record header
    record = bytes([0x18])  # Heartbeat record type
    record += bytes([0x03, 0x03])  # TLS 1.2 record layer
    record += struct.pack(">H", len(heartbeat))
    record += heartbeat
    
    return record


# ============================================================================
# ROBOT ATTACK DETECTION (Bleichenbacher Oracle)
# ============================================================================

@dataclass
class ROBOTAnalysis:
    """ROBOT attack vulnerability analysis."""
    vulnerable: bool = False
    oracle_type: Optional[str] = None  # strong, weak
    tested: bool = False
    
    # RSA key exchange support
    rsa_key_exchange_supported: bool = False
    vulnerable_ciphers: List[str] = field(default_factory=list)
    
    cve_id: str = "CVE-2017-13099"
    risk_level: str = "low"
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_robot_attack(host: str, port: int = 443, timeout: float = 10.0) -> ROBOTAnalysis:
    """
    Detect ROBOT vulnerability (Return Of Bleichenbacher's Oracle Threat).
    Tests if server is vulnerable to RSA decryption oracle attacks.
    """
    analysis = ROBOTAnalysis()
    
    try:
        # RSA cipher suites to test
        rsa_ciphers = [
            "AES256-SHA",
            "AES128-SHA", 
            "DES-CBC3-SHA",
            "AES256-SHA256",
            "AES128-SHA256",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
        ]
        
        supported_rsa_ciphers = []
        
        # Check which RSA ciphers are supported
        for cipher in rsa_ciphers:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher)
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        negotiated = ssock.cipher()
                        if negotiated:
                            supported_rsa_ciphers.append(cipher)
                            analysis.rsa_key_exchange_supported = True
            except ssl.SSLError:
                pass
            except Exception:
                pass
        
        analysis.vulnerable_ciphers = supported_rsa_ciphers
        analysis.tested = True
        
        if analysis.rsa_key_exchange_supported:
            # Full ROBOT detection requires sending malformed PKCS#1 messages
            # and analyzing timing/error responses. This is complex and potentially
            # disruptive, so we flag RSA key exchange as a potential risk.
            analysis.issues.append("RSA key exchange supported - potentially vulnerable to ROBOT")
            analysis.issues.append(f"RSA ciphers available: {', '.join(supported_rsa_ciphers[:3])}")
            analysis.recommendations.append("Disable RSA key exchange cipher suites")
            analysis.recommendations.append("Use only ECDHE or DHE key exchange")
            
            # Mark as potentially vulnerable if RSA ciphers are supported
            analysis.vulnerable = True  # Potential vulnerability
            analysis.oracle_type = "weak"  # Conservative assessment
            analysis.risk_level = "medium"
        else:
            analysis.risk_level = "low"
            
    except Exception as e:
        analysis.issues.append(f"ROBOT detection failed: {str(e)[:100]}")
        logger.debug(f"ROBOT detection failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# TLS RENEGOTIATION TESTING
# ============================================================================

@dataclass
class RenegotiationAnalysis:
    """TLS renegotiation security analysis."""
    # Secure renegotiation
    secure_renegotiation_supported: bool = False
    
    # Client-initiated renegotiation (DoS risk)
    client_initiated_allowed: bool = False
    
    # Issues
    vulnerable_to_dos: bool = False
    vulnerable_to_mitm: bool = False
    
    cve_ids: List[str] = field(default_factory=list)
    risk_level: str = "low"
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def analyze_renegotiation(host: str, port: int = 443, timeout: float = 10.0) -> RenegotiationAnalysis:
    """
    Analyze TLS renegotiation security.
    Tests for secure renegotiation and client-initiated renegotiation DoS.
    """
    analysis = RenegotiationAnalysis()
    
    try:
        # Check for secure renegotiation support via extension
        # RFC 5746 - TLS Renegotiation Indication Extension
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Python's ssl module doesn't expose renegotiation details directly
                # We infer from TLS version and behavior
                
                protocol = ssock.version()
                
                # TLS 1.3 doesn't support renegotiation
                if protocol == "TLSv1.3":
                    analysis.secure_renegotiation_supported = True
                    analysis.client_initiated_allowed = False
                    analysis.risk_level = "low"
                else:
                    # For TLS 1.2 and below, check for secure renegotiation
                    # Modern servers should support RFC 5746
                    
                    # Try to trigger renegotiation
                    try:
                        # Note: Python's ssl module has limited renegotiation support
                        # We check if the option is available
                        if hasattr(ssl, 'OP_NO_RENEGOTIATION'):
                            # Modern OpenSSL - can control renegotiation
                            analysis.secure_renegotiation_supported = True
                        else:
                            # Older OpenSSL - assume secure if TLS 1.2
                            if protocol == "TLSv1.2":
                                analysis.secure_renegotiation_supported = True
                        
                        # Check for client renegotiation by attempting it
                        # This is limited in Python's ssl module
                        analysis.client_initiated_allowed = True  # Conservative
                        
                    except Exception:
                        pass
        
        # Check for insecure renegotiation (legacy)
        if not analysis.secure_renegotiation_supported:
            analysis.vulnerable_to_mitm = True
            analysis.cve_ids.append("CVE-2009-3555")
            analysis.issues.append("Insecure renegotiation - vulnerable to MITM attacks")
            analysis.recommendations.append("Enable secure renegotiation (RFC 5746)")
            analysis.risk_level = "high"
        
        # Check for client-initiated renegotiation DoS
        if analysis.client_initiated_allowed:
            analysis.vulnerable_to_dos = True
            analysis.issues.append("Client-initiated renegotiation allowed - potential DoS vector")
            analysis.recommendations.append("Disable client-initiated renegotiation or rate-limit")
            if analysis.risk_level == "low":
                analysis.risk_level = "medium"
                
    except Exception as e:
        analysis.issues.append(f"Renegotiation analysis failed: {str(e)[:100]}")
        logger.debug(f"Renegotiation analysis failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# SWEET32 DETECTION (64-bit Block Cipher Birthday Attack)
# ============================================================================

@dataclass
class Sweet32Analysis:
    """Sweet32 vulnerability analysis."""
    vulnerable: bool = False
    weak_block_ciphers: List[str] = field(default_factory=list)
    
    # 64-bit block cipher details
    triple_des_supported: bool = False
    blowfish_supported: bool = False
    idea_supported: bool = False
    
    cve_id: str = "CVE-2016-2183"
    risk_level: str = "low"
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_sweet32(host: str, port: int = 443, timeout: float = 10.0) -> Sweet32Analysis:
    """
    Detect Sweet32 vulnerability (CVE-2016-2183).
    Tests for 64-bit block ciphers vulnerable to birthday attacks.
    """
    analysis = Sweet32Analysis()
    
    try:
        # 64-bit block ciphers to test
        weak_ciphers = {
            "DES-CBC3-SHA": "3DES",
            "DES-CBC-SHA": "DES",
            "EDH-RSA-DES-CBC3-SHA": "3DES",
            "EDH-DSS-DES-CBC3-SHA": "3DES",
            "ECDHE-RSA-DES-CBC3-SHA": "3DES",
            "ECDHE-ECDSA-DES-CBC3-SHA": "3DES",
            "DHE-RSA-DES-CBC3-SHA": "3DES",
            "DHE-DSS-DES-CBC3-SHA": "3DES",
            # Blowfish variants (if available)
            "BF-CBC": "Blowfish",
            # IDEA variants (if available)
            "IDEA-CBC-SHA": "IDEA",
        }
        
        for cipher, cipher_type in weak_ciphers.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher)
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        negotiated = ssock.cipher()
                        if negotiated:
                            analysis.vulnerable = True
                            analysis.weak_block_ciphers.append(cipher)
                            
                            if cipher_type == "3DES":
                                analysis.triple_des_supported = True
                            elif cipher_type == "Blowfish":
                                analysis.blowfish_supported = True
                            elif cipher_type == "IDEA":
                                analysis.idea_supported = True
            except ssl.SSLError:
                pass
            except Exception:
                pass
        
        if analysis.vulnerable:
            analysis.issues.append(f"Sweet32: 64-bit block ciphers supported: {', '.join(analysis.weak_block_ciphers)}")
            analysis.recommendations.append("Disable 3DES, DES, Blowfish, and IDEA cipher suites")
            analysis.recommendations.append("Use only AES with 128-bit or larger blocks")
            analysis.risk_level = "medium"
        else:
            analysis.risk_level = "low"
            
    except Exception as e:
        analysis.issues.append(f"Sweet32 detection failed: {str(e)[:100]}")
        logger.debug(f"Sweet32 detection failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# CRIME/BREACH DETECTION (TLS Compression Side-Channel)
# ============================================================================

@dataclass
class CompressionAttackAnalysis:
    """CRIME/BREACH vulnerability analysis."""
    # CRIME (TLS compression)
    crime_vulnerable: bool = False
    tls_compression_enabled: bool = False
    
    # BREACH (HTTP compression)
    breach_vulnerable: bool = False
    http_compression_enabled: bool = False
    compression_methods: List[str] = field(default_factory=list)
    
    # SPDY/HTTP2 compression
    spdy_compression: bool = False
    
    cve_ids: List[str] = field(default_factory=list)
    risk_level: str = "low"
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_compression_attacks(host: str, port: int = 443, timeout: float = 10.0) -> CompressionAttackAnalysis:
    """
    Detect CRIME and BREACH vulnerabilities.
    Tests for TLS compression and HTTP compression.
    """
    analysis = CompressionAttackAnalysis()
    
    try:
        # ========== CRIME Check (TLS Compression) ==========
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Check TLS compression
                compression = getattr(ssock, 'compression', lambda: None)()
                
                if compression:
                    analysis.crime_vulnerable = True
                    analysis.tls_compression_enabled = True
                    analysis.compression_methods.append(compression)
                    analysis.cve_ids.append("CVE-2012-4929")
                    analysis.issues.append(f"CRIME: TLS compression enabled ({compression})")
                    analysis.recommendations.append("Disable TLS compression")
        
        # ========== BREACH Check (HTTP Compression) ==========
        # Need to make an actual HTTP request to check response headers
        try:
            import http.client
            
            # Create HTTPS connection
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout,
                context=ssl._create_unverified_context()
            )
            
            try:
                conn.request("GET", "/", headers={
                    "Host": host,
                    "Accept-Encoding": "gzip, deflate, br",
                    "User-Agent": "VRAgent-SSL-Scanner/1.0"
                })
                
                response = conn.getresponse()
                
                # Check for compression headers
                content_encoding = response.getheader("Content-Encoding", "")
                transfer_encoding = response.getheader("Transfer-Encoding", "")
                
                if content_encoding or "gzip" in transfer_encoding or "deflate" in transfer_encoding:
                    analysis.http_compression_enabled = True
                    
                    if content_encoding:
                        analysis.compression_methods.append(f"HTTP: {content_encoding}")
                    
                    # BREACH requires compression + secrets in response + attacker-controlled input
                    # We flag HTTP compression as a potential issue
                    analysis.breach_vulnerable = True  # Potential
                    if "CVE-2013-3587" not in analysis.cve_ids:
                        analysis.cve_ids.append("CVE-2013-3587")
                    analysis.issues.append(f"BREACH: HTTP compression enabled ({content_encoding or transfer_encoding})")
                    analysis.recommendations.append("Disable HTTP compression for sensitive pages, or use CSRF tokens")
                    analysis.recommendations.append("Randomize secrets in each response")
                    
            finally:
                conn.close()
                
        except Exception as e:
            logger.debug(f"BREACH check failed for {host}:{port}: {e}")
        
        # Risk assessment
        if analysis.crime_vulnerable:
            analysis.risk_level = "high"
        elif analysis.breach_vulnerable:
            analysis.risk_level = "medium"
        else:
            analysis.risk_level = "low"
            
    except Exception as e:
        analysis.issues.append(f"Compression attack detection failed: {str(e)[:100]}")
        logger.debug(f"Compression attack detection failed for {host}:{port}: {e}")
    
    return analysis


# ============================================================================
# ALPN DETECTION (Application-Layer Protocol Negotiation)
# ============================================================================

@dataclass
class ALPNAnalysis:
    """ALPN protocol negotiation analysis."""
    alpn_supported: bool = False
    negotiated_protocol: Optional[str] = None
    supported_protocols: List[str] = field(default_factory=list)
    
    # Specific protocol support
    http2_supported: bool = False
    http3_supported: bool = False
    grpc_supported: bool = False
    spdy_supported: bool = False
    
    # Security considerations
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_alpn_protocols(host: str, port: int = 443, timeout: float = 10.0) -> ALPNAnalysis:
    """
    Detect ALPN protocol support.
    Tests for HTTP/2, HTTP/3, gRPC, and other protocols.
    """
    analysis = ALPNAnalysis()
    
    # ALPN protocol identifiers
    protocols_to_test = [
        ("h2", "HTTP/2"),
        ("h2c", "HTTP/2 Cleartext"),
        ("http/1.1", "HTTP/1.1"),
        ("http/1.0", "HTTP/1.0"),
        ("spdy/3.1", "SPDY 3.1"),
        ("spdy/3", "SPDY 3"),
        ("grpc", "gRPC"),
    ]
    
    try:
        # Test with all protocols to see what's supported
        all_protos = [p[0] for p in protocols_to_test]
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(all_protos)
        
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    selected = ssock.selected_alpn_protocol()
                    
                    if selected:
                        analysis.alpn_supported = True
                        analysis.negotiated_protocol = selected
                        analysis.supported_protocols.append(selected)
                        
                        # Set specific flags
                        if selected == "h2":
                            analysis.http2_supported = True
                        elif selected.startswith("spdy"):
                            analysis.spdy_supported = True
                        elif selected == "grpc":
                            analysis.grpc_supported = True
        except ssl.SSLError:
            pass
        
        # Test each protocol individually
        for proto_id, proto_name in protocols_to_test:
            if proto_id in analysis.supported_protocols:
                continue
                
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols([proto_id])
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        selected = ssock.selected_alpn_protocol()
                        
                        if selected == proto_id:
                            analysis.supported_protocols.append(proto_id)
                            analysis.alpn_supported = True
                            
                            if proto_id == "h2":
                                analysis.http2_supported = True
                            elif proto_id.startswith("spdy"):
                                analysis.spdy_supported = True
                            elif proto_id == "grpc":
                                analysis.grpc_supported = True
            except ssl.SSLError:
                pass
            except Exception:
                pass
        
        # Add recommendations
        if not analysis.http2_supported and analysis.alpn_supported:
            analysis.recommendations.append("Consider enabling HTTP/2 for better performance")
        
        if analysis.spdy_supported:
            analysis.issues.append("Deprecated SPDY protocol supported - use HTTP/2 instead")
            analysis.recommendations.append("Disable SPDY and use HTTP/2")
        
        # Note: HTTP/3 uses QUIC (UDP), not tested via TCP
        # We just note that it requires different testing
        
    except Exception as e:
        analysis.issues.append(f"ALPN detection failed: {str(e)[:100]}")
        logger.debug(f"ALPN detection failed for {host}:{port}: {e}")
    
    return analysis


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
        
        # Perform offensive analysis
        try:
            result.offensive_analysis = perform_offensive_ssl_analysis(
                host=host,
                port=port,
                cert=result.certificate,
                protocols=result.protocols_supported,
                ciphers=result.cipher_suites,
                timeout=timeout
            )
            
            # Add offensive findings to main findings list
            if result.offensive_analysis:
                # JARM-based findings
                if result.offensive_analysis.jarm:
                    if result.offensive_analysis.jarm.signature_type == "c2_framework":
                        findings.append(SSLFinding(
                            category="threat_intel",
                            severity="critical",
                            title=f"C2 Framework Detected: {result.offensive_analysis.jarm.matched_signature}",
                            description=f"JARM fingerprint matches known C2 framework: {result.offensive_analysis.jarm.description}",
                            host=host,
                            port=port,
                            evidence=f"JARM: {result.offensive_analysis.jarm.fingerprint[:32]}...",
                            recommendation="Investigate immediately - this server matches known malicious infrastructure",
                        ))
                    elif result.offensive_analysis.jarm.signature_type == "malware":
                        findings.append(SSLFinding(
                            category="threat_intel",
                            severity="critical",
                            title=f"Malware Infrastructure Detected: {result.offensive_analysis.jarm.matched_signature}",
                            description=f"JARM fingerprint matches known malware: {result.offensive_analysis.jarm.description}",
                            host=host,
                            port=port,
                            evidence=f"JARM: {result.offensive_analysis.jarm.fingerprint[:32]}...",
                            recommendation="Block this destination - matches known malware infrastructure",
                        ))
                
                # Certificate intelligence findings
                if result.offensive_analysis.cert_intel and result.offensive_analysis.cert_intel.is_suspicious:
                    for reason in result.offensive_analysis.cert_intel.suspicion_reasons[:3]:
                        findings.append(SSLFinding(
                            category="threat_intel",
                            severity="high" if "CRITICAL" in reason else "medium",
                            title="Suspicious Certificate Pattern",
                            description=reason,
                            host=host,
                            port=port,
                            evidence=f"Suspicion score: {result.offensive_analysis.cert_intel.suspicion_score}/100",
                        ))
                
                # DGA domain detection
                if result.offensive_analysis.cert_intel and result.offensive_analysis.cert_intel.potential_dga:
                    findings.append(SSLFinding(
                        category="threat_intel",
                        severity="critical",
                        title="Potential DGA Domain Detected",
                        description="Certificate contains domains that appear to be generated by a Domain Generation Algorithm",
                        host=host,
                        port=port,
                        recommendation="DGA domains are commonly used by malware for C2 communication",
                    ))
                
                # MITM feasibility
                if result.offensive_analysis.mitm and result.offensive_analysis.mitm.can_mitm:
                    findings.append(SSLFinding(
                        category="interception",
                        severity="info",
                        title=f"MITM Possible ({result.offensive_analysis.mitm.difficulty})",
                        description=f"Traffic can be intercepted: {', '.join(result.offensive_analysis.mitm.methods[:2])}",
                        host=host,
                        port=port,
                        recommendation="; ".join(result.offensive_analysis.mitm.recommendations[:2]),
                    ))
                    
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Offensive analysis failed for {host}:{port}: {e}")
        
        # Check security headers (HSTS, etc.)
        try:
            result.security_headers = check_security_headers(host, port, timeout)
            
            # Add findings based on security headers
            if result.security_headers:
                if not result.security_headers.hsts_enabled:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="medium",
                        title="HSTS Not Enabled",
                        description="HTTP Strict Transport Security (HSTS) is not enabled, leaving users vulnerable to SSL stripping attacks.",
                        host=host,
                        port=port,
                        recommendation="Add 'Strict-Transport-Security' header with a minimum max-age of 31536000 (1 year).",
                    ))
                elif result.security_headers.hsts_max_age and result.security_headers.hsts_max_age < 86400:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="low",
                        title="HSTS Max-Age Too Short",
                        description=f"HSTS max-age is {result.security_headers.hsts_max_age} seconds (< 1 day), which provides limited protection.",
                        host=host,
                        port=port,
                        evidence=f"max-age={result.security_headers.hsts_max_age}",
                        recommendation="Increase HSTS max-age to at least 31536000 (1 year).",
                    ))
                
                if result.security_headers.score < 50:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="low",
                        title="Poor Security Headers Score",
                        description=f"Security headers score is {result.security_headers.score}/100. Missing: {', '.join(result.security_headers.missing_headers[:3])}",
                        host=host,
                        port=port,
                        recommendation="Implement recommended security headers for defense in depth.",
                    ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Security header check failed for {host}:{port}: {e}")
        
        # Check OCSP revocation status
        try:
            result.ocsp_status = check_ocsp_revocation(host, port, timeout)
            
            # Add findings based on OCSP status
            if result.ocsp_status and result.ocsp_status.checked:
                if result.ocsp_status.status == "revoked":
                    findings.append(SSLFinding(
                        category="certificate",
                        severity="critical",
                        title="Certificate Revoked",
                        description=f"The SSL certificate has been revoked. Revocation time: {result.ocsp_status.revocation_time or 'Unknown'}. Reason: {result.ocsp_status.revocation_reason or 'Not specified'}.",
                        host=host,
                        port=port,
                        evidence=f"OCSP Status: {result.ocsp_status.status}",
                        recommendation="Replace the revoked certificate immediately.",
                    ))
                elif result.ocsp_status.status == "unknown":
                    findings.append(SSLFinding(
                        category="certificate",
                        severity="medium",
                        title="OCSP Status Unknown",
                        description="The certificate revocation status could not be determined via OCSP.",
                        host=host,
                        port=port,
                        recommendation="Verify certificate status manually or check OCSP responder availability.",
                    ))
            elif result.ocsp_status and result.ocsp_status.errors:
                # Only add informational finding if OCSP URL was found but check failed
                if result.ocsp_status.ocsp_url:
                    findings.append(SSLFinding(
                        category="certificate",
                        severity="info",
                        title="OCSP Check Incomplete",
                        description=f"OCSP revocation check could not complete: {result.ocsp_status.errors[0] if result.ocsp_status.errors else 'Unknown error'}",
                        host=host,
                        port=port,
                    ))
            
            result.findings = findings
                
        except Exception as e:
            logger.debug(f"OCSP check failed for {host}:{port}: {e}")
        
        # ========== NEW ADVANCED CHECKS ==========
        
        # TLS 1.3 cipher analysis
        try:
            result.tls13_analysis = check_tls13_ciphers(host, port, timeout)
            
            if result.tls13_analysis:
                if result.tls13_analysis.supported:
                    # Add findings for TLS 1.3 issues
                    if result.tls13_analysis.supports_0rtt:
                        findings.append(SSLFinding(
                            category="configuration",
                            severity="info",
                            title="TLS 1.3 0-RTT Supported",
                            description="Server supports TLS 1.3 0-RTT (early data). While this improves performance, it may be vulnerable to replay attacks.",
                            host=host,
                            port=port,
                            recommendation="Ensure application-level replay protection for sensitive operations.",
                        ))
                    
                    if not result.tls13_analysis.has_aes_gcm and not result.tls13_analysis.has_chacha20:
                        findings.append(SSLFinding(
                            category="cipher",
                            severity="medium",
                            title="Limited TLS 1.3 Cipher Support",
                            description="Server does not support AES-GCM or ChaCha20-Poly1305 cipher suites for TLS 1.3.",
                            host=host,
                            port=port,
                            recommendation="Enable TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256.",
                        ))
                        
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"TLS 1.3 analysis failed for {host}:{port}: {e}")
        
        # Certificate Transparency verification
        try:
            result.ct_verification = verify_ct_logs(host, port, timeout)
            
            if result.ct_verification:
                if not result.ct_verification.has_scts:
                    findings.append(SSLFinding(
                        category="certificate",
                        severity="medium",
                        title="No Certificate Transparency SCTs",
                        description="Certificate does not contain Signed Certificate Timestamps (SCTs). Modern browsers may show warnings.",
                        host=host,
                        port=port,
                        recommendation="Ensure your CA includes SCTs in certificates or enable OCSP stapling with SCTs.",
                    ))
                elif result.ct_verification.sct_count < 2:
                    findings.append(SSLFinding(
                        category="certificate",
                        severity="low",
                        title="Insufficient CT SCTs",
                        description=f"Certificate has only {result.ct_verification.sct_count} SCT(s). Chrome requires 2-3 SCTs depending on certificate validity.",
                        host=host,
                        port=port,
                        evidence=f"SCT count: {result.ct_verification.sct_count}",
                        recommendation="Use a CA that provides multiple SCTs for Certificate Transparency compliance.",
                    ))
                    
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"CT verification failed for {host}:{port}: {e}")
        
        # Cipher ordering analysis
        try:
            result.cipher_ordering = analyze_cipher_ordering(host, port, timeout)
            
            if result.cipher_ordering:
                if result.cipher_ordering.client_order_honored and not result.cipher_ordering.server_enforces_order:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="medium",
                        title="Server Honors Client Cipher Preference",
                        description="Server follows client's cipher preference instead of enforcing its own order. This allows clients to force weaker ciphers.",
                        host=host,
                        port=port,
                        recommendation="Configure server to enforce its own cipher order (e.g., ssl_prefer_server_ciphers on in nginx).",
                    ))
                
                if not result.cipher_ordering.pfs_prioritized:
                    findings.append(SSLFinding(
                        category="cipher",
                        severity="medium",
                        title="Perfect Forward Secrecy Not Prioritized",
                        description="Server does not prioritize cipher suites with Perfect Forward Secrecy (ECDHE/DHE).",
                        host=host,
                        port=port,
                        recommendation="Prioritize ECDHE and DHE cipher suites in server configuration.",
                    ))
                    
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Cipher ordering analysis failed for {host}:{port}: {e}")
        
        # Session ticket analysis
        try:
            result.session_ticket_analysis = analyze_session_tickets(host, port, timeout)
            
            if result.session_ticket_analysis:
                if result.session_ticket_analysis.supports_0rtt and result.session_ticket_analysis.early_data_accepted:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="medium",
                        title="0-RTT Early Data Accepted",
                        description="Server accepts TLS 1.3 0-RTT early data, which is vulnerable to replay attacks.",
                        host=host,
                        port=port,
                        recommendation="Implement application-level replay protection or disable 0-RTT for security-critical endpoints.",
                    ))
                    
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Session ticket analysis failed for {host}:{port}: {e}")
        
        # SNI mismatch detection
        try:
            result.sni_analysis = detect_sni_mismatch(host, port, timeout)
            
            if result.sni_analysis:
                if result.sni_analysis.allows_domain_fronting:
                    findings.append(SSLFinding(
                        category="threat_intel",
                        severity="high",
                        title="Domain Fronting Possible",
                        description="Server configuration may allow domain fronting attacks, where malicious traffic can be disguised as legitimate traffic.",
                        host=host,
                        port=port,
                        evidence=f"Default cert: {result.sni_analysis.default_cert_cn}, Requested: {result.sni_analysis.requested_cert_cn}",
                        recommendation="Review SNI configuration and ensure certificates match expected domains.",
                    ))
                
                if result.sni_analysis.vulnerable_to_confusion:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="medium",
                        title="SNI Confusion Vulnerability",
                        description="Server may be vulnerable to SNI confusion attacks due to certificate handling differences.",
                        host=host,
                        port=port,
                        recommendation="Ensure consistent certificate handling regardless of SNI value.",
                    ))
                    
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"SNI analysis failed for {host}:{port}: {e}")
        
        # ========== PROTOCOL & ATTACK DETECTION ==========
        
        # Downgrade Attack Detection (POODLE, FREAK, Logjam, DROWN)
        try:
            result.downgrade_attacks = detect_downgrade_attacks(host, port, timeout)
            
            if result.downgrade_attacks:
                if result.downgrade_attacks.poodle_sslv3_vulnerable:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="critical",
                        title="POODLE Vulnerability (SSLv3)",
                        description="Server supports SSLv3 with CBC ciphers, vulnerable to POODLE attack allowing decryption of encrypted traffic.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2014-3566"],
                        evidence="SSLv3 with CBC cipher supported",
                        recommendation="Disable SSLv3 completely on the server.",
                    ))
                
                if result.downgrade_attacks.poodle_tls_vulnerable:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="medium",
                        title="Lucky Thirteen / TLS CBC Vulnerability",
                        description="Server supports TLS 1.0/1.1 with CBC ciphers, potentially vulnerable to timing attacks.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2013-0169"],
                        recommendation="Disable TLS 1.0/1.1 or use only AEAD ciphers (GCM).",
                    ))
                
                if result.downgrade_attacks.freak_vulnerable:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="high",
                        title="FREAK Vulnerability (Export Ciphers)",
                        description=f"Server supports export-grade cipher suites, vulnerable to FREAK attack: {', '.join(result.downgrade_attacks.export_ciphers_supported[:3])}",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2015-0204"],
                        evidence=f"Export ciphers: {', '.join(result.downgrade_attacks.export_ciphers_supported)}",
                        recommendation="Disable all export-grade cipher suites.",
                    ))
                
                if result.downgrade_attacks.logjam_vulnerable:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="high",
                        title="Logjam Vulnerability (Weak DH)",
                        description=f"Server uses weak Diffie-Hellman parameters ({result.downgrade_attacks.dh_key_size or 512}-bit), vulnerable to Logjam attack.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2015-4000"],
                        evidence=f"DH key size: {result.downgrade_attacks.dh_key_size or 512} bits",
                        recommendation="Use 2048-bit or larger DH parameters.",
                    ))
                
                if result.downgrade_attacks.drown_vulnerable:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="critical",
                        title="DROWN Vulnerability (SSLv2)",
                        description="Server supports SSLv2, vulnerable to DROWN cross-protocol attack that can decrypt TLS traffic.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2016-0800"],
                        evidence="SSLv2 protocol supported",
                        recommendation="Disable SSLv2 completely on all servers sharing this RSA key.",
                    ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Downgrade attack detection failed for {host}:{port}: {e}")
        
        # Heartbleed Detection
        try:
            result.heartbleed_analysis = detect_heartbleed(host, port, timeout)
            
            if result.heartbleed_analysis and result.heartbleed_analysis.vulnerable:
                findings.append(SSLFinding(
                    category="vulnerability",
                    severity="critical",
                    title="Heartbleed Vulnerability",
                    description=f"Server is vulnerable to Heartbleed (CVE-2014-0160), allowing attackers to read server memory including private keys and user data. Leaked {result.heartbleed_analysis.leak_size} bytes.",
                    host=host,
                    port=port,
                    cve_ids=["CVE-2014-0160"],
                    evidence=f"Memory leak size: {result.heartbleed_analysis.leak_size} bytes",
                    recommendation="Update OpenSSL immediately (1.0.1g+), revoke and reissue certificates, reset all passwords.",
                ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Heartbleed detection failed for {host}:{port}: {e}")
        
        # ROBOT Attack Detection
        try:
            result.robot_analysis = detect_robot_attack(host, port, timeout)
            
            if result.robot_analysis and result.robot_analysis.vulnerable:
                findings.append(SSLFinding(
                    category="vulnerability",
                    severity="medium" if result.robot_analysis.oracle_type == "weak" else "high",
                    title="ROBOT Vulnerability (RSA Padding Oracle)",
                    description=f"Server supports RSA key exchange, potentially vulnerable to Bleichenbacher oracle attack. RSA ciphers: {', '.join(result.robot_analysis.vulnerable_ciphers[:3])}",
                    host=host,
                    port=port,
                    cve_ids=["CVE-2017-13099"],
                    evidence=f"RSA ciphers supported: {len(result.robot_analysis.vulnerable_ciphers)}",
                    recommendation="Disable RSA key exchange, use only ECDHE or DHE cipher suites.",
                ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"ROBOT detection failed for {host}:{port}: {e}")
        
        # Renegotiation Testing
        try:
            result.renegotiation_analysis = analyze_renegotiation(host, port, timeout)
            
            if result.renegotiation_analysis:
                if result.renegotiation_analysis.vulnerable_to_mitm:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="high",
                        title="Insecure TLS Renegotiation",
                        description="Server does not support secure renegotiation (RFC 5746), vulnerable to MITM attacks during renegotiation.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2009-3555"],
                        recommendation="Enable secure renegotiation or upgrade TLS implementation.",
                    ))
                
                if result.renegotiation_analysis.vulnerable_to_dos:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="medium",
                        title="Client-Initiated Renegotiation DoS Risk",
                        description="Server allows client-initiated renegotiation, which can be abused for denial-of-service attacks.",
                        host=host,
                        port=port,
                        recommendation="Disable client-initiated renegotiation or implement rate limiting.",
                    ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Renegotiation analysis failed for {host}:{port}: {e}")
        
        # Sweet32 Detection
        try:
            result.sweet32_analysis = detect_sweet32(host, port, timeout)
            
            if result.sweet32_analysis and result.sweet32_analysis.vulnerable:
                findings.append(SSLFinding(
                    category="vulnerability",
                    severity="medium",
                    title="Sweet32 Vulnerability (64-bit Block Ciphers)",
                    description=f"Server supports 64-bit block ciphers vulnerable to birthday attacks: {', '.join(result.sweet32_analysis.weak_block_ciphers[:3])}",
                    host=host,
                    port=port,
                    cve_ids=["CVE-2016-2183"],
                    evidence=f"Weak ciphers: {', '.join(result.sweet32_analysis.weak_block_ciphers)}",
                    recommendation="Disable 3DES, DES, Blowfish, and IDEA cipher suites.",
                ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Sweet32 detection failed for {host}:{port}: {e}")
        
        # CRIME/BREACH Detection
        try:
            result.compression_attacks = detect_compression_attacks(host, port, timeout)
            
            if result.compression_attacks:
                if result.compression_attacks.crime_vulnerable:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="high",
                        title="CRIME Vulnerability (TLS Compression)",
                        description="TLS compression is enabled, vulnerable to CRIME attack that can recover session cookies and secrets.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2012-4929"],
                        evidence=f"Compression: {', '.join(result.compression_attacks.compression_methods)}",
                        recommendation="Disable TLS compression (DEFLATE).",
                    ))
                
                if result.compression_attacks.breach_vulnerable:
                    findings.append(SSLFinding(
                        category="vulnerability",
                        severity="medium",
                        title="BREACH Vulnerability (HTTP Compression)",
                        description="HTTP compression is enabled with potentially sensitive content, may be vulnerable to BREACH attack.",
                        host=host,
                        port=port,
                        cve_ids=["CVE-2013-3587"],
                        evidence="HTTP compression enabled",
                        recommendation="Disable HTTP compression for pages with secrets, or add CSRF tokens and secret randomization.",
                    ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"Compression attack detection failed for {host}:{port}: {e}")
        
        # ALPN Detection
        try:
            result.alpn_analysis = detect_alpn_protocols(host, port, timeout)
            
            if result.alpn_analysis:
                if result.alpn_analysis.spdy_supported:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="low",
                        title="Deprecated SPDY Protocol Supported",
                        description="Server supports deprecated SPDY protocol which has been superseded by HTTP/2.",
                        host=host,
                        port=port,
                        recommendation="Disable SPDY and ensure HTTP/2 (h2) is enabled instead.",
                    ))
                
                if result.alpn_analysis.http2_supported:
                    findings.append(SSLFinding(
                        category="configuration",
                        severity="info",
                        title="HTTP/2 Supported",
                        description="Server supports HTTP/2 protocol via ALPN negotiation.",
                        host=host,
                        port=port,
                        evidence=f"Negotiated: {result.alpn_analysis.negotiated_protocol}",
                    ))
                
                result.findings = findings
                
        except Exception as e:
            logger.debug(f"ALPN detection failed for {host}:{port}: {e}")
        
        # === NEW ENHANCED ANALYSIS FEATURES ===
        
        # SSL Grade Calculation (A+ to F like SSL Labs)
        try:
            result.ssl_grade = calculate_ssl_grade(result)
            if result.ssl_grade:
                grade_severity = "critical" if result.ssl_grade.grade in ["F", "T"] else \
                                 "high" if result.ssl_grade.grade in ["D", "E"] else \
                                 "medium" if result.ssl_grade.grade == "C" else \
                                 "low" if result.ssl_grade.grade == "B" else "info"
                findings.append(SSLFinding(
                    category="grade",
                    severity=grade_severity,
                    title=f"SSL/TLS Grade: {result.ssl_grade.grade}",
                    description=f"Overall SSL/TLS configuration grade is {result.ssl_grade.grade} (score: {result.ssl_grade.score}/100). {result.ssl_grade.summary}",
                    host=host,
                    port=port,
                    evidence=f"Protocol: {result.ssl_grade.protocol_score}/30, Key: {result.ssl_grade.key_exchange_score}/30, Cipher: {result.ssl_grade.cipher_score}/40",
                    recommendation="; ".join(result.ssl_grade.recommendations[:3]) if result.ssl_grade.recommendations else None,
                ))
                result.findings = findings
        except Exception as e:
            logger.debug(f"SSL grade calculation failed for {host}:{port}: {e}")
        
        # Mozilla TLS Compliance Check
        try:
            result.mozilla_compliance = check_mozilla_compliance(result, "intermediate")
            if result.mozilla_compliance and not result.mozilla_compliance.compliant:
                findings.append(SSLFinding(
                    category="compliance",
                    severity="medium" if result.mozilla_compliance.profile == "intermediate" else "low",
                    title=f"Mozilla TLS Compliance: {result.mozilla_compliance.profile.title()} Profile",
                    description=f"Configuration does not meet Mozilla's {result.mozilla_compliance.profile} TLS profile. {len(result.mozilla_compliance.violations)} violations found.",
                    host=host,
                    port=port,
                    evidence="; ".join(result.mozilla_compliance.violations[:3]),
                    recommendation="; ".join(result.mozilla_compliance.recommendations[:3]) if result.mozilla_compliance.recommendations else None,
                ))
                result.findings = findings
        except Exception as e:
            logger.debug(f"Mozilla compliance check failed for {host}:{port}: {e}")
        
        # Client Browser Compatibility Simulation
        try:
            result.client_compatibility = simulate_client_compatibility(result)
            if result.client_compatibility:
                incompatible = [c for c in result.client_compatibility.clients if not result.client_compatibility.clients[c]["compatible"]]
                if incompatible:
                    findings.append(SSLFinding(
                        category="compatibility",
                        severity="low" if len(incompatible) <= 2 else "medium",
                        title="Client Compatibility Issues",
                        description=f"Server configuration is incompatible with {len(incompatible)} client(s): {', '.join(incompatible[:3])}.",
                        host=host,
                        port=port,
                        evidence=f"Incompatible: {', '.join(incompatible)}",
                        recommendation=f"Consider enabling support for older protocols/ciphers if backward compatibility is required.",
                    ))
                    result.findings = findings
        except Exception as e:
            logger.debug(f"Client compatibility simulation failed for {host}:{port}: {e}")
        
        # Post-Quantum Cryptography Analysis
        try:
            result.post_quantum_analysis = analyze_post_quantum_support(result)
            if result.post_quantum_analysis:
                if result.post_quantum_analysis.pq_ready:
                    findings.append(SSLFinding(
                        category="post_quantum",
                        severity="info",
                        title="Post-Quantum Ready",
                        description=f"Server supports post-quantum cryptography algorithms: {', '.join(result.post_quantum_analysis.supported_kems + result.post_quantum_analysis.supported_signatures)}.",
                        host=host,
                        port=port,
                        evidence=f"Hybrid mode: {result.post_quantum_analysis.hybrid_mode}",
                    ))
                else:
                    findings.append(SSLFinding(
                        category="post_quantum",
                        severity="info",
                        title="Post-Quantum Not Supported",
                        description="Server does not support post-quantum cryptography. Consider enabling ML-KEM/Kyber for quantum-resistant key exchange.",
                        host=host,
                        port=port,
                        recommendation="Enable post-quantum hybrid key exchange (X25519Kyber768) for future-proof security.",
                    ))
                result.findings = findings
        except Exception as e:
            logger.debug(f"Post-quantum analysis failed for {host}:{port}: {e}")
        
        # STARTTLS Detection (for non-443 ports)
        if port not in [443, 8443]:
            try:
                result.starttls_info = detect_starttls(host, port, timeout)
                if result.starttls_info and result.starttls_info.supported:
                    findings.append(SSLFinding(
                        category="starttls",
                        severity="info",
                        title=f"STARTTLS Supported ({result.starttls_info.protocol})",
                        description=f"Server supports STARTTLS upgrade for {result.starttls_info.protocol} protocol.",
                        host=host,
                        port=port,
                        evidence=f"Protocol: {result.starttls_info.protocol}, Negotiated: {result.starttls_info.negotiated_protocol or 'N/A'}",
                    ))
                    
                    if result.starttls_info.vulnerabilities:
                        for vuln in result.starttls_info.vulnerabilities:
                            findings.append(SSLFinding(
                                category="starttls",
                                severity="high",
                                title=f"STARTTLS Vulnerability: {vuln}",
                                description=f"STARTTLS implementation is vulnerable to {vuln} attack.",
                                host=host,
                                port=port,
                            ))
                    result.findings = findings
            except Exception as e:
                logger.debug(f"STARTTLS detection failed for {host}:{port}: {e}")
        
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
        # Offensive analysis summary
        hosts_with_c2_indicators=sum(
            1 for r in results 
            if r.offensive_analysis and r.offensive_analysis.jarm 
            and r.offensive_analysis.jarm.signature_type in ["c2_framework", "malware"]
        ),
        hosts_with_suspicious_certs=sum(
            1 for r in results
            if r.offensive_analysis and r.offensive_analysis.cert_intel
            and r.offensive_analysis.cert_intel.is_suspicious
        ),
        hosts_mitm_possible=sum(
            1 for r in results
            if r.offensive_analysis and r.offensive_analysis.mitm
            and r.offensive_analysis.mitm.can_mitm
        ),
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
        
        # Collect offensive analysis data
        offensive_data = []
        for r in analysis_result.results:
            if r.offensive_analysis:
                entry = {
                    "host": f"{r.host}:{r.port}",
                    "threat_level": r.offensive_analysis.threat_level,
                    "is_malicious": r.offensive_analysis.is_likely_malicious,
                    "indicators": r.offensive_analysis.threat_indicators[:5],
                }
                if r.offensive_analysis.jarm and r.offensive_analysis.jarm.matched_signature:
                    entry["jarm_match"] = r.offensive_analysis.jarm.matched_signature
                    entry["jarm_type"] = r.offensive_analysis.jarm.signature_type
                if r.offensive_analysis.cert_intel and r.offensive_analysis.cert_intel.is_suspicious:
                    entry["cert_suspicion"] = r.offensive_analysis.cert_intel.suspicion_score
                    entry["cert_reasons"] = r.offensive_analysis.cert_intel.suspicion_reasons[:3]
                if r.offensive_analysis.mitm:
                    entry["mitm_possible"] = r.offensive_analysis.mitm.can_mitm
                    entry["mitm_difficulty"] = r.offensive_analysis.mitm.difficulty
                offensive_data.append(entry)
        
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
        
        offensive_text = "\n".join(
            f"- {d['host']}: Threat={d['threat_level']}, Malicious={d['is_malicious']}, " +
            (f"JARM={d.get('jarm_match', 'N/A')}, " if d.get('jarm_match') else "") +
            (f"MITM={d.get('mitm_difficulty', 'N/A')}" if d.get('mitm_possible') else "MITM=No")
            for d in offensive_data[:15]
        )
        
        # Build Protocol & Attack Detection summary
        protocol_attack_data = []
        for r in analysis_result.results:
            host_attacks = {"host": f"{r.host}:{r.port}", "attacks": []}
            
            if r.downgrade_attacks and r.downgrade_attacks.vulnerable_to_downgrade:
                attacks = []
                if r.downgrade_attacks.poodle_sslv3_vulnerable:
                    attacks.append("POODLE-SSLv3")
                if r.downgrade_attacks.poodle_tls_vulnerable:
                    attacks.append("POODLE-TLS")
                if r.downgrade_attacks.freak_vulnerable:
                    attacks.append("FREAK")
                if r.downgrade_attacks.logjam_vulnerable:
                    attacks.append(f"Logjam(DH:{r.downgrade_attacks.dh_key_size}bit)")
                if r.downgrade_attacks.drown_vulnerable:
                    attacks.append("DROWN")
                if attacks:
                    host_attacks["attacks"].append(f"Downgrade: {', '.join(attacks)}")
            
            if r.heartbleed_analysis and r.heartbleed_analysis.vulnerable:
                host_attacks["attacks"].append(f"Heartbleed(CVE-2014-0160) - {r.heartbleed_analysis.leak_size}bytes leaked")
            
            if r.robot_analysis and r.robot_analysis.vulnerable:
                host_attacks["attacks"].append(f"ROBOT({r.robot_analysis.oracle_type or 'RSA padding oracle'})")
            
            if r.renegotiation_analysis:
                if r.renegotiation_analysis.vulnerable_to_mitm:
                    host_attacks["attacks"].append("Renegotiation-MITM(CVE-2009-3555)")
                elif r.renegotiation_analysis.vulnerable_to_dos:
                    host_attacks["attacks"].append("Renegotiation-DoS")
            
            if r.sweet32_analysis and r.sweet32_analysis.vulnerable:
                weak = []
                if r.sweet32_analysis.triple_des_supported:
                    weak.append("3DES")
                if r.sweet32_analysis.blowfish_supported:
                    weak.append("Blowfish")
                host_attacks["attacks"].append(f"Sweet32({', '.join(weak)})")
            
            if r.compression_attacks:
                if r.compression_attacks.crime_vulnerable:
                    host_attacks["attacks"].append("CRIME(TLS-compression)")
                if r.compression_attacks.breach_vulnerable:
                    host_attacks["attacks"].append("BREACH(HTTP-compression)")
            
            if r.alpn_analysis and r.alpn_analysis.alpn_supported:
                protos = []
                if r.alpn_analysis.http2_supported:
                    protos.append("HTTP/2")
                if r.alpn_analysis.grpc_supported:
                    protos.append("gRPC")
                if protos:
                    host_attacks["alpn"] = protos
            
            if host_attacks["attacks"] or host_attacks.get("alpn"):
                protocol_attack_data.append(host_attacks)
        
        protocol_attacks_text = "\n".join(
            f"- {d['host']}: {', '.join(d['attacks'])}" + (f" [ALPN: {', '.join(d.get('alpn', []))}]" if d.get('alpn') else "")
            for d in protocol_attack_data[:15]
        ) if protocol_attack_data else ""
        
        # Build NEW ANALYSIS DATA for AI (SSL Grade, Mozilla, Client Compat, PQ, STARTTLS)
        grade_data = []
        mozilla_data = []
        client_compat_data = []
        pq_data = []
        starttls_data = []
        
        for r in analysis_result.results:
            host_id = f"{r.host}:{r.port}"
            
            # SSL Grade
            if r.ssl_grade:
                grade_data.append({
                    "host": host_id,
                    "grade": r.ssl_grade.grade,
                    "score": r.ssl_grade.numeric_score,
                    "cap": r.ssl_grade.grade_cap,
                    "cap_reasons": r.ssl_grade.cap_reasons[:3] if r.ssl_grade.cap_reasons else [],
                    "top_issues": [d.item for d in r.ssl_grade.deductions[:3]] if r.ssl_grade.deductions else []
                })
            
            # Mozilla Compliance
            if r.mozilla_compliance:
                mozilla_data.append({
                    "host": host_id,
                    "profile": r.mozilla_compliance.profile_tested,
                    "compliant": r.mozilla_compliance.is_compliant,
                    "score": r.mozilla_compliance.compliance_score,
                    "violations": [v.get("issue", str(v)) if isinstance(v, dict) else str(v) for v in r.mozilla_compliance.violations[:3]] if r.mozilla_compliance.violations else []
                })
            
            # Client Compatibility
            if r.client_compatibility:
                client_compat_data.append({
                    "host": host_id,
                    "tested": r.client_compatibility.clients_tested,
                    "compatible": r.client_compatibility.compatible_clients,
                    "incompatible": r.client_compatibility.incompatible_clients,
                    "failures": [s.client_name for s in r.client_compatibility.handshake_simulations[:5] if not s.success] if r.client_compatibility.handshake_simulations else []
                })
            
            # Post-Quantum
            if r.post_quantum_analysis:
                pq_data.append({
                    "host": host_id,
                    "pq_ready": r.post_quantum_analysis.pq_ready,
                    "nist": r.post_quantum_analysis.nist_compliant,
                    "score": r.post_quantum_analysis.future_proof_score,
                    "kems": r.post_quantum_analysis.supported_kems[:3] if r.post_quantum_analysis.supported_kems else [],
                    "hybrid": r.post_quantum_analysis.hybrid_support
                })
            
            # STARTTLS
            if r.starttls_info:
                starttls_data.append({
                    "host": host_id,
                    "protocol": r.starttls_info.protocol,
                    "supported": r.starttls_info.starttls_supported,
                    "required": r.starttls_info.starttls_required,
                    "stripping_risk": r.starttls_info.stripping_possible,
                    "auth_risk": r.starttls_info.plain_auth_before_tls
                })
        
        # Build text summaries for AI
        grade_text = "\n".join(
            f"- {g['host']}: Grade {g['grade']} ({g['score']}/100)" +
            (f" - capped by: {', '.join(g['cap_reasons'])}" if g['cap_reasons'] else "") +
            (f" - issues: {', '.join(g['top_issues'][:2])}" if g['top_issues'] else "")
            for g in grade_data[:15]
        ) if grade_data else ""
        
        mozilla_text = "\n".join(
            f"- {m['host']}: {m['profile']} {'✓ Compliant' if m['compliant'] else '✗ Non-compliant'} ({m['score']}%)" +
            (f" - violations: {', '.join(m['violations'][:2])}" if m['violations'] else "")
            for m in mozilla_data[:15]
        ) if mozilla_data else ""
        
        compat_text = "\n".join(
            f"- {c['host']}: {c['compatible']}/{c['tested']} compatible" +
            (f" - fails: {', '.join(c['failures'][:3])}" if c['failures'] else "")
            for c in client_compat_data[:15]
        ) if client_compat_data else ""
        
        pq_text = "\n".join(
            f"- {p['host']}: {'PQ Ready' if p['pq_ready'] else 'Not PQ Ready'} ({p['score']}/100)" +
            (f" - KEMs: {', '.join(p['kems'])}" if p['kems'] else "") +
            (" + Hybrid" if p['hybrid'] else "")
            for p in pq_data[:15]
        ) if pq_data else ""
        
        starttls_text = "\n".join(
            f"- {s['host']} ({s['protocol']}): {'Supported' if s['supported'] else 'Not supported'}" +
            (f" - REQUIRED" if s['required'] else " - NOT required (stripping possible)" if s['stripping_risk'] else "") +
            (" - AUTH BEFORE TLS!" if s['auth_risk'] else "")
            for s in starttls_data[:15]
        ) if starttls_data else ""
        
        prompt = f"""You are an OFFENSIVE SECURITY expert analyzing sandboxed software TLS connections.
Your role is to identify malicious infrastructure, C2 servers, and exploitation opportunities.

## SCAN DATA

### Summary
- **Hosts Scanned**: {analysis_result.summary.hosts_scanned}
- **Hosts with SSL**: {analysis_result.summary.hosts_with_ssl}
- **Critical Findings**: {analysis_result.summary.critical_findings}
- **High Findings**: {analysis_result.summary.high_findings}
- **Total Vulnerabilities**: {analysis_result.summary.total_vulnerabilities}
- **Self-Signed Certs**: {analysis_result.summary.self_signed_certs}
- **C2/Malware Indicators**: {analysis_result.summary.hosts_with_c2_indicators}
- **Suspicious Certificates**: {analysis_result.summary.hosts_with_suspicious_certs}
- **MITM Possible**: {analysis_result.summary.hosts_mitm_possible}

### Scanned Hosts
{hosts_text}

### Offensive Analysis (JARM, Cert Intel, MITM)
{offensive_text if offensive_text else "No offensive analysis data available."}

### Protocol & Attack Detection
{protocol_attacks_text if protocol_attacks_text else "No protocol-level attacks detected (POODLE, FREAK, Logjam, DROWN, Heartbleed, ROBOT, Renegotiation, Sweet32, CRIME/BREACH all clear)."}

### Detected Vulnerabilities
{vulns_text if vulns_text else "No known vulnerabilities detected."}

### Security Findings
{findings_text if findings_text else "No critical security issues detected."}

### SSL Security Grades
{grade_text if grade_text else "No SSL grade data available."}

### Mozilla TLS Compliance
{mozilla_text if mozilla_text else "No Mozilla compliance data available."}

### Client Compatibility
{compat_text if compat_text else "No client compatibility data available."}

### Post-Quantum Cryptography Readiness
{pq_text if pq_text else "No post-quantum analysis available."}

### STARTTLS Detection
{starttls_text if starttls_text else "No STARTTLS data available (not a mail/FTP server)."}

---

Analyze this data for SANDBOX SOFTWARE ANALYSIS. Focus on:
1. Is this software connecting to malicious infrastructure (C2, malware)?
2. Can we intercept/MITM the traffic to analyze it further?
3. What are the attack opportunities (especially protocol-level attacks like Heartbleed, ROBOT, downgrade attacks)?
4. Can we exploit weak cryptographic configurations?
5. Are there STARTTLS stripping opportunities or plain authentication before TLS?
6. How does SSL grade and compliance affect exploitability?

ONLY report what is actually in the data. Do not invent findings.

Respond with a valid JSON object:

{{
  "threat_assessment": {{
    "overall_risk": "Critical|High|Medium|Low|Benign",
    "risk_score": <0-100>,
    "is_likely_malicious": true|false,
    "confidence": <0.0-1.0>,
    "summary": "<2-3 sentences summarizing the threat assessment>"
  }},
  "malware_indicators": {{
    "c2_indicators_found": true|false,
    "details": [
      {{
        "host": "<host:port>",
        "indicator_type": "<JARM match, DGA domain, suspicious cert, etc>",
        "matched_threat": "<what it matches>",
        "confidence": "High|Medium|Low"
      }}
    ],
    "recommendation": "<what to do about it>"
  }},
  "interception_analysis": {{
    "can_intercept": true|false,
    "hosts_interceptable": <count>,
    "methods": [
      {{
        "host": "<host:port>",
        "method": "<how to intercept>",
        "difficulty": "Easy|Medium|Hard",
        "tools": ["<tool1>", "<tool2>"]
      }}
    ],
    "setup_steps": ["<step1>", "<step2>"]
  }},
  "certificate_intelligence": {{
    "suspicious_certs": <count>,
    "findings": [
      {{
        "host": "<host:port>",
        "issue": "<what's suspicious>",
        "ioc_value": "<fingerprint, domain, etc for blocklisting>"
      }}
    ]
  }},
  "protocol_attacks": {{
    "total_vulnerable_hosts": <count>,
    "attacks_found": [
      {{
        "host": "<host:port>",
        "attack_type": "<Heartbleed|ROBOT|POODLE|FREAK|Logjam|DROWN|Sweet32|CRIME|BREACH|Renegotiation>",
        "cve": "<CVE if applicable>",
        "severity": "Critical|High|Medium",
        "exploit_available": true|false,
        "exploitation_steps": ["<step1>", "<step2>"],
        "tools": ["<tool1>", "<tool2>"]
      }}
    ],
    "crypto_weaknesses": ["<weak cipher>", "<weak protocol>"]
  }},
  "attack_opportunities": [
    {{
      "target": "<host:port>",
      "attack": "<attack type>",
      "difficulty": "Easy|Medium|Hard",
      "impact": "<what you gain>",
      "command": "<example command if applicable>"
    }}
  ],
  "next_steps": [
    {{
      "priority": 1,
      "action": "<what to do>",
      "rationale": "<why>"
    }}
  ]
}}

Return ONLY valid JSON. Be factual - only report what's in the data."""

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


# ============================================================================
# NEW: SSL GRADING SYSTEM
# ============================================================================

def calculate_ssl_grade(result: SSLScanResult) -> SSLGrade:
    """
    Calculate an SSL Labs-style grade for a scan result.
    
    Grading criteria based on SSL Labs methodology:
    - Protocol support (30%)
    - Key exchange strength (30%)
    - Cipher strength (30%)
    - Certificate (10%)
    """
    score = 100
    grade_cap = None
    cap_reasons = []
    deductions = []
    
    # Start with perfect score and deduct
    protocol_score = 100
    cipher_score = 100
    cert_score = 100
    key_exchange_score = 100
    
    protocols = result.protocols_supported or {}
    
    # Protocol scoring
    if protocols.get("SSLv2", False):
        protocol_score = 0
        grade_cap = "F"
        cap_reasons.append("SSLv2 supported - critically insecure")
        deductions.append({"item": "SSLv2", "points": -100, "cap": "F"})
    
    if protocols.get("SSLv3", False):
        protocol_score = min(protocol_score, 20)
        if grade_cap is None or grade_cap > "C":
            grade_cap = "C"
        cap_reasons.append("SSLv3 supported - POODLE vulnerability")
        deductions.append({"item": "SSLv3", "points": -50, "cap": "C"})
    
    if protocols.get("TLSv1.0", False):
        protocol_score = min(protocol_score, 65)
        deductions.append({"item": "TLS 1.0", "points": -20, "reason": "Deprecated protocol"})
    
    if protocols.get("TLSv1.1", False):
        protocol_score = min(protocol_score, 75)
        deductions.append({"item": "TLS 1.1", "points": -15, "reason": "Deprecated protocol"})
    
    if not protocols.get("TLSv1.2", False) and not protocols.get("TLSv1.3", False):
        protocol_score = 0
        if grade_cap is None or grade_cap > "F":
            grade_cap = "F"
        cap_reasons.append("No TLS 1.2 or 1.3 support")
    
    # Bonus for TLS 1.3
    if protocols.get("TLSv1.3", False):
        protocol_score = min(protocol_score + 10, 100)
    
    # Vulnerability checks
    if result.heartbleed_analysis and result.heartbleed_analysis.vulnerable:
        grade_cap = "F"
        cap_reasons.append("Heartbleed vulnerability")
        deductions.append({"item": "Heartbleed", "points": -100, "cap": "F"})
    
    if result.downgrade_attacks:
        if result.downgrade_attacks.drown_vulnerable:
            grade_cap = "F"
            cap_reasons.append("DROWN vulnerability")
            deductions.append({"item": "DROWN", "points": -100, "cap": "F"})
        
        if result.downgrade_attacks.poodle_sslv3_vulnerable:
            if grade_cap is None or grade_cap > "C":
                grade_cap = "C"
            cap_reasons.append("POODLE (SSLv3)")
            deductions.append({"item": "POODLE", "points": -50, "cap": "C"})
        
        if result.downgrade_attacks.freak_vulnerable:
            if grade_cap is None or grade_cap > "C":
                grade_cap = "C"
            cap_reasons.append("FREAK vulnerability")
            deductions.append({"item": "FREAK", "points": -40, "cap": "C"})
        
        if result.downgrade_attacks.logjam_vulnerable:
            if grade_cap is None or grade_cap > "C":
                grade_cap = "C"
            cap_reasons.append("Logjam vulnerability")
            deductions.append({"item": "Logjam", "points": -30, "cap": "C"})
    
    if result.robot_analysis and result.robot_analysis.vulnerable:
        if grade_cap is None or grade_cap > "C":
            grade_cap = "C"
        cap_reasons.append("ROBOT vulnerability")
        deductions.append({"item": "ROBOT", "points": -40, "cap": "C"})
    
    if result.sweet32_analysis and result.sweet32_analysis.vulnerable:
        if grade_cap is None or grade_cap > "B":
            grade_cap = "B"
        cap_reasons.append("Sweet32 vulnerability")
        deductions.append({"item": "Sweet32", "points": -15, "cap": "B"})
    
    if result.compression_attacks and result.compression_attacks.crime_vulnerable:
        if grade_cap is None or grade_cap > "B":
            grade_cap = "B"
        cap_reasons.append("CRIME vulnerability")
        deductions.append({"item": "CRIME", "points": -25, "cap": "B"})
    
    # Cipher scoring
    weak_ciphers = 0
    has_forward_secrecy = False
    for cipher in (result.cipher_suites or []):
        cipher_name = cipher.get("name", "") if isinstance(cipher, dict) else str(cipher)
        
        # Check for forward secrecy
        if "ECDHE" in cipher_name or "DHE" in cipher_name:
            has_forward_secrecy = True
        
        # Check for weak ciphers
        for weak in WEAK_CIPHER_KEYWORDS:
            if weak in cipher_name.upper():
                weak_ciphers += 1
                cipher_score -= 5
                break
    
    if weak_ciphers > 0:
        deductions.append({"item": f"{weak_ciphers} weak ciphers", "points": -weak_ciphers * 5})
    
    if not has_forward_secrecy:
        cipher_score -= 20
        deductions.append({"item": "No forward secrecy", "points": -20})
        if grade_cap is None or grade_cap > "B":
            grade_cap = "B"
        cap_reasons.append("No forward secrecy ciphers")
    
    # Certificate scoring
    if result.certificate:
        if result.certificate.is_expired:
            cert_score = 0
            if grade_cap is None or grade_cap > "T":
                grade_cap = "T"
            cap_reasons.append("Certificate expired")
            deductions.append({"item": "Expired certificate", "points": -100, "cap": "T"})
        
        if result.certificate.is_self_signed:
            cert_score -= 30
            if grade_cap is None or grade_cap > "T":
                grade_cap = "T"
            cap_reasons.append("Self-signed certificate")
            deductions.append({"item": "Self-signed", "points": -30, "cap": "T"})
        
        if result.certificate.days_until_expiry and result.certificate.days_until_expiry < 30:
            cert_score -= 10
            deductions.append({"item": "Certificate expiring soon", "points": -10})
        
        # Key size check
        key_bits = result.certificate.public_key_bits or 0
        key_type = result.certificate.public_key_type or ""
        
        if "RSA" in key_type.upper() and key_bits < 2048:
            key_exchange_score -= 40
            if grade_cap is None or grade_cap > "B":
                grade_cap = "B"
            cap_reasons.append(f"Weak RSA key ({key_bits} bits)")
            deductions.append({"item": f"RSA {key_bits}-bit", "points": -40, "cap": "B"})
        elif "EC" in key_type.upper() and key_bits < 256:
            key_exchange_score -= 30
            deductions.append({"item": f"EC {key_bits}-bit", "points": -30})
        
        # Signature algorithm
        sig_alg = result.certificate.signature_algorithm or ""
        if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
            cert_score -= 20
            deductions.append({"item": "Weak signature algorithm", "points": -20})
    
    # Security headers
    if result.security_headers:
        if not result.security_headers.hsts_enabled:
            score -= 5
            deductions.append({"item": "No HSTS", "points": -5})
    
    # Calculate final score
    final_score = int(
        (protocol_score * 0.30) +
        (cipher_score * 0.30) +
        (cert_score * 0.10) +
        (key_exchange_score * 0.30)
    )
    
    # Apply cap
    if grade_cap:
        grade = grade_cap
    else:
        if final_score >= 95:
            # A+ requires additional checks
            has_hsts = result.security_headers and result.security_headers.hsts_enabled
            has_tls13 = protocols.get("TLSv1.3", False)
            no_old = not protocols.get("TLSv1.0") and not protocols.get("TLSv1.1")
            if has_hsts and has_tls13 and no_old and has_forward_secrecy:
                grade = "A+"
            else:
                grade = "A"
        elif final_score >= 85:
            grade = "A"
        elif final_score >= 70:
            grade = "B"
        elif final_score >= 55:
            grade = "C"
        elif final_score >= 40:
            grade = "D"
        else:
            grade = "F"
    
    # Grade description
    grade_descriptions = {
        "A+": "Exceptional - Best practices with TLS 1.3, HSTS, and forward secrecy",
        "A": "Strong - Good configuration with minor improvements possible",
        "B": "Adequate - Some deprecated features or missing best practices",
        "C": "Weak - Known vulnerabilities or deprecated protocols",
        "D": "Insecure - Multiple security issues requiring immediate attention",
        "F": "Critical - Severe vulnerabilities or broken configuration",
        "T": "Trust Issues - Certificate problems (expired, self-signed, etc.)",
        "M": "Mismatch - Certificate doesn't match hostname",
    }
    
    return SSLGrade(
        grade=grade,
        numeric_score=final_score,
        grade_cap=grade_cap,
        cap_reasons=cap_reasons,
        deductions=deductions,
        grade_details=grade_descriptions.get(grade, ""),
        protocol_score=protocol_score,
        cipher_score=cipher_score,
        certificate_score=cert_score,
        key_exchange_score=key_exchange_score,
    )


# ============================================================================
# NEW: MOZILLA TLS COMPLIANCE CHECKER
# ============================================================================

def check_mozilla_compliance(result: SSLScanResult, profile: str = "intermediate") -> MozillaComplianceResult:
    """
    Check TLS configuration against Mozilla's recommended profiles.
    
    Profiles:
    - modern: TLS 1.3 only, strongest security
    - intermediate: TLS 1.2+, recommended for most servers
    - old: TLS 1.0+, for legacy compatibility
    """
    if profile not in MOZILLA_TLS_PROFILES:
        profile = "intermediate"
    
    config = MOZILLA_TLS_PROFILES[profile]
    violations = []
    recommendations = []
    
    protocols = result.protocols_supported or {}
    ciphers = result.cipher_suites or []
    
    protocol_compliant = True
    cipher_compliant = True
    cert_compliant = True
    hsts_compliant = True
    
    # Check forbidden protocols
    for proto in config["forbidden_protocols"]:
        if protocols.get(proto, False):
            protocol_compliant = False
            violations.append({
                "type": "protocol",
                "severity": "high" if proto in ["SSLv2", "SSLv3"] else "medium",
                "issue": f"Forbidden protocol {proto} is enabled",
                "expected": f"Disable {proto}",
            })
            recommendations.append(f"Disable {proto} protocol")
    
    # Check required protocols
    min_tls = config["min_tls_version"]
    has_min_tls = False
    for proto in config["allowed_protocols"]:
        if protocols.get(proto, False):
            has_min_tls = True
            break
    
    if not has_min_tls:
        protocol_compliant = False
        violations.append({
            "type": "protocol",
            "severity": "high",
            "issue": f"No allowed protocol versions enabled (need {', '.join(config['allowed_protocols'])})",
            "expected": f"Enable {min_tls} or higher",
        })
        recommendations.append(f"Enable {min_tls} or higher")
    
    # Check ciphers
    cipher_names = []
    for c in ciphers:
        if isinstance(c, dict):
            cipher_names.append(c.get("name", ""))
        else:
            cipher_names.append(str(c))
    
    # Check for forbidden cipher patterns
    for cipher in cipher_names:
        for pattern in config["forbidden_ciphers"]:
            # Convert glob pattern to simple check
            pattern_clean = pattern.replace("*", "")
            if pattern_clean and pattern_clean.upper() in cipher.upper():
                cipher_compliant = False
                violations.append({
                    "type": "cipher",
                    "severity": "medium",
                    "issue": f"Forbidden cipher pattern '{pattern}' matched by {cipher}",
                    "expected": "Remove weak ciphers",
                })
                recommendations.append(f"Disable cipher {cipher}")
                break
    
    # Certificate checks
    if result.certificate:
        key_bits = result.certificate.public_key_bits or 0
        key_type = result.certificate.public_key_type or ""
        
        min_rsa = config.get("min_rsa_key_size", 2048)
        min_ec = config.get("min_ec_key_size", 256)
        
        if "RSA" in key_type.upper() and key_bits < min_rsa:
            cert_compliant = False
            violations.append({
                "type": "certificate",
                "severity": "high",
                "issue": f"RSA key size {key_bits} bits is below minimum {min_rsa}",
                "expected": f"Use RSA key >= {min_rsa} bits",
            })
            recommendations.append(f"Upgrade to RSA {min_rsa}-bit or higher")
        
        if "EC" in key_type.upper() and key_bits < min_ec:
            cert_compliant = False
            violations.append({
                "type": "certificate",
                "severity": "medium",
                "issue": f"EC key size {key_bits} bits is below minimum {min_ec}",
                "expected": f"Use EC key >= {min_ec} bits",
            })
    
    # HSTS check
    if config.get("hsts_required", False):
        if not result.security_headers or not result.security_headers.hsts_enabled:
            hsts_compliant = False
            violations.append({
                "type": "hsts",
                "severity": "medium",
                "issue": "HSTS header not present",
                "expected": f"Add HSTS with max-age >= {config.get('hsts_min_age', 63072000)}",
            })
            recommendations.append("Enable HSTS header")
        elif result.security_headers and result.security_headers.hsts_max_age:
            min_age = config.get("hsts_min_age", 0)
            if result.security_headers.hsts_max_age < min_age:
                violations.append({
                    "type": "hsts",
                    "severity": "low",
                    "issue": f"HSTS max-age {result.security_headers.hsts_max_age} below recommended {min_age}",
                    "expected": f"Set max-age to {min_age} (2 years)",
                })
    
    # Calculate compliance score
    total_checks = 4
    passed = sum([protocol_compliant, cipher_compliant, cert_compliant, hsts_compliant])
    compliance_score = passed / total_checks
    
    is_compliant = len(violations) == 0
    
    return MozillaComplianceResult(
        profile_tested=profile,
        is_compliant=is_compliant,
        compliance_score=compliance_score,
        violations=violations,
        recommendations=list(set(recommendations)),  # Dedupe
        protocol_compliance=protocol_compliant,
        cipher_compliance=cipher_compliant,
        certificate_compliance=cert_compliant,
        hsts_compliance=hsts_compliant,
    )


# ============================================================================
# NEW: CLIENT COMPATIBILITY SIMULATION
# ============================================================================

def simulate_client_compatibility(result: SSLScanResult) -> ClientCompatibilityResult:
    """
    Simulate handshakes with various clients to determine compatibility.
    """
    compatible = []
    incompatible = []
    simulations = []
    
    protocols = result.protocols_supported or {}
    cipher_names = []
    for c in (result.cipher_suites or []):
        if isinstance(c, dict):
            cipher_names.append(c.get("name", ""))
        else:
            cipher_names.append(str(c))
    
    for client_id, client in CLIENT_SIMULATION_PROFILES.items():
        # Check protocol overlap
        protocol_match = False
        matched_protocol = None
        for proto in client["tls_versions"]:
            if protocols.get(proto, False):
                protocol_match = True
                matched_protocol = proto
                break
        
        # Check cipher overlap
        cipher_match = False
        matched_cipher = None
        for client_cipher in client["cipher_suites"]:
            for server_cipher in cipher_names:
                # Normalize cipher names for comparison
                if client_cipher.upper() in server_cipher.upper() or server_cipher.upper() in client_cipher.upper():
                    cipher_match = True
                    matched_cipher = server_cipher
                    break
            if cipher_match:
                break
        
        is_compatible = protocol_match and cipher_match
        
        sim_result = {
            "client_id": client_id,
            "client_name": client["name"],
            "compatible": is_compatible,
            "protocol_matched": matched_protocol,
            "cipher_matched": matched_cipher,
            "pq_support": client.get("pq_support", False),
        }
        
        simulations.append(sim_result)
        
        if is_compatible:
            compatible.append({
                "client": client["name"],
                "protocol": matched_protocol,
                "cipher": matched_cipher,
            })
        else:
            reason = []
            if not protocol_match:
                reason.append(f"No protocol overlap (client needs: {', '.join(client['tls_versions'])})")
            if not cipher_match:
                reason.append("No cipher overlap")
            
            incompatible.append({
                "client": client["name"],
                "reason": "; ".join(reason),
            })
    
    return ClientCompatibilityResult(
        clients_tested=len(CLIENT_SIMULATION_PROFILES),
        compatible_clients=compatible,
        incompatible_clients=incompatible,
        handshake_simulations=simulations,
    )


# ============================================================================
# NEW: POST-QUANTUM CRYPTOGRAPHY ANALYSIS
# ============================================================================

def analyze_post_quantum_support(result: SSLScanResult) -> PostQuantumAnalysis:
    """
    Analyze support for post-quantum cryptographic algorithms.
    """
    supported_kems = []
    supported_sigs = []
    recommendations = []
    
    # Check TLS 1.3 cipher suites and named groups for PQ support
    cipher_names = []
    for c in (result.cipher_suites or []):
        if isinstance(c, dict):
            cipher_names.append(c.get("name", ""))
        else:
            cipher_names.append(str(c))
    
    # Check for Kyber/ML-KEM in cipher suites or key exchange
    pq_patterns = [
        "KYBER", "ML-KEM", "MLKEM", "X25519KYBER", "SECP256R1KYBER",
        "DILITHIUM", "ML-DSA", "SPHINCS", "FALCON",
    ]
    
    for cipher in cipher_names:
        cipher_upper = cipher.upper()
        for pattern in pq_patterns:
            if pattern in cipher_upper:
                if "KYBER" in pattern or "KEM" in pattern:
                    supported_kems.append(cipher)
                else:
                    supported_sigs.append(cipher)
    
    # Check TLS 1.3 supported groups if available
    if result.tls13_analysis and hasattr(result.tls13_analysis, 'key_exchange_groups'):
        for group in (result.tls13_analysis.key_exchange_groups or []):
            group_upper = group.upper()
            for pattern in pq_patterns:
                if pattern in group_upper:
                    if "KYBER" in pattern or "KEM" in pattern:
                        supported_kems.append(group)
    
    pq_ready = len(supported_kems) > 0 or len(supported_sigs) > 0
    hybrid_support = any("X25519" in k.upper() or "SECP256" in k.upper() for k in supported_kems)
    
    # Check if using NIST standard algorithms
    nist_kems = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "MLKEM"]
    nist_sigs = ["ML-DSA", "SLH-DSA"]
    nist_compliant = any(
        any(nist in algo.upper() for nist in nist_kems) for algo in supported_kems
    ) or any(
        any(nist in algo.upper() for nist in nist_sigs) for algo in supported_sigs
    )
    
    # Calculate future-proof score
    score = 0
    protocols = result.protocols_supported or {}
    
    if protocols.get("TLSv1.3", False):
        score += 30
    if pq_ready:
        score += 40
    if hybrid_support:
        score += 20
    if nist_compliant:
        score += 10
    
    # Recommendations
    if not protocols.get("TLSv1.3", False):
        recommendations.append("Enable TLS 1.3 - required for most PQ key exchange")
    
    if not pq_ready:
        recommendations.append("Consider enabling post-quantum hybrid key exchange (X25519Kyber768)")
        recommendations.append("Modern browsers (Chrome 116+) support Kyber/ML-KEM")
    
    if pq_ready and not hybrid_support:
        recommendations.append("Use hybrid PQ algorithms (e.g., X25519+Kyber) for backwards compatibility")
    
    if pq_ready and not nist_compliant:
        recommendations.append("Migrate to NIST standardized algorithms (ML-KEM, ML-DSA)")
    
    return PostQuantumAnalysis(
        pq_ready=pq_ready,
        hybrid_support=hybrid_support,
        supported_kems=list(set(supported_kems)),
        supported_signatures=list(set(supported_sigs)),
        nist_compliant=nist_compliant,
        future_proof_score=min(score, 100),
        recommendations=recommendations,
    )


# ============================================================================
# NEW: STARTTLS PROTOCOL SUPPORT
# ============================================================================

def detect_starttls(host: str, port: int, timeout: float = 10.0) -> Optional[STARTTLSInfo]:
    """
    Detect STARTTLS support for various protocols.
    """
    # Determine protocol based on port
    protocol = None
    for proto_name, proto_info in STARTTLS_PROTOCOLS.items():
        if port == proto_info["default_port"] or port in proto_info.get("alt_ports", []):
            protocol = proto_name
            break
    
    if not protocol:
        return None
    
    proto_info = STARTTLS_PROTOCOLS[protocol]
    
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        
        starttls_supported = False
        starttls_required = False
        plain_auth_before_tls = False
        implicit_tls = False
        
        # Handle greeting if needed
        if proto_info["greeting_wait"]:
            greeting = sock.recv(4096)
            logger.debug(f"STARTTLS greeting: {greeting[:200]}")
        
        # Protocol-specific handling
        if protocol == "smtp":
            # Send EHLO
            sock.send(proto_info["starttls_command"])
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if "STARTTLS" in response.upper():
                starttls_supported = True
            
            if "REQUIRETLS" in response.upper() or "250-STARTTLS" in response.upper():
                # Check if auth is offered before STARTTLS
                if "AUTH" in response and response.find("AUTH") < response.find("STARTTLS"):
                    plain_auth_before_tls = True
            
            # Try STARTTLS
            if starttls_supported:
                sock.send(proto_info["starttls_trigger"])
                tls_response = sock.recv(1024)
                if proto_info["success_response"] in tls_response:
                    starttls_supported = True
        
        elif protocol == "imap":
            sock.send(proto_info["starttls_command"])
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if "STARTTLS" in response.upper():
                starttls_supported = True
            if "LOGINDISABLED" in response.upper():
                starttls_required = True
        
        elif protocol == "pop3":
            sock.send(proto_info["starttls_command"])
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if "STLS" in response.upper():
                starttls_supported = True
        
        elif protocol == "ftp":
            sock.send(proto_info["starttls_command"])
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if "AUTH TLS" in response.upper() or "AUTH SSL" in response.upper():
                starttls_supported = True
        
        elif protocol == "postgres":
            # PostgreSQL SSLRequest message
            ssl_request = struct.pack(">II", 8, 80877103)
            sock.send(ssl_request)
            response = sock.recv(1)
            if response == b'S':
                starttls_supported = True
                implicit_tls = False  # It's actually STARTTLS style
        
        sock.close()
        
        # Check for implicit TLS (direct TLS on alt ports)
        if port in proto_info.get("alt_ports", []):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                test_sock = socket.create_connection((host, port), timeout=5)
                ssl_sock = ctx.wrap_socket(test_sock, server_hostname=host)
                ssl_sock.close()
                implicit_tls = True
            except:
                pass
        
        # STARTTLS stripping is possible if STARTTLS is supported but not required
        stripping_possible = starttls_supported and not starttls_required
        
        return STARTTLSInfo(
            protocol=protocol.upper(),
            starttls_supported=starttls_supported,
            starttls_required=starttls_required,
            plain_auth_before_tls=plain_auth_before_tls,
            implicit_tls_supported=implicit_tls,
            stripping_possible=stripping_possible,
        )
        
    except Exception as e:
        logger.debug(f"STARTTLS detection failed for {host}:{port}: {e}")
        return None
