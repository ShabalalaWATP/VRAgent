"""
Security Fuzzing Service

Comprehensive fuzzing service for web application security testing including:
- Multiple attack modes (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
- Real HTTP request execution with response capture
- Automatic vulnerability detection
- Rate limiting and thread control
- Full request/response logging
"""

import asyncio
import httpx
import time
import logging
import re
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, AsyncGenerator
from urllib.parse import urlparse, urlencode, parse_qs
from enum import Enum
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class AttackMode(str, Enum):
    SNIPER = "sniper"
    BATTERING_RAM = "batteringram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "clusterbomb"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FuzzRequest:
    """Represents a single fuzz request."""
    id: str
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str]
    payload: str
    position_index: int
    payload_index: int


@dataclass
class FuzzResponse:
    """Represents the response from a fuzz request."""
    id: str
    payload: str
    status_code: int
    response_length: int
    response_time: float  # in milliseconds
    content_type: str
    headers: Dict[str, str]
    body: str
    timestamp: str
    error: Optional[str] = None
    interesting: bool = False
    flags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FuzzFinding:
    """A potential security finding from fuzzing."""
    type: str
    severity: str
    description: str
    payload: str
    evidence: List[str]
    recommendation: str
    response_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FuzzStats:
    """Statistics for a fuzzing session."""
    total_requests: int = 0
    success_count: int = 0
    error_count: int = 0
    interesting_count: int = 0
    avg_response_time: float = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    requests_per_second: float = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FuzzConfig:
    """Configuration for a fuzzing session."""
    target_url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    positions: List[str] = field(default_factory=list)
    payloads: List[List[str]] = field(default_factory=list)
    attack_mode: str = "sniper"
    threads: int = 10
    delay: int = 0  # milliseconds
    timeout: int = 10000  # milliseconds
    follow_redirects: bool = True
    match_codes: List[int] = field(default_factory=lambda: [200, 301, 302, 401, 403])
    filter_codes: List[int] = field(default_factory=list)
    match_regex: str = ""
    proxy_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FuzzResult:
    """Complete result of a fuzzing session."""
    config: FuzzConfig
    responses: List[FuzzResponse]
    findings: List[FuzzFinding]
    stats: FuzzStats
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "responses": [r.to_dict() for r in self.responses],
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats.to_dict(),
        }


# Detection patterns for automatic vulnerability flagging
DETECTION_PATTERNS = {
    "sql_error": {
        "patterns": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft.*ODBC.*SQL Server",
            r"Unclosed quotation mark",
            r"syntax error at or near",
            r"SQLite.*error",
            r"SQLSTATE\[",
            r"pg_query\(\):",
            r"mysql_fetch_array\(\)",
            r"sqlite3\.OperationalError",
        ],
        "severity": Severity.CRITICAL,
        "type": "SQL Injection",
        "recommendation": "Implement parameterized queries and input validation"
    },
    "xss_reflection": {
        "patterns": [
            r"<script[^>]*>.*</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<img[^>]+onerror",
            r"<svg[^>]+onload",
        ],
        "severity": Severity.HIGH,
        "type": "Reflected XSS",
        "recommendation": "Implement output encoding and Content Security Policy"
    },
    "path_traversal": {
        "patterns": [
            r"root:.*:0:0:",
            r"\[boot loader\]",
            r"Windows.*System32",
            r"/etc/passwd",
            r"No such file or directory",
        ],
        "severity": Severity.HIGH,
        "type": "Path Traversal",
        "recommendation": "Validate and sanitize file path inputs"
    },
    "command_injection": {
        "patterns": [
            r"uid=\d+.*gid=\d+",
            r"root.*bash",
            r"bin/sh",
            r"command not found",
            r"sh:.*not found",
        ],
        "severity": Severity.CRITICAL,
        "type": "Command Injection",
        "recommendation": "Avoid shell commands with user input; use safe APIs"
    },
    "ssti": {
        "patterns": [
            r"49",  # Result of 7*7 in template injection
            r"Traceback.*most recent call",
            r"TemplateSyntaxError",
            r"jinja2\.exceptions",
            r"freemarker\.template",
        ],
        "severity": Severity.CRITICAL,
        "type": "Server-Side Template Injection",
        "recommendation": "Use sandboxed template engines and avoid user input in templates"
    },
    "error_disclosure": {
        "patterns": [
            r"Exception in thread",
            r"Stack trace:",
            r"Traceback \(most recent",
            r"Parse error:",
            r"Fatal error:",
            r"Warning:.*on line \d+",
            r"Notice:.*on line \d+",
            r"<b>Warning</b>:",
            r"DEBUG = True",
        ],
        "severity": Severity.MEDIUM,
        "type": "Error/Debug Information Disclosure",
        "recommendation": "Disable debug mode and implement proper error handling"
    },
    "sensitive_data": {
        "patterns": [
            r"password['\"]?\s*[:=]\s*['\"]?[^'\"]+",
            r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]+",
            r"secret['\"]?\s*[:=]\s*['\"]?[^'\"]+",
            r"token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9._-]+",
            r"private[_-]?key",
            r"-----BEGIN.*PRIVATE KEY-----",
        ],
        "severity": Severity.HIGH,
        "type": "Sensitive Data Exposure",
        "recommendation": "Remove sensitive data from responses and implement proper access controls"
    },
}

# ============================================================================
# OFFENSIVE SECURITY DETECTION PATTERNS
# For analyzing sandboxed software, malware behavior, and C2 communication
# ============================================================================

# C2 (Command & Control) Communication Indicators
C2_DETECTION_PATTERNS = {
    "c2_beacon_patterns": {
        "patterns": [
            r"beacon\s*=",
            r"heartbeat\s*interval",
            r"callback\s*url",
            r"exfil(tration)?",
            r"c2\s*server",
            r"command\s*queue",
            r"task\s*poll",
            r"sleep\s*=\s*\d+",
            r"jitter\s*=",
        ],
        "severity": Severity.CRITICAL,
        "type": "C2 Beacon Configuration",
        "category": "c2",
        "recommendation": "Analyze beacon parameters for C2 infrastructure identification"
    },
    "c2_domain_generation": {
        "patterns": [
            r"dga[_-]?seed",
            r"domain[_-]?gen",
            r"[a-z]{12,}\.(xyz|top|club|online|site|info)",
            r"(\d{1,3}\.){3}\d{1,3}:\d{4,5}",
            r"tor2web",
            r"\.onion",
            r"pastebin\.com/raw",
            r"ghostbin",
            r"hastebin",
        ],
        "severity": Severity.CRITICAL,
        "type": "C2 Domain/Infrastructure",
        "category": "c2",
        "recommendation": "Extract and analyze C2 infrastructure indicators"
    },
    "c2_protocols": {
        "patterns": [
            r"dns\s*tunnel",
            r"icmp\s*covert",
            r"http\s*beacon",
            r"websocket.*c2",
            r"covert\s*channel",
            r"data\s*exfil",
            r"staging\s*server",
            r"payload\s*download",
        ],
        "severity": Severity.CRITICAL,
        "type": "C2 Protocol Indicator",
        "category": "c2",
        "recommendation": "Document C2 protocol for network detection signatures"
    },
    "c2_cobalt_strike": {
        "patterns": [
            r"malleable\s*c2",
            r"beacon\s*payload",
            r"\.cobaltstrike",
            r"watermark\s*=\s*\d+",
            r"spawn\s*to",
            r"process\s*inject",
            r"post\s*ex",
            r"hashdump",
            r"mimikatz",
            r"logonpasswords",
        ],
        "severity": Severity.CRITICAL,
        "type": "Cobalt Strike Indicator",
        "category": "c2",
        "recommendation": "Cobalt Strike C2 detected - extract beacon configuration"
    },
    "c2_metasploit": {
        "patterns": [
            r"meterpreter",
            r"reverse_tcp",
            r"reverse_http",
            r"bind_tcp",
            r"staged\s*payload",
            r"multi/handler",
            r"exploit/multi",
            r"post/windows",
            r"post/linux",
            r"auxiliary/scanner",
        ],
        "severity": Severity.CRITICAL,
        "type": "Metasploit Framework Indicator",
        "category": "c2",
        "recommendation": "Metasploit C2 detected - analyze handler configuration"
    },
}

# Malware Behavior Indicators
MALWARE_DETECTION_PATTERNS = {
    "malware_persistence": {
        "patterns": [
            r"HKLM\\.*\\Run",
            r"HKCU\\.*\\Run",
            r"CurrentVersion\\Run",
            r"schtasks\s*/create",
            r"startup\s*folder",
            r"launchagent",
            r"launchdaemon",
            r"systemd\s*service",
            r"crontab",
            r"at\s*\d+:\d+",
            r"wmic\s*startup",
        ],
        "severity": Severity.HIGH,
        "type": "Persistence Mechanism",
        "category": "malware",
        "recommendation": "Document persistence technique for IOC development"
    },
    "malware_evasion": {
        "patterns": [
            r"virtualmachine\s*detect",
            r"sandbox\s*detect",
            r"vmware",
            r"virtualbox",
            r"qemu",
            r"hyperv",
            r"wine\s*detect",
            r"debugger\s*detect",
            r"IsDebuggerPresent",
            r"CheckRemoteDebugger",
            r"anti[_-]?analysis",
            r"anti[_-]?vm",
            r"anti[_-]?sandbox",
            r"sleep\s*evasion",
            r"timing\s*check",
        ],
        "severity": Severity.HIGH,
        "type": "Sandbox/VM Evasion",
        "category": "malware",
        "recommendation": "Evasion technique detected - use bare-metal analysis"
    },
    "malware_credential_theft": {
        "patterns": [
            r"password\s*dump",
            r"credential\s*harvest",
            r"keylog",
            r"browser\s*password",
            r"chrome\s*login",
            r"firefox\s*login",
            r"wallet\s*steal",
            r"crypto\s*wallet",
            r"clipboard\s*hijack",
            r"screenshot\s*capture",
            r"webcam\s*capture",
        ],
        "severity": Severity.CRITICAL,
        "type": "Credential Theft Capability",
        "category": "malware",
        "recommendation": "Information stealer capability detected"
    },
    "malware_ransomware": {
        "patterns": [
            r"ransom\s*note",
            r"\.encrypted",
            r"\.locked",
            r"bitcoin\s*address",
            r"monero\s*address",
            r"payment\s*instruction",
            r"decrypt\s*key",
            r"RSA\s*encrypt",
            r"AES\s*encrypt",
            r"file\s*encrypt",
            r"shadow\s*copy\s*delete",
            r"vssadmin\s*delete",
        ],
        "severity": Severity.CRITICAL,
        "type": "Ransomware Indicator",
        "category": "malware",
        "recommendation": "Ransomware capability detected - analyze encryption method"
    },
    "malware_dropper": {
        "patterns": [
            r"stage\s*2\s*payload",
            r"download\s*execute",
            r"powershell\s*-enc",
            r"certutil\s*-urlcache",
            r"bitsadmin\s*/transfer",
            r"wget\s+-O",
            r"curl\s+-o",
            r"invoke-webrequest",
            r"downloadstring",
            r"downloadfile",
            r"shellcode\s*inject",
        ],
        "severity": Severity.CRITICAL,
        "type": "Dropper/Downloader",
        "category": "malware",
        "recommendation": "Stage 2 payload delivery detected - analyze download URL"
    },
    "malware_rat": {
        "patterns": [
            r"remote\s*access",
            r"remote\s*shell",
            r"reverse\s*shell",
            r"bind\s*shell",
            r"remote\s*desktop",
            r"vnc\s*inject",
            r"rdp\s*wrapper",
            r"keylogger",
            r"screen\s*capture",
            r"file\s*manager",
            r"process\s*list",
            r"system\s*info",
        ],
        "severity": Severity.CRITICAL,
        "type": "RAT Capability",
        "category": "malware",
        "recommendation": "Remote Access Trojan functionality detected"
    },
}

# API Hooking & Process Injection Indicators
API_HOOKING_PATTERNS = {
    "api_hook_indicators": {
        "patterns": [
            r"CreateRemoteThread",
            r"NtCreateThreadEx",
            r"RtlCreateUserThread",
            r"WriteProcessMemory",
            r"VirtualAllocEx",
            r"NtMapViewOfSection",
            r"QueueUserAPC",
            r"SetWindowsHookEx",
            r"NtWriteVirtualMemory",
            r"NtProtectVirtualMemory",
        ],
        "severity": Severity.HIGH,
        "type": "Process Injection API",
        "category": "api_hook",
        "recommendation": "Process injection technique identified"
    },
    "dll_injection": {
        "patterns": [
            r"LoadLibrary",
            r"LdrLoadDll",
            r"DLL\s*inject",
            r"reflective\s*dll",
            r"manual\s*map",
            r"dll\s*hijack",
            r"search\s*order\s*hijack",
            r"phantom\s*dll",
            r"sideload",
        ],
        "severity": Severity.HIGH,
        "type": "DLL Injection",
        "category": "api_hook",
        "recommendation": "DLL injection technique detected"
    },
    "hook_evasion": {
        "patterns": [
            r"syscall\s*direct",
            r"ntdll\s*unhook",
            r"unhook\s*api",
            r"bypass\s*edr",
            r"bypass\s*av",
            r"amsi\s*bypass",
            r"etw\s*bypass",
            r"patch\s*ntdll",
            r"fresh\s*copy",
            r"heaven.*gate",
        ],
        "severity": Severity.CRITICAL,
        "type": "Security Bypass Technique",
        "category": "api_hook",
        "recommendation": "EDR/AV bypass technique detected"
    },
    "memory_manipulation": {
        "patterns": [
            r"process\s*hollow",
            r"process\s*doppelgang",
            r"process\s*herpaderp",
            r"transacted\s*hollow",
            r"ghostwriting",
            r"atom\s*bombing",
            r"module\s*stomp",
            r"early\s*bird",
            r"apc\s*inject",
        ],
        "severity": Severity.CRITICAL,
        "type": "Advanced Process Injection",
        "category": "api_hook",
        "recommendation": "Advanced injection technique - analyze execution flow"
    },
}

# Exploit and Vulnerability Indicators
EXPLOIT_DETECTION_PATTERNS = {
    "buffer_overflow": {
        "patterns": [
            r"stack\s*overflow",
            r"heap\s*overflow",
            r"buffer\s*overflow",
            r"EIP\s*overwrite",
            r"RIP\s*control",
            r"SEH\s*overwrite",
            r"ROP\s*chain",
            r"gadget\s*chain",
            r"shellcode",
            r"NOP\s*sled",
            r"\\x90{10,}",
        ],
        "severity": Severity.CRITICAL,
        "type": "Memory Corruption Exploit",
        "category": "exploit",
        "recommendation": "Buffer overflow exploit payload detected"
    },
    "format_string": {
        "patterns": [
            r"%n\s*%n",
            r"%x\s*%x\s*%x",
            r"%p\s*%p\s*%p",
            r"format\s*string",
            r"printf\s*vuln",
        ],
        "severity": Severity.CRITICAL,
        "type": "Format String Vulnerability",
        "category": "exploit",
        "recommendation": "Format string exploitation attempt detected"
    },
    "deserialization": {
        "patterns": [
            r"ysoserial",
            r"java\s*deserialize",
            r"pickle\s*load",
            r"unserialize",
            r"ObjectInputStream",
            r"readObject",
            r"__reduce__",
            r"gadget\s*chain",
            r"rmi\s*registry",
            r"jndi\s*inject",
        ],
        "severity": Severity.CRITICAL,
        "type": "Deserialization Attack",
        "category": "exploit",
        "recommendation": "Deserialization exploit detected - analyze gadget chain"
    },
    "prototype_pollution": {
        "patterns": [
            r"__proto__",
            r"constructor\s*\.\s*prototype",
            r"Object\.prototype",
            r"prototype\s*pollution",
            r"\[\"__proto__\"\]",
        ],
        "severity": Severity.HIGH,
        "type": "Prototype Pollution",
        "category": "exploit",
        "recommendation": "Prototype pollution attack detected"
    },
}

# Network Indicators for Sandbox Analysis
NETWORK_MALWARE_PATTERNS = {
    "suspicious_dns": {
        "patterns": [
            r"txt\s*record\s*exfil",
            r"dns\s*tunneling",
            r"subdomain\s*encode",
            r"base64\s*subdomain",
            r"hex\s*subdomain",
            r"\.duckdns\.org",
            r"\.no-ip\.org",
            r"\.ddns\.net",
            r"\.hopto\.org",
        ],
        "severity": Severity.HIGH,
        "type": "Suspicious DNS Activity",
        "category": "network",
        "recommendation": "DNS-based C2 or exfiltration detected"
    },
    "data_exfiltration": {
        "patterns": [
            r"upload\s*file",
            r"exfil\s*data",
            r"steal\s*data",
            r"send\s*loot",
            r"ftp\s*upload",
            r"http\s*post\s*data",
            r"telegram\s*bot",
            r"discord\s*webhook",
            r"slack\s*webhook",
        ],
        "severity": Severity.CRITICAL,
        "type": "Data Exfiltration",
        "category": "network",
        "recommendation": "Data exfiltration channel detected"
    },
    "proxy_tunnel": {
        "patterns": [
            r"socks\s*proxy",
            r"http\s*tunnel",
            r"ngrok",
            r"localtunnel",
            r"cloudflare\s*tunnel",
            r"frp\s*client",
            r"chisel",
            r"reverse\s*proxy",
            r"port\s*forward",
        ],
        "severity": Severity.HIGH,
        "type": "Proxy/Tunnel Infrastructure",
        "category": "network",
        "recommendation": "Network tunneling infrastructure detected"
    },
}

# Cryptominer Indicators
CRYPTOMINER_PATTERNS = {
    "mining_indicators": {
        "patterns": [
            r"stratum\+tcp",
            r"stratum\+ssl",
            r"pool\.(hashvault|minexmr|nanopool|f2pool|supportxmr)",
            r"xmrig",
            r"cpuminer",
            r"ethminer",
            r"monero\s*pool",
            r"bitcoin\s*pool",
            r"mining\s*pool",
            r"hashrate",
            r"worker\s*name",
            r"wallet\s*address.*\b4[0-9a-zA-Z]{94}\b",  # Monero address
            r"wallet\s*address.*\b0x[0-9a-fA-F]{40}\b",  # ETH address
        ],
        "severity": Severity.HIGH,
        "type": "Cryptominer Activity",
        "category": "cryptominer",
        "recommendation": "Cryptocurrency mining activity detected"
    },
    "browser_mining": {
        "patterns": [
            r"coinhive",
            r"cryptoloot",
            r"webassembly\s*mining",
            r"wasm\s*miner",
            r"browser\s*mining",
            r"coinimp",
            r"crypto-loot",
        ],
        "severity": Severity.MEDIUM,
        "type": "Browser-based Cryptominer",
        "category": "cryptominer",
        "recommendation": "Browser cryptojacking script detected"
    },
}

# Botnet Indicators
BOTNET_PATTERNS = {
    "botnet_commands": {
        "patterns": [
            r"ddos\s*attack",
            r"flood\s*attack",
            r"syn\s*flood",
            r"udp\s*flood",
            r"http\s*flood",
            r"slowloris",
            r"spam\s*send",
            r"spread\s*worm",
            r"infect\s*host",
            r"bot\s*command",
            r"bot\s*status",
            r"bot\s*list",
        ],
        "severity": Severity.CRITICAL,
        "type": "Botnet Command",
        "category": "botnet",
        "recommendation": "Botnet command/control functionality detected"
    },
    "irc_botnet": {
        "patterns": [
            r"irc\..*:\d{4}",
            r"PRIVMSG\s*#",
            r"JOIN\s*#",
            r"NICK\s*[a-z]{3,}\d+",
            r"irc\s*bot",
            r"irc\s*command",
        ],
        "severity": Severity.HIGH,
        "type": "IRC Botnet",
        "category": "botnet",
        "recommendation": "IRC-based botnet communication detected"
    },
}

# Combine all offensive patterns into a single lookup
OFFENSIVE_DETECTION_PATTERNS = {
    **C2_DETECTION_PATTERNS,
    **MALWARE_DETECTION_PATTERNS,
    **API_HOOKING_PATTERNS,
    **EXPLOIT_DETECTION_PATTERNS,
    **NETWORK_MALWARE_PATTERNS,
    **CRYPTOMINER_PATTERNS,
    **BOTNET_PATTERNS,
}


# Response length anomaly thresholds
LENGTH_ANOMALY_THRESHOLD = 0.3  # 30% deviation from baseline


def extract_positions_from_url(url: str) -> List[str]:
    """Extract position markers (§0§, §1§, etc.) from URL and return as list."""
    positions = re.findall(r'§(\d+)§', url)
    return [f"§{i}§" for i in sorted(set(int(p) for p in positions))]


def generate_payload_combinations(config: FuzzConfig) -> List[Tuple[List[str], int, int]]:
    """Generate payload combinations based on attack mode.
    
    Returns list of tuples: (payload_values, position_index, payload_index)
    """
    combinations = []
    payload_sets = [p for p in config.payloads if p]
    
    if not payload_sets:
        return []
    
    # Extract positions from URL if not explicitly provided
    positions = config.positions if config.positions else extract_positions_from_url(config.target_url)
    
    # If still no positions, use payload set count as position count
    num_positions = len(positions) if positions else len(payload_sets)
    
    if num_positions == 0:
        return []
    
    if config.attack_mode == AttackMode.SNIPER.value:
        # Test each position one at a time with each payload
        for set_idx, payload_set in enumerate(payload_sets):
            if set_idx >= num_positions:
                break
            for payload_idx, payload in enumerate(payload_set):
                combo = [""] * num_positions
                combo[set_idx] = payload
                combinations.append((combo, set_idx, payload_idx))
                
    elif config.attack_mode == AttackMode.BATTERING_RAM.value:
        # Same payload in all positions
        if payload_sets:
            for payload_idx, payload in enumerate(payload_sets[0]):
                combo = [payload] * num_positions
                combinations.append((combo, 0, payload_idx))
                
    elif config.attack_mode == AttackMode.PITCHFORK.value:
        # Parallel - position N gets payload set N, iterate in parallel
        min_len = min(len(s) for s in payload_sets) if payload_sets else 0
        for i in range(min_len):
            combo = [payload_sets[j][i] if j < len(payload_sets) else "" for j in range(num_positions)]
            combinations.append((combo, 0, i))
            
    elif config.attack_mode == AttackMode.CLUSTER_BOMB.value:
        # All combinations (cartesian product)
        def cartesian_product(arrays, index=0, current=[]):
            if index == len(arrays):
                return [current[:]]
            results = []
            for item in arrays[index]:
                current.append(item)
                results.extend(cartesian_product(arrays, index + 1, current))
                current.pop()
            return results
        
        if payload_sets:
            all_combos = cartesian_product(payload_sets)
            for i, combo in enumerate(all_combos):
                combinations.append((combo, 0, i))
    
    return combinations


def substitute_payloads(template: str, positions: List[str], payloads: List[str]) -> str:
    """Substitute payload markers in the template with actual payloads."""
    result = template
    for i, (pos, payload) in enumerate(zip(positions, payloads)):
        marker = f"§{i}§"
        result = result.replace(marker, payload)
        # Also try position value as marker
        result = result.replace(pos, payload)
    return result


def detect_anomalies(
    response: FuzzResponse, 
    baseline_length: Optional[int], 
    all_responses: List[FuzzResponse],
    include_offensive: bool = True
) -> List[str]:
    """Detect anomalies in the response that might indicate vulnerabilities.
    
    Args:
        response: The fuzz response to analyze
        baseline_length: The baseline response length for comparison
        all_responses: All responses in the session for statistical analysis
        include_offensive: Whether to include offensive security patterns (C2, malware, etc.)
    """
    flags = []
    
    # Check response body against standard detection patterns
    body_lower = response.body.lower()
    for pattern_name, pattern_config in DETECTION_PATTERNS.items():
        for pattern in pattern_config["patterns"]:
            if re.search(pattern, response.body, re.IGNORECASE):
                flags.append(pattern_config["type"])
                break
    
    # Check response body against offensive detection patterns
    if include_offensive:
        for pattern_name, pattern_config in OFFENSIVE_DETECTION_PATTERNS.items():
            for pattern in pattern_config["patterns"]:
                if re.search(pattern, response.body, re.IGNORECASE):
                    # Include category in the flag for better classification
                    category = pattern_config.get("category", "")
                    flag_name = f"[{category.upper()}] {pattern_config['type']}" if category else pattern_config["type"]
                    flags.append(flag_name)
                    break
    
    # Check for response length anomaly
    if baseline_length and all_responses:
        avg_length = sum(r.response_length for r in all_responses) / len(all_responses)
        if avg_length > 0:
            deviation = abs(response.response_length - avg_length) / avg_length
            if deviation > LENGTH_ANOMALY_THRESHOLD:
                flags.append("Response Length Anomaly")
    
    # Check for unusual status codes
    if response.status_code in [500, 502, 503]:
        flags.append("Server Error")
    elif response.status_code == 200 and any(err in body_lower for err in ["error", "exception", "warning"]):
        flags.append("Error in 200 Response")
    
    # Check for time-based anomalies (potential blind injection)
    if response.response_time > 5000:  # 5 seconds
        flags.append("Slow Response (Potential Time-Based Attack)")
    
    # Additional offensive indicators
    if include_offensive:
        # Check for base64 encoded payloads (common in malware)
        base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        if re.search(base64_pattern, response.body):
            flags.append("[MALWARE] Potential Encoded Payload")
        
        # Check for hex-encoded shellcode patterns
        hex_pattern = r'(\\x[0-9a-fA-F]{2}){10,}'
        if re.search(hex_pattern, response.body):
            flags.append("[EXPLOIT] Potential Shellcode")
        
        # Check for suspicious binary data in response
        if '\x00' in response.body[:1000]:
            flags.append("[MALWARE] Binary Data in Response")
    
    return list(set(flags))


def analyze_findings(responses: List[FuzzResponse], config: FuzzConfig) -> List[FuzzFinding]:
    """Analyze responses and generate security findings including offensive indicators."""
    findings = []
    
    # Combine all patterns for lookup
    all_patterns = {**DETECTION_PATTERNS, **OFFENSIVE_DETECTION_PATTERNS}
    
    for response in responses:
        if not response.flags:
            continue
            
        for flag in response.flags:
            # Clean the flag for pattern matching (remove category prefix)
            clean_flag = flag
            if flag.startswith("["):
                # Extract just the type part after the category
                parts = flag.split("] ", 1)
                if len(parts) > 1:
                    clean_flag = parts[1]
            
            # Find the pattern config for this flag
            found = False
            for pattern_name, pattern_config in all_patterns.items():
                if pattern_config["type"] == clean_flag or pattern_config["type"] in flag:
                    category = pattern_config.get("category", "")
                    finding = FuzzFinding(
                        type=flag,
                        severity=pattern_config["severity"].value if isinstance(pattern_config["severity"], Severity) else pattern_config["severity"],
                        description=f"Potential {clean_flag} detected with payload: {response.payload[:100]}",
                        payload=response.payload,
                        evidence=[
                            f"Status Code: {response.status_code}",
                            f"Response Length: {response.response_length}",
                            f"Response Time: {response.response_time}ms",
                            f"Category: {category}" if category else "Category: vulnerability",
                        ],
                        recommendation=pattern_config["recommendation"],
                        response_id=response.id,
                    )
                    findings.append(finding)
                    found = True
                    break
            
            if not found:
                # Generic finding for anomalies without specific patterns
                finding = FuzzFinding(
                    type=flag,
                    severity=Severity.MEDIUM.value,
                    description=f"{flag} detected with payload: {response.payload[:100]}",
                    payload=response.payload,
                    evidence=[
                        f"Status Code: {response.status_code}",
                        f"Response Length: {response.response_length}",
                        f"Response Time: {response.response_time}ms",
                    ],
                    recommendation="Investigate the anomalous response manually",
                    response_id=response.id,
                )
                findings.append(finding)
    
    return findings


async def execute_fuzz_request(
    client: httpx.AsyncClient,
    config: FuzzConfig,
    payloads: List[str],
    request_id: str,
    position_idx: int,
    payload_idx: int,
) -> FuzzResponse:
    """Execute a single fuzz request and return the response."""
    
    # Build the URL with payload substitution
    url = substitute_payloads(config.target_url, config.positions, payloads)
    
    # Build headers with payload substitution
    headers = {}
    for key, value in config.headers.items():
        headers[key] = substitute_payloads(value, config.positions, payloads)
    
    # Build body with payload substitution
    body = None
    if config.body:
        body = substitute_payloads(config.body, config.positions, payloads)
    
    payload_str = ", ".join(p for p in payloads if p)
    
    start_time = time.perf_counter()
    
    try:
        response = await client.request(
            method=config.method,
            url=url,
            headers=headers,
            content=body if body else None,
            follow_redirects=config.follow_redirects,
        )
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        # Get response body (limit size for memory)
        body_text = response.text[:50000] if len(response.text) > 50000 else response.text
        
        return FuzzResponse(
            id=request_id,
            payload=payload_str,
            status_code=response.status_code,
            response_length=len(response.content),
            response_time=round(elapsed_ms, 2),
            content_type=response.headers.get("content-type", ""),
            headers=dict(response.headers),
            body=body_text,
            timestamp=datetime.utcnow().isoformat(),
        )
        
    except httpx.TimeoutException:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return FuzzResponse(
            id=request_id,
            payload=payload_str,
            status_code=0,
            response_length=0,
            response_time=round(elapsed_ms, 2),
            content_type="",
            headers={},
            body="",
            timestamp=datetime.utcnow().isoformat(),
            error="Request timeout",
            flags=["Timeout"],
        )
        
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return FuzzResponse(
            id=request_id,
            payload=payload_str,
            status_code=0,
            response_length=0,
            response_time=round(elapsed_ms, 2),
            content_type="",
            headers={},
            body="",
            timestamp=datetime.utcnow().isoformat(),
            error=str(e),
            flags=["Request Error"],
        )


async def run_fuzzing_session(config: FuzzConfig) -> FuzzResult:
    """Run a complete fuzzing session with the given configuration."""
    
    # Normalize positions from URL if not provided
    if not config.positions:
        config.positions = extract_positions_from_url(config.target_url)
        # If still no positions found, create synthetic positions based on payload sets
        if not config.positions and config.payloads:
            config.positions = [f"§{i}§" for i in range(len(config.payloads))]
    
    responses: List[FuzzResponse] = []
    stats = FuzzStats(start_time=datetime.utcnow().isoformat())
    
    # Generate all payload combinations
    combinations = generate_payload_combinations(config)
    
    if not combinations:
        return FuzzResult(
            config=config,
            responses=[],
            findings=[],
            stats=stats,
        )
    
    stats.total_requests = len(combinations)
    
    # Configure HTTP client
    timeout = httpx.Timeout(config.timeout / 1000)  # Convert ms to seconds
    
    # Build client kwargs
    client_kwargs = {
        "timeout": timeout,
        "verify": False,
    }
    if config.proxy_url:
        client_kwargs["proxy"] = config.proxy_url
    
    async with httpx.AsyncClient(**client_kwargs) as client:
        # Use semaphore for concurrency control
        semaphore = asyncio.Semaphore(config.threads)
        
        async def bounded_request(combo, idx):
            async with semaphore:
                payloads, pos_idx, payload_idx = combo
                request_id = f"fuzz-{idx}-{int(time.time() * 1000)}"
                
                response = await execute_fuzz_request(
                    client=client,
                    config=config,
                    payloads=payloads,
                    request_id=request_id,
                    position_idx=pos_idx,
                    payload_idx=payload_idx,
                )
                
                # Apply delay if configured
                if config.delay > 0:
                    await asyncio.sleep(config.delay / 1000)
                
                return response
        
        # Execute all requests with controlled concurrency
        tasks = [bounded_request(combo, i) for i, combo in enumerate(combinations)]
        responses = await asyncio.gather(*tasks)
    
    # Calculate baseline response length (from first successful response)
    baseline_length = None
    for r in responses:
        if r.status_code == 200:
            baseline_length = r.response_length
            break
    
    # Detect anomalies and mark interesting responses
    for response in responses:
        flags = detect_anomalies(response, baseline_length, responses)
        response.flags.extend(flags)
        response.interesting = bool(response.flags)
    
    # Update statistics
    total_time = 0
    for r in responses:
        total_time += r.response_time
        if r.status_code >= 200 and r.status_code < 400:
            stats.success_count += 1
        elif r.error or r.status_code >= 400:
            stats.error_count += 1
        if r.interesting:
            stats.interesting_count += 1
    
    stats.avg_response_time = total_time / len(responses) if responses else 0
    stats.end_time = datetime.utcnow().isoformat()
    
    # Calculate requests per second
    if stats.start_time and stats.end_time:
        start = datetime.fromisoformat(stats.start_time)
        end = datetime.fromisoformat(stats.end_time)
        duration = (end - start).total_seconds()
        if duration > 0:
            stats.requests_per_second = round(len(responses) / duration, 2)
    
    # Analyze findings
    findings = analyze_findings(responses, config)
    
    return FuzzResult(
        config=config,
        responses=responses,
        findings=findings,
        stats=stats,
    )


async def stream_fuzzing_session(config: FuzzConfig) -> AsyncGenerator[Dict[str, Any], None]:
    """Stream fuzzing results as they come in (for real-time updates)."""
    
    # Normalize positions from URL if not provided
    if not config.positions:
        config.positions = extract_positions_from_url(config.target_url)
        # If still no positions found, create synthetic positions based on payload sets
        if not config.positions and config.payloads:
            config.positions = [f"§{i}§" for i in range(len(config.payloads))]
    
    combinations = generate_payload_combinations(config)
    
    if not combinations:
        yield {"type": "complete", "stats": FuzzStats().to_dict(), "findings": []}
        return
    
    total = len(combinations)
    responses: List[FuzzResponse] = []
    stats = FuzzStats(start_time=datetime.utcnow().isoformat(), total_requests=total)
    
    yield {"type": "start", "total": total}
    
    timeout = httpx.Timeout(config.timeout / 1000)
    
    # Build client kwargs
    client_kwargs = {
        "timeout": timeout,
        "verify": False,
    }
    if config.proxy_url:
        client_kwargs["proxy"] = config.proxy_url
    
    baseline_length = None
    
    async with httpx.AsyncClient(**client_kwargs) as client:
        semaphore = asyncio.Semaphore(config.threads)
        
        for i, combo in enumerate(combinations):
            async with semaphore:
                payloads, pos_idx, payload_idx = combo
                request_id = f"fuzz-{i}-{int(time.time() * 1000)}"
                
                response = await execute_fuzz_request(
                    client=client,
                    config=config,
                    payloads=payloads,
                    request_id=request_id,
                    position_idx=pos_idx,
                    payload_idx=payload_idx,
                )
                
                # Set baseline from first 200 response
                if baseline_length is None and response.status_code == 200:
                    baseline_length = response.response_length
                
                # Detect anomalies
                flags = detect_anomalies(response, baseline_length, responses)
                response.flags.extend(flags)
                response.interesting = bool(response.flags)
                
                responses.append(response)
                
                # Update stats
                if response.status_code >= 200 and response.status_code < 400:
                    stats.success_count += 1
                elif response.error or response.status_code >= 400:
                    stats.error_count += 1
                if response.interesting:
                    stats.interesting_count += 1
                
                # Yield progress update
                yield {
                    "type": "progress",
                    "current": i + 1,
                    "total": total,
                    "response": response.to_dict(),
                }
                
                # Apply delay
                if config.delay > 0:
                    await asyncio.sleep(config.delay / 1000)
    
    # Calculate final stats
    total_time = sum(r.response_time for r in responses)
    stats.avg_response_time = total_time / len(responses) if responses else 0
    stats.end_time = datetime.utcnow().isoformat()
    
    if stats.start_time and stats.end_time:
        start = datetime.fromisoformat(stats.start_time)
        end = datetime.fromisoformat(stats.end_time)
        duration = (end - start).total_seconds()
        if duration > 0:
            stats.requests_per_second = round(len(responses) / duration, 2)
    
    # Analyze findings
    findings = analyze_findings(responses, config)
    
    yield {
        "type": "complete",
        "stats": stats.to_dict(),
        "findings": [f.to_dict() for f in findings],
    }


def export_fuzz_results_json(result: FuzzResult) -> str:
    """Export fuzzing results as JSON."""
    return json.dumps(result.to_dict(), indent=2)


def export_fuzz_results_markdown(result: FuzzResult) -> str:
    """Export fuzzing results as Markdown report."""
    md = f"""# 🔒 Security Fuzzing Report

**Generated:** {datetime.utcnow().isoformat()}

**Target:** `{result.config.target_url}`

**Method:** {result.config.method}

**Attack Mode:** {result.config.attack_mode.title()}

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Total Requests | {result.stats.total_requests} |
| Successful (2xx/3xx) | {result.stats.success_count} |
| Errors | {result.stats.error_count} |
| Interesting Responses | {result.stats.interesting_count} |
| Avg Response Time | {result.stats.avg_response_time:.0f}ms |
| Requests/Second | {result.stats.requests_per_second} |

"""
    
    # Findings section
    if result.findings:
        md += "## 🔍 Security Findings\n\n"
        
        # Group by severity
        by_severity = {}
        for f in result.findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings = by_severity.get(severity, [])
            if findings:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "")
                md += f"### {emoji} {severity.upper()} ({len(findings)})\n\n"
                
                for f in findings:
                    md += f"#### {f.type}\n\n"
                    md += f"{f.description}\n\n"
                    md += f"**Payload:** `{f.payload[:100]}{'...' if len(f.payload) > 100 else ''}`\n\n"
                    md += f"**Evidence:**\n"
                    for e in f.evidence:
                        md += f"- {e}\n"
                    md += f"\n**Recommendation:** {f.recommendation}\n\n"
                    md += "---\n\n"
    
    # Interesting responses
    interesting = [r for r in result.responses if r.interesting]
    if interesting:
        md += "## ⚠️ Interesting Responses\n\n"
        md += "| Payload | Status | Length | Time | Flags |\n"
        md += "|---------|--------|--------|------|-------|\n"
        
        for r in interesting[:50]:
            flags = ", ".join(r.flags) if r.flags else "-"
            payload_short = r.payload[:40] + "..." if len(r.payload) > 40 else r.payload
            md += f"| `{payload_short}` | {r.status_code} | {r.response_length} | {r.response_time}ms | {flags} |\n"
        
        md += "\n"
    
    # Configuration
    md += "## ⚙️ Configuration\n\n"
    md += f"- **URL:** `{result.config.target_url}`\n"
    md += f"- **Method:** {result.config.method}\n"
    md += f"- **Attack Mode:** {result.config.attack_mode}\n"
    md += f"- **Threads:** {result.config.threads}\n"
    md += f"- **Delay:** {result.config.delay}ms\n"
    md += f"- **Timeout:** {result.config.timeout}ms\n"
    md += f"- **Positions:** {len(result.config.positions)}\n"
    
    md += "\n---\n\n*Report generated by VRAgent Security Fuzzer*\n"
    
    return md


# ============================================================================
# WEBSOCKET DEEP FUZZING
# Advanced WebSocket security testing with state-aware attacks
# ============================================================================

class WSAttackCategory(str, Enum):
    """WebSocket attack categories."""
    AUTH_BYPASS = "auth_bypass"
    STATE_MANIPULATION = "state_manipulation"
    FRAME_INJECTION = "frame_injection"
    MESSAGE_TAMPERING = "message_tampering"
    RACE_CONDITION = "race_condition"
    CSWSH = "cswsh"  # Cross-Site WebSocket Hijacking
    PROTOCOL_VIOLATION = "protocol_violation"
    DENIAL_OF_SERVICE = "dos"


@dataclass
class WSFuzzConfig:
    """Configuration for WebSocket fuzzing."""
    target_url: str  # ws:// or wss:// URL
    initial_messages: List[str] = field(default_factory=list)  # Messages to establish state
    auth_token: Optional[str] = None
    auth_header: str = "Authorization"
    origin: Optional[str] = None  # For CSWSH testing
    subprotocols: List[str] = field(default_factory=list)
    attack_categories: List[str] = field(default_factory=lambda: ["all"])
    custom_payloads: List[str] = field(default_factory=list)
    message_template: str = ""  # Template with §0§ markers
    timeout: int = 10000  # ms
    delay_between_tests: int = 100  # ms
    max_messages_per_test: int = 10
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WSFuzzResult:
    """Result from a WebSocket fuzz test."""
    id: str
    category: str
    test_name: str
    payload: str
    messages_sent: List[Dict[str, Any]]
    messages_received: List[Dict[str, Any]]
    connection_state: str  # "connected", "closed", "error"
    close_code: Optional[int] = None
    close_reason: Optional[str] = None
    duration_ms: float = 0
    interesting: bool = False
    flags: List[str] = field(default_factory=list)
    vulnerability_detected: bool = False
    severity: str = "info"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WSFuzzStats:
    """Statistics for WebSocket fuzzing session."""
    total_tests: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    interesting_count: int = 0
    vulnerabilities_found: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    tests_per_category: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WSFuzzSession:
    """Complete WebSocket fuzzing session."""
    config: WSFuzzConfig
    results: List[WSFuzzResult]
    stats: WSFuzzStats
    findings: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "results": [r.to_dict() for r in self.results],
            "stats": self.stats.to_dict(),
            "findings": self.findings,
        }


# WebSocket Attack Payloads by Category
WS_ATTACK_PAYLOADS = {
    WSAttackCategory.AUTH_BYPASS: {
        "name": "Authentication Bypass",
        "description": "Tests for authentication and authorization bypass vulnerabilities",
        "payloads": [
            # Missing/invalid auth tokens
            {"type": "no_auth", "payload": '{"action": "get_data"}', "description": "Request without authentication"},
            {"type": "empty_token", "payload": '{"token": "", "action": "get_data"}', "description": "Empty auth token"},
            {"type": "null_token", "payload": '{"token": null, "action": "get_data"}', "description": "Null auth token"},
            {"type": "admin_role", "payload": '{"role": "admin", "action": "get_users"}', "description": "Self-assigned admin role"},
            {"type": "user_id_zero", "payload": '{"user_id": 0, "action": "get_profile"}', "description": "User ID zero"},
            {"type": "user_id_negative", "payload": '{"user_id": -1, "action": "get_profile"}', "description": "Negative user ID"},
            {"type": "jwt_none_alg", "payload": '{"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiYWRtaW4iOnRydWV9.", "action": "admin"}', "description": "JWT with none algorithm"},
            {"type": "idor", "payload": '{"user_id": "OTHER_USER_ID", "action": "view_data"}', "description": "IDOR - access other user data"},
        ],
        "severity": "high",
    },
    WSAttackCategory.STATE_MANIPULATION: {
        "name": "State Machine Manipulation",
        "description": "Tests for state machine vulnerabilities and workflow bypass",
        "payloads": [
            # Out-of-order state transitions
            {"type": "skip_auth", "payload": '{"action": "execute", "skip_validation": true}', "description": "Skip authentication step"},
            {"type": "replay_init", "payload": '{"action": "init", "session_id": "EXISTING"}', "description": "Replay initialization"},
            {"type": "double_action", "payload": '{"action": "complete"}', "description": "Double-complete action"},
            {"type": "revert_state", "payload": '{"action": "set_state", "state": "initial"}', "description": "Revert to initial state"},
            {"type": "parallel_state", "payload": '{"action": "fork_state"}', "description": "Create parallel state"},
            {"type": "negative_seq", "payload": '{"seq": -1, "action": "process"}', "description": "Negative sequence number"},
            {"type": "overflow_seq", "payload": '{"seq": 999999999999, "action": "process"}', "description": "Sequence overflow"},
        ],
        "severity": "medium",
    },
    WSAttackCategory.FRAME_INJECTION: {
        "name": "Frame Injection & Manipulation",
        "description": "Tests WebSocket frame-level vulnerabilities",
        "payloads": [
            # Malformed frames
            {"type": "oversized_frame", "payload": "A" * 100000, "description": "Oversized frame"},
            {"type": "fragmented_attack", "payload": '{"act', "description": "Incomplete JSON (fragmentation)"},
            {"type": "binary_in_text", "payload": b"\x00\x01\x02\x03\x04".decode('latin-1'), "description": "Binary data in text frame"},
            {"type": "utf8_invalid", "payload": "\xff\xfe invalid utf-8", "description": "Invalid UTF-8 sequence"},
            {"type": "control_chars", "payload": '{"data": "\x00\x01\x02\x03"}', "description": "Control characters"},
            {"type": "null_byte", "payload": '{"action": "test\x00admin"}', "description": "Null byte injection"},
            {"type": "ping_flood", "payload": "PING", "description": "Ping frame flood"},
        ],
        "severity": "medium",
    },
    WSAttackCategory.MESSAGE_TAMPERING: {
        "name": "Message Content Tampering",
        "description": "Tests for injection vulnerabilities in message content",
        "payloads": [
            # Injection payloads
            {"type": "sqli", "payload": '{"query": "\' OR 1=1--"}', "description": "SQL injection in message"},
            {"type": "nosqli", "payload": '{"filter": {"$gt": ""}}', "description": "NoSQL injection"},
            {"type": "xss", "payload": '{"message": "<script>alert(1)</script>"}', "description": "XSS in message"},
            {"type": "ssti", "payload": '{"template": "{{7*7}}"}', "description": "SSTI in message"},
            {"type": "cmdi", "payload": '{"cmd": "test; id"}', "description": "Command injection"},
            {"type": "path_traversal", "payload": '{"file": "../../../etc/passwd"}', "description": "Path traversal"},
            {"type": "xxe", "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "description": "XXE injection"},
            {"type": "json_injection", "payload": '{"data": "value", "__proto__": {"admin": true}}', "description": "Prototype pollution"},
            {"type": "deserialization", "payload": '{"__class__": "os.system", "args": ["id"]}', "description": "Insecure deserialization"},
        ],
        "severity": "high",
    },
    WSAttackCategory.RACE_CONDITION: {
        "name": "Race Condition Testing",
        "description": "Tests for race conditions in concurrent message handling",
        "payloads": [
            # Race condition scenarios
            {"type": "parallel_transfer", "payload": '{"action": "transfer", "amount": 100, "race": true}', "description": "Parallel fund transfer"},
            {"type": "double_spend", "payload": '{"action": "spend", "item_id": "1"}', "description": "Double-spend attack"},
            {"type": "concurrent_update", "payload": '{"action": "update", "field": "balance"}', "description": "Concurrent update"},
            {"type": "lock_bypass", "payload": '{"action": "acquire_lock", "force": true}', "description": "Lock bypass attempt"},
        ],
        "severity": "high",
    },
    WSAttackCategory.CSWSH: {
        "name": "Cross-Site WebSocket Hijacking",
        "description": "Tests for CSWSH vulnerabilities",
        "payloads": [
            # Origin manipulation
            {"type": "no_origin", "origin": None, "payload": '{"action": "get_data"}', "description": "Request without Origin"},
            {"type": "null_origin", "origin": "null", "payload": '{"action": "get_data"}', "description": "Null origin"},
            {"type": "evil_origin", "origin": "https://evil.com", "payload": '{"action": "get_data"}', "description": "Malicious origin"},
            {"type": "subdomain_origin", "origin": "https://evil.target.com", "payload": '{"action": "get_data"}', "description": "Subdomain takeover origin"},
            {"type": "port_origin", "origin": "https://target.com:8443", "payload": '{"action": "get_data"}', "description": "Different port origin"},
        ],
        "severity": "critical",
    },
    WSAttackCategory.PROTOCOL_VIOLATION: {
        "name": "Protocol Violation",
        "description": "Tests WebSocket protocol implementation",
        "payloads": [
            # Protocol-level attacks
            {"type": "invalid_opcode", "payload": "INVALID_OPCODE", "description": "Invalid WebSocket opcode"},
            {"type": "reserved_bits", "payload": "RESERVED_BITS_SET", "description": "Reserved bits manipulation"},
            {"type": "mask_violation", "payload": "UNMASKED_CLIENT_FRAME", "description": "Unmasked client frame"},
            {"type": "close_code_invalid", "payload": "CLOSE_1005", "description": "Invalid close code"},
            {"type": "subprotocol_mismatch", "payload": '{"protocol": "invalid"}', "description": "Subprotocol mismatch"},
        ],
        "severity": "low",
    },
    WSAttackCategory.DENIAL_OF_SERVICE: {
        "name": "Denial of Service",
        "description": "Tests for DoS vulnerabilities",
        "payloads": [
            # DoS payloads
            {"type": "large_message", "payload": "X" * 1000000, "description": "1MB message"},
            {"type": "nested_json", "payload": '{"a":' * 100 + '1' + '}' * 100, "description": "Deeply nested JSON"},
            {"type": "regex_dos", "payload": '{"pattern": "' + 'a' * 30 + '!"}', "description": "ReDoS payload"},
            {"type": "rapid_reconnect", "payload": "RAPID_RECONNECT", "description": "Rapid connection cycling"},
            {"type": "resource_exhaustion", "payload": '{"action": "create", "count": 999999}', "description": "Resource exhaustion"},
        ],
        "severity": "medium",
    },
}


async def execute_ws_test(
    config: WSFuzzConfig,
    category: WSAttackCategory,
    test: Dict[str, Any],
    test_id: str,
) -> WSFuzzResult:
    """Execute a single WebSocket fuzz test."""
    import websockets
    from websockets.exceptions import WebSocketException
    
    messages_sent = []
    messages_received = []
    connection_state = "unknown"
    close_code = None
    close_reason = None
    flags = []
    start_time = time.perf_counter()
    
    try:
        # Build connection headers
        extra_headers = {}
        if config.auth_token:
            extra_headers[config.auth_header] = config.auth_token
        
        # Handle origin for CSWSH testing
        origin = config.origin
        if category == WSAttackCategory.CSWSH and "origin" in test:
            origin = test.get("origin")
        if origin:
            extra_headers["Origin"] = origin
        
        async with websockets.connect(
            config.target_url,
            extra_headers=extra_headers if extra_headers else None,
            subprotocols=config.subprotocols or None,
            close_timeout=config.timeout / 1000,
            open_timeout=config.timeout / 1000,
        ) as websocket:
            connection_state = "connected"
            
            # Send initial messages to establish state
            for init_msg in config.initial_messages:
                await websocket.send(init_msg)
                messages_sent.append({"type": "init", "content": init_msg, "time": time.perf_counter() - start_time})
                
                try:
                    response = await asyncio.wait_for(
                        websocket.recv(),
                        timeout=config.timeout / 1000
                    )
                    messages_received.append({"type": "init_response", "content": str(response)[:1000], "time": time.perf_counter() - start_time})
                except asyncio.TimeoutError:
                    pass
            
            # Send the test payload
            payload = test.get("payload", "")
            if config.message_template:
                payload = config.message_template.replace("§0§", payload).replace("FUZZ", payload)
            
            await websocket.send(payload)
            messages_sent.append({"type": "test", "content": payload[:1000], "time": time.perf_counter() - start_time})
            
            # Collect responses
            for _ in range(config.max_messages_per_test):
                try:
                    response = await asyncio.wait_for(
                        websocket.recv(),
                        timeout=2  # Short timeout for responses
                    )
                    response_str = str(response)[:5000]
                    messages_received.append({"type": "response", "content": response_str, "time": time.perf_counter() - start_time})
                    
                    # Analyze response for vulnerabilities
                    response_lower = response_str.lower()
                    
                    # Check for error messages that might indicate vulnerabilities
                    if any(err in response_lower for err in ["sql", "syntax error", "mysql", "postgresql", "oracle"]):
                        flags.append("SQL Error Detected")
                    if any(err in response_lower for err in ["exception", "traceback", "stack trace", "error:"]):
                        flags.append("Error Disclosure")
                    if any(err in response_lower for err in ["root:", "/etc/passwd", "c:\\windows"]):
                        flags.append("Sensitive File Content")
                    if "<script>" in response_lower or "javascript:" in response_lower:
                        flags.append("XSS Reflection")
                    if "admin" in response_lower and category == WSAttackCategory.AUTH_BYPASS:
                        flags.append("Potential Auth Bypass")
                        
                except asyncio.TimeoutError:
                    break
            
            # Gracefully close
            connection_state = "closed"
            
    except websockets.exceptions.InvalidStatusCode as e:
        connection_state = "rejected"
        close_code = e.status_code
        flags.append(f"Connection rejected: {e.status_code}")
        
        # For CSWSH testing, rejection might be good (proper origin checking)
        if category == WSAttackCategory.CSWSH and e.status_code in [401, 403]:
            flags.append("Origin properly validated (good)")
            
    except websockets.exceptions.InvalidHandshake as e:
        connection_state = "handshake_failed"
        flags.append(f"Handshake failed: {str(e)[:100]}")
        
    except Exception as e:
        connection_state = "error"
        flags.append(f"Error: {str(e)[:100]}")
    
    duration_ms = (time.perf_counter() - start_time) * 1000
    
    # Determine if result is interesting
    interesting = bool(flags) or (
        category == WSAttackCategory.AUTH_BYPASS and connection_state == "connected" and messages_received
    ) or (
        category == WSAttackCategory.CSWSH and connection_state == "connected"
    )
    
    # Determine vulnerability detection
    vulnerability_detected = any(f in ["SQL Error Detected", "Sensitive File Content", "Potential Auth Bypass", "XSS Reflection"] for f in flags)
    
    # For CSWSH, successful connection with malicious origin is a vulnerability
    if category == WSAttackCategory.CSWSH and test.get("origin") and connection_state == "connected":
        vulnerability_detected = True
        flags.append("CSWSH Vulnerability - Connection accepted with malicious origin")
    
    severity = WS_ATTACK_PAYLOADS.get(category, {}).get("severity", "info")
    if vulnerability_detected:
        severity = "high" if severity in ["high", "critical"] else "medium"
    
    return WSFuzzResult(
        id=test_id,
        category=category.value,
        test_name=test.get("description", test.get("type", "unknown")),
        payload=test.get("payload", "")[:500],
        messages_sent=messages_sent,
        messages_received=messages_received,
        connection_state=connection_state,
        close_code=close_code,
        close_reason=close_reason,
        duration_ms=round(duration_ms, 2),
        interesting=interesting,
        flags=flags,
        vulnerability_detected=vulnerability_detected,
        severity=severity,
    )


async def run_websocket_fuzzing(config: WSFuzzConfig) -> WSFuzzSession:
    """Run a complete WebSocket fuzzing session."""
    results: List[WSFuzzResult] = []
    stats = WSFuzzStats(start_time=datetime.utcnow().isoformat())
    findings = []
    
    # Determine which categories to test
    if "all" in config.attack_categories:
        categories = list(WSAttackCategory)
    else:
        categories = [WSAttackCategory(cat) for cat in config.attack_categories if cat in [c.value for c in WSAttackCategory]]
    
    test_count = 0
    
    for category in categories:
        attack_config = WS_ATTACK_PAYLOADS.get(category, {})
        payloads = attack_config.get("payloads", [])
        
        for test in payloads:
            test_id = f"ws-{category.value}-{test_count}-{int(time.time() * 1000)}"
            
            try:
                result = await execute_ws_test(config, category, test, test_id)
                results.append(result)
                
                # Update stats
                stats.total_tests += 1
                if result.connection_state == "connected":
                    stats.successful_connections += 1
                else:
                    stats.failed_connections += 1
                if result.interesting:
                    stats.interesting_count += 1
                if result.vulnerability_detected:
                    stats.vulnerabilities_found += 1
                    
                    # Add to findings
                    findings.append({
                        "type": attack_config.get("name", category.value),
                        "severity": result.severity,
                        "description": f"{result.test_name} - {', '.join(result.flags)}",
                        "payload": result.payload,
                        "evidence": result.flags,
                        "recommendation": get_ws_recommendation(category),
                    })
                
                stats.tests_per_category[category.value] = stats.tests_per_category.get(category.value, 0) + 1
                
            except Exception as e:
                logger.exception(f"WebSocket test failed: {e}")
            
            test_count += 1
            
            # Apply delay between tests
            if config.delay_between_tests > 0:
                await asyncio.sleep(config.delay_between_tests / 1000)
    
    # Also run custom payloads if provided
    if config.custom_payloads:
        for payload in config.custom_payloads:
            test_id = f"ws-custom-{test_count}-{int(time.time() * 1000)}"
            test = {"type": "custom", "payload": payload, "description": f"Custom payload: {payload[:50]}"}
            
            try:
                result = await execute_ws_test(config, WSAttackCategory.MESSAGE_TAMPERING, test, test_id)
                results.append(result)
                stats.total_tests += 1
                if result.interesting:
                    stats.interesting_count += 1
            except Exception as e:
                logger.exception(f"Custom WebSocket test failed: {e}")
            
            test_count += 1
    
    stats.end_time = datetime.utcnow().isoformat()
    
    return WSFuzzSession(
        config=config,
        results=results,
        stats=stats,
        findings=findings,
    )


async def stream_websocket_fuzzing(config: WSFuzzConfig) -> AsyncGenerator[Dict[str, Any], None]:
    """Stream WebSocket fuzzing results as they come in."""
    stats = WSFuzzStats(start_time=datetime.utcnow().isoformat())
    findings = []
    
    # Determine categories
    if "all" in config.attack_categories:
        categories = list(WSAttackCategory)
    else:
        categories = [WSAttackCategory(cat) for cat in config.attack_categories if cat in [c.value for c in WSAttackCategory]]
    
    # Calculate total tests
    total_tests = sum(len(WS_ATTACK_PAYLOADS.get(cat, {}).get("payloads", [])) for cat in categories)
    total_tests += len(config.custom_payloads)
    
    yield {"type": "start", "total": total_tests, "categories": [c.value for c in categories]}
    
    test_count = 0
    
    for category in categories:
        attack_config = WS_ATTACK_PAYLOADS.get(category, {})
        payloads = attack_config.get("payloads", [])
        
        for test in payloads:
            test_id = f"ws-{category.value}-{test_count}-{int(time.time() * 1000)}"
            
            try:
                result = await execute_ws_test(config, category, test, test_id)
                
                stats.total_tests += 1
                if result.connection_state == "connected":
                    stats.successful_connections += 1
                else:
                    stats.failed_connections += 1
                if result.interesting:
                    stats.interesting_count += 1
                if result.vulnerability_detected:
                    stats.vulnerabilities_found += 1
                    findings.append({
                        "type": attack_config.get("name", category.value),
                        "severity": result.severity,
                        "description": f"{result.test_name} - {', '.join(result.flags)}",
                        "payload": result.payload,
                        "evidence": result.flags,
                        "recommendation": get_ws_recommendation(category),
                    })
                
                yield {
                    "type": "progress",
                    "current": test_count + 1,
                    "total": total_tests,
                    "category": category.value,
                    "result": result.to_dict(),
                }
                
            except Exception as e:
                yield {
                    "type": "error",
                    "test_id": test_id,
                    "message": str(e),
                }
            
            test_count += 1
            
            if config.delay_between_tests > 0:
                await asyncio.sleep(config.delay_between_tests / 1000)
    
    # Custom payloads
    for payload in config.custom_payloads:
        test_id = f"ws-custom-{test_count}-{int(time.time() * 1000)}"
        test = {"type": "custom", "payload": payload, "description": f"Custom: {payload[:50]}"}
        
        try:
            result = await execute_ws_test(config, WSAttackCategory.MESSAGE_TAMPERING, test, test_id)
            stats.total_tests += 1
            if result.interesting:
                stats.interesting_count += 1
            
            yield {
                "type": "progress",
                "current": test_count + 1,
                "total": total_tests,
                "category": "custom",
                "result": result.to_dict(),
            }
        except Exception as e:
            yield {"type": "error", "test_id": test_id, "message": str(e)}
        
        test_count += 1
    
    stats.end_time = datetime.utcnow().isoformat()
    
    yield {
        "type": "complete",
        "stats": stats.to_dict(),
        "findings": findings,
    }


def get_ws_recommendation(category: WSAttackCategory) -> str:
    """Get security recommendation for a WebSocket vulnerability category."""
    recommendations = {
        WSAttackCategory.AUTH_BYPASS: "Implement proper authentication for all WebSocket messages. Validate tokens server-side and enforce authorization checks on every operation.",
        WSAttackCategory.STATE_MANIPULATION: "Implement a robust state machine on the server side. Validate all state transitions and reject out-of-order operations.",
        WSAttackCategory.FRAME_INJECTION: "Implement strict input validation and frame size limits. Use a well-tested WebSocket library that handles frame parsing securely.",
        WSAttackCategory.MESSAGE_TAMPERING: "Sanitize and validate all message content. Use parameterized queries for database operations and encode output appropriately.",
        WSAttackCategory.RACE_CONDITION: "Implement proper locking mechanisms and transaction isolation. Use atomic operations for sensitive state changes.",
        WSAttackCategory.CSWSH: "Implement strict Origin validation. Only accept connections from trusted origins and implement CSRF tokens for WebSocket connections.",
        WSAttackCategory.PROTOCOL_VIOLATION: "Use a robust WebSocket library and implement proper error handling. Reject malformed frames and close connections gracefully.",
        WSAttackCategory.DENIAL_OF_SERVICE: "Implement rate limiting, message size limits, and connection limits. Monitor for abnormal patterns and implement circuit breakers.",
    }
    return recommendations.get(category, "Review the vulnerability and implement appropriate security controls.")


# ============================================================================
# COVERAGE TRACKING & VISUALIZATION
# Track testing coverage across endpoints, parameters, and techniques
# ============================================================================

class CoverageStatus(str, Enum):
    """Coverage status for a technique/endpoint."""
    NOT_TESTED = "not_tested"
    TESTED = "tested"
    VULNERABLE = "vulnerable"
    SECURE = "secure"
    INCONCLUSIVE = "inconclusive"


class TechniqueCategory(str, Enum):
    """Categories of security testing techniques."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_EXPOSURE = "data_exposure"
    SECURITY_MISCONFIG = "security_misconfiguration"
    XSS = "xss"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    COMPONENTS = "vulnerable_components"
    LOGGING = "logging_monitoring"
    SSRF = "ssrf"
    WEBSOCKET = "websocket"


@dataclass
class TechniqueMetadata:
    """Metadata for a security testing technique."""
    id: str
    name: str
    category: str
    owasp_category: str  # OWASP Top 10 mapping
    description: str
    severity: str
    payloads_required: int
    estimated_time: int  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EndpointCoverage:
    """Coverage information for a single endpoint."""
    endpoint: str
    method: str
    parameters: List[str]
    techniques_tested: Dict[str, CoverageStatus]
    findings: List[str]
    last_tested: Optional[str]
    total_requests: int
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["techniques_tested"] = {k: v.value for k, v in self.techniques_tested.items()}
        return result


@dataclass
class CoverageSession:
    """Complete coverage tracking session."""
    session_id: str
    target_base_url: str
    endpoints: Dict[str, EndpointCoverage]
    overall_stats: Dict[str, Any]
    technique_coverage: Dict[str, Dict[str, Any]]
    owasp_coverage: Dict[str, Dict[str, Any]]
    started_at: str
    updated_at: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_base_url": self.target_base_url,
            "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
            "overall_stats": self.overall_stats,
            "technique_coverage": self.technique_coverage,
            "owasp_coverage": self.owasp_coverage,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }


# Technique metadata registry
TECHNIQUE_REGISTRY: Dict[str, TechniqueMetadata] = {
    # Injection techniques
    "sqli_error": TechniqueMetadata("sqli_error", "SQL Injection (Error-based)", TechniqueCategory.INJECTION.value, "A03:2021", "Error-based SQL injection detection", "critical", 20, 30),
    "sqli_blind_boolean": TechniqueMetadata("sqli_blind_boolean", "SQL Injection (Boolean-blind)", TechniqueCategory.INJECTION.value, "A03:2021", "Boolean-based blind SQL injection", "critical", 50, 120),
    "sqli_blind_time": TechniqueMetadata("sqli_blind_time", "SQL Injection (Time-blind)", TechniqueCategory.INJECTION.value, "A03:2021", "Time-based blind SQL injection", "critical", 20, 180),
    "sqli_union": TechniqueMetadata("sqli_union", "SQL Injection (UNION-based)", TechniqueCategory.INJECTION.value, "A03:2021", "UNION-based SQL injection", "critical", 30, 60),
    "nosql_injection": TechniqueMetadata("nosql_injection", "NoSQL Injection", TechniqueCategory.INJECTION.value, "A03:2021", "NoSQL database injection", "high", 15, 30),
    "ldap_injection": TechniqueMetadata("ldap_injection", "LDAP Injection", TechniqueCategory.INJECTION.value, "A03:2021", "LDAP injection vulnerabilities", "high", 10, 20),
    "xpath_injection": TechniqueMetadata("xpath_injection", "XPath Injection", TechniqueCategory.INJECTION.value, "A03:2021", "XPath injection attacks", "high", 10, 20),
    "command_injection": TechniqueMetadata("command_injection", "OS Command Injection", TechniqueCategory.INJECTION.value, "A03:2021", "Operating system command injection", "critical", 25, 45),
    "ssti": TechniqueMetadata("ssti", "Server-Side Template Injection", TechniqueCategory.INJECTION.value, "A03:2021", "Template engine injection", "critical", 30, 60),
    "header_injection": TechniqueMetadata("header_injection", "HTTP Header Injection", TechniqueCategory.INJECTION.value, "A03:2021", "HTTP response header injection", "medium", 15, 20),
    
    # XSS techniques
    "xss_reflected": TechniqueMetadata("xss_reflected", "Reflected XSS", TechniqueCategory.XSS.value, "A03:2021", "Reflected cross-site scripting", "high", 40, 60),
    "xss_stored": TechniqueMetadata("xss_stored", "Stored XSS", TechniqueCategory.XSS.value, "A03:2021", "Stored cross-site scripting", "high", 30, 90),
    "xss_dom": TechniqueMetadata("xss_dom", "DOM-based XSS", TechniqueCategory.XSS.value, "A03:2021", "DOM-based cross-site scripting", "high", 25, 45),
    
    # Authentication
    "auth_bypass": TechniqueMetadata("auth_bypass", "Authentication Bypass", TechniqueCategory.AUTHENTICATION.value, "A07:2021", "Authentication mechanism bypass", "critical", 20, 40),
    "brute_force": TechniqueMetadata("brute_force", "Brute Force Protection", TechniqueCategory.AUTHENTICATION.value, "A07:2021", "Account lockout and rate limiting", "medium", 100, 120),
    "session_fixation": TechniqueMetadata("session_fixation", "Session Fixation", TechniqueCategory.AUTHENTICATION.value, "A07:2021", "Session fixation vulnerability", "high", 10, 30),
    "jwt_attacks": TechniqueMetadata("jwt_attacks", "JWT Security", TechniqueCategory.AUTHENTICATION.value, "A07:2021", "JWT token vulnerabilities", "high", 25, 45),
    
    # Authorization
    "idor": TechniqueMetadata("idor", "IDOR", TechniqueCategory.AUTHORIZATION.value, "A01:2021", "Insecure direct object references", "high", 50, 60),
    "privilege_escalation": TechniqueMetadata("privilege_escalation", "Privilege Escalation", TechniqueCategory.AUTHORIZATION.value, "A01:2021", "Vertical/horizontal privilege escalation", "critical", 20, 45),
    "forced_browsing": TechniqueMetadata("forced_browsing", "Forced Browsing", TechniqueCategory.AUTHORIZATION.value, "A01:2021", "Unauthorized resource access", "medium", 100, 90),
    
    # Data Exposure
    "sensitive_data_exposure": TechniqueMetadata("sensitive_data_exposure", "Sensitive Data Exposure", TechniqueCategory.DATA_EXPOSURE.value, "A02:2021", "Unprotected sensitive data", "high", 30, 45),
    "information_disclosure": TechniqueMetadata("information_disclosure", "Information Disclosure", TechniqueCategory.DATA_EXPOSURE.value, "A02:2021", "Server and technology fingerprinting", "low", 20, 30),
    "path_traversal": TechniqueMetadata("path_traversal", "Path Traversal", TechniqueCategory.DATA_EXPOSURE.value, "A01:2021", "Directory traversal attacks", "high", 30, 45),
    
    # Security Misconfiguration
    "cors_misconfig": TechniqueMetadata("cors_misconfig", "CORS Misconfiguration", TechniqueCategory.SECURITY_MISCONFIG.value, "A05:2021", "Cross-origin resource sharing issues", "medium", 10, 20),
    "security_headers": TechniqueMetadata("security_headers", "Security Headers", TechniqueCategory.SECURITY_MISCONFIG.value, "A05:2021", "Missing security headers", "low", 5, 10),
    "debug_mode": TechniqueMetadata("debug_mode", "Debug Mode Enabled", TechniqueCategory.SECURITY_MISCONFIG.value, "A05:2021", "Debug mode in production", "medium", 5, 10),
    "default_credentials": TechniqueMetadata("default_credentials", "Default Credentials", TechniqueCategory.SECURITY_MISCONFIG.value, "A05:2021", "Default username/password combinations", "high", 50, 60),
    
    # SSRF
    "ssrf_basic": TechniqueMetadata("ssrf_basic", "SSRF (Basic)", TechniqueCategory.SSRF.value, "A10:2021", "Server-side request forgery", "high", 20, 40),
    "ssrf_blind": TechniqueMetadata("ssrf_blind", "SSRF (Blind)", TechniqueCategory.SSRF.value, "A10:2021", "Blind SSRF with OOB detection", "high", 15, 60),
    
    # Deserialization
    "insecure_deserialization": TechniqueMetadata("insecure_deserialization", "Insecure Deserialization", TechniqueCategory.INSECURE_DESERIALIZATION.value, "A08:2021", "Object deserialization vulnerabilities", "critical", 20, 45),
    
    # WebSocket
    "ws_auth_bypass": TechniqueMetadata("ws_auth_bypass", "WebSocket Auth Bypass", TechniqueCategory.WEBSOCKET.value, "A07:2021", "WebSocket authentication bypass", "high", 15, 30),
    "ws_cswsh": TechniqueMetadata("ws_cswsh", "Cross-Site WebSocket Hijacking", TechniqueCategory.WEBSOCKET.value, "A07:2021", "CSWSH vulnerability", "critical", 10, 20),
    "ws_injection": TechniqueMetadata("ws_injection", "WebSocket Message Injection", TechniqueCategory.WEBSOCKET.value, "A03:2021", "Injection via WebSocket messages", "high", 25, 45),
}

# OWASP Top 10 2021 categories
OWASP_CATEGORIES = {
    "A01:2021": {"name": "Broken Access Control", "description": "Access control enforces policy such that users cannot act outside of their intended permissions"},
    "A02:2021": {"name": "Cryptographic Failures", "description": "Failures related to cryptography which often lead to sensitive data exposure"},
    "A03:2021": {"name": "Injection", "description": "Injection flaws occur when untrusted data is sent to an interpreter"},
    "A04:2021": {"name": "Insecure Design", "description": "Risks related to design and architectural flaws"},
    "A05:2021": {"name": "Security Misconfiguration", "description": "Missing appropriate security hardening"},
    "A06:2021": {"name": "Vulnerable Components", "description": "Using components with known vulnerabilities"},
    "A07:2021": {"name": "Identification and Authentication Failures", "description": "Confirmation of the user's identity and session management"},
    "A08:2021": {"name": "Software and Data Integrity Failures", "description": "Code and infrastructure that does not protect against integrity violations"},
    "A09:2021": {"name": "Security Logging and Monitoring Failures", "description": "Insufficient logging, detection, monitoring and active response"},
    "A10:2021": {"name": "Server-Side Request Forgery", "description": "SSRF flaws occur when fetching a remote resource without validating the URL"},
}


def create_coverage_session(target_base_url: str) -> CoverageSession:
    """Create a new coverage tracking session."""
    session_id = f"cov-{int(time.time() * 1000)}"
    now = datetime.utcnow().isoformat()
    
    # Initialize technique coverage
    technique_coverage = {}
    for technique_id, metadata in TECHNIQUE_REGISTRY.items():
        technique_coverage[technique_id] = {
            "metadata": metadata.to_dict(),
            "status": CoverageStatus.NOT_TESTED.value,
            "endpoints_tested": 0,
            "findings_count": 0,
        }
    
    # Initialize OWASP coverage
    owasp_coverage = {}
    for owasp_id, info in OWASP_CATEGORIES.items():
        related_techniques = [t for t, m in TECHNIQUE_REGISTRY.items() if m.owasp_category == owasp_id]
        owasp_coverage[owasp_id] = {
            "name": info["name"],
            "description": info["description"],
            "techniques": related_techniques,
            "coverage_percent": 0,
            "findings_count": 0,
        }
    
    return CoverageSession(
        session_id=session_id,
        target_base_url=target_base_url,
        endpoints={},
        overall_stats={
            "total_endpoints": 0,
            "total_techniques": len(TECHNIQUE_REGISTRY),
            "techniques_tested": 0,
            "techniques_with_findings": 0,
            "coverage_percent": 0,
            "total_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
        },
        technique_coverage=technique_coverage,
        owasp_coverage=owasp_coverage,
        started_at=now,
        updated_at=now,
    )


def update_coverage_from_fuzz_results(
    session: CoverageSession,
    fuzz_result: FuzzResult,
    endpoint: str,
    method: str,
    techniques_tested: List[str],
) -> CoverageSession:
    """Update coverage session based on fuzzing results."""
    # Create endpoint key
    endpoint_key = f"{method}:{endpoint}"
    
    # Initialize endpoint if not exists
    if endpoint_key not in session.endpoints:
        session.endpoints[endpoint_key] = EndpointCoverage(
            endpoint=endpoint,
            method=method,
            parameters=[],
            techniques_tested={t: CoverageStatus.NOT_TESTED for t in TECHNIQUE_REGISTRY},
            findings=[],
            last_tested=None,
            total_requests=0,
        )
    
    ep_coverage = session.endpoints[endpoint_key]
    ep_coverage.total_requests += 1
    ep_coverage.last_tested = datetime.utcnow().isoformat()
    
    # Update technique coverage based on results
    for technique_id in techniques_tested:
        if technique_id in TECHNIQUE_REGISTRY:
            # Determine status based on findings
            if fuzz_result.flags:
                # Check if this technique found something
                technique_name = TECHNIQUE_REGISTRY[technique_id].name.lower()
                if any(technique_name in flag.lower() or technique_id in flag.lower() for flag in fuzz_result.flags):
                    ep_coverage.techniques_tested[technique_id] = CoverageStatus.VULNERABLE
                    ep_coverage.findings.append(f"{technique_id}: {', '.join(fuzz_result.flags)}")
                else:
                    if ep_coverage.techniques_tested[technique_id] == CoverageStatus.NOT_TESTED:
                        ep_coverage.techniques_tested[technique_id] = CoverageStatus.TESTED
            else:
                if ep_coverage.techniques_tested[technique_id] == CoverageStatus.NOT_TESTED:
                    ep_coverage.techniques_tested[technique_id] = CoverageStatus.TESTED
    
    # Update overall stats
    session.updated_at = datetime.utcnow().isoformat()
    recalculate_coverage_stats(session)
    
    return session


def recalculate_coverage_stats(session: CoverageSession) -> None:
    """Recalculate overall coverage statistics."""
    # Count endpoints
    session.overall_stats["total_endpoints"] = len(session.endpoints)
    
    # Aggregate technique coverage across all endpoints
    technique_status: Dict[str, set] = {t: set() for t in TECHNIQUE_REGISTRY}
    technique_findings: Dict[str, int] = {t: 0 for t in TECHNIQUE_REGISTRY}
    
    total_findings = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for ep in session.endpoints.values():
        for technique_id, status in ep.techniques_tested.items():
            technique_status[technique_id].add(status)
            if status == CoverageStatus.VULNERABLE:
                technique_findings[technique_id] += 1
                total_findings += 1
                severity = TECHNIQUE_REGISTRY[technique_id].severity
                if severity in severity_counts:
                    severity_counts[severity] += 1
    
    # Update technique coverage
    techniques_tested = 0
    techniques_with_findings = 0
    
    for technique_id in TECHNIQUE_REGISTRY:
        statuses = technique_status[technique_id]
        findings = technique_findings[technique_id]
        
        if CoverageStatus.VULNERABLE in statuses:
            session.technique_coverage[technique_id]["status"] = CoverageStatus.VULNERABLE.value
            techniques_with_findings += 1
            techniques_tested += 1
        elif CoverageStatus.TESTED in statuses or CoverageStatus.SECURE in statuses:
            session.technique_coverage[technique_id]["status"] = CoverageStatus.TESTED.value
            techniques_tested += 1
        else:
            session.technique_coverage[technique_id]["status"] = CoverageStatus.NOT_TESTED.value
        
        session.technique_coverage[technique_id]["endpoints_tested"] = len([
            ep for ep in session.endpoints.values()
            if ep.techniques_tested.get(technique_id) != CoverageStatus.NOT_TESTED
        ])
        session.technique_coverage[technique_id]["findings_count"] = findings
    
    # Update OWASP coverage
    for owasp_id, owasp_info in session.owasp_coverage.items():
        techniques = owasp_info["techniques"]
        tested_count = sum(1 for t in techniques if session.technique_coverage[t]["status"] != CoverageStatus.NOT_TESTED.value)
        findings_count = sum(session.technique_coverage[t]["findings_count"] for t in techniques)
        
        owasp_info["coverage_percent"] = round((tested_count / len(techniques)) * 100, 1) if techniques else 0
        owasp_info["findings_count"] = findings_count
    
    # Update overall stats
    session.overall_stats["techniques_tested"] = techniques_tested
    session.overall_stats["techniques_with_findings"] = techniques_with_findings
    session.overall_stats["coverage_percent"] = round((techniques_tested / len(TECHNIQUE_REGISTRY)) * 100, 1)
    session.overall_stats["total_findings"] = total_findings
    session.overall_stats["critical_findings"] = severity_counts["critical"]
    session.overall_stats["high_findings"] = severity_counts["high"]
    session.overall_stats["medium_findings"] = severity_counts["medium"]
    session.overall_stats["low_findings"] = severity_counts["low"]


def get_coverage_gaps(session: CoverageSession) -> Dict[str, Any]:
    """Identify gaps in test coverage."""
    gaps = {
        "untested_techniques": [],
        "partially_tested_techniques": [],
        "owasp_gaps": [],
        "recommendations": [],
    }
    
    # Find untested techniques
    for technique_id, coverage in session.technique_coverage.items():
        if coverage["status"] == CoverageStatus.NOT_TESTED.value:
            metadata = TECHNIQUE_REGISTRY[technique_id]
            gaps["untested_techniques"].append({
                "id": technique_id,
                "name": metadata.name,
                "severity": metadata.severity,
                "owasp": metadata.owasp_category,
                "estimated_time": metadata.estimated_time,
            })
        elif coverage["endpoints_tested"] < len(session.endpoints):
            gaps["partially_tested_techniques"].append({
                "id": technique_id,
                "name": TECHNIQUE_REGISTRY[technique_id].name,
                "endpoints_tested": coverage["endpoints_tested"],
                "total_endpoints": len(session.endpoints),
            })
    
    # Find OWASP categories with low coverage
    for owasp_id, owasp_info in session.owasp_coverage.items():
        if owasp_info["coverage_percent"] < 50:
            gaps["owasp_gaps"].append({
                "id": owasp_id,
                "name": owasp_info["name"],
                "coverage_percent": owasp_info["coverage_percent"],
                "untested_techniques": [t for t in owasp_info["techniques"] 
                                       if session.technique_coverage[t]["status"] == CoverageStatus.NOT_TESTED.value],
            })
    
    # Generate recommendations
    # Prioritize by severity
    critical_untested = [t for t in gaps["untested_techniques"] if t["severity"] == "critical"]
    high_untested = [t for t in gaps["untested_techniques"] if t["severity"] == "high"]
    
    if critical_untested:
        gaps["recommendations"].append({
            "priority": "critical",
            "message": f"Test {len(critical_untested)} critical severity techniques: {', '.join(t['name'] for t in critical_untested[:3])}",
            "techniques": [t["id"] for t in critical_untested],
        })
    
    if high_untested:
        gaps["recommendations"].append({
            "priority": "high",
            "message": f"Test {len(high_untested)} high severity techniques: {', '.join(t['name'] for t in high_untested[:3])}",
            "techniques": [t["id"] for t in high_untested],
        })
    
    # OWASP-based recommendations
    for owasp_gap in gaps["owasp_gaps"]:
        if owasp_gap["coverage_percent"] < 25:
            gaps["recommendations"].append({
                "priority": "high",
                "message": f"OWASP {owasp_gap['id']} ({owasp_gap['name']}) has only {owasp_gap['coverage_percent']}% coverage",
                "techniques": owasp_gap["untested_techniques"],
            })
    
    return gaps


def generate_coverage_heatmap_data(session: CoverageSession) -> Dict[str, Any]:
    """Generate data for coverage heatmap visualization."""
    heatmap_data = {
        "endpoints": [],
        "techniques": list(TECHNIQUE_REGISTRY.keys()),
        "technique_names": {t: m.name for t, m in TECHNIQUE_REGISTRY.items()},
        "matrix": [],  # 2D array: endpoints x techniques
        "categories": list(set(m.category for m in TECHNIQUE_REGISTRY.values())),
    }
    
    status_values = {
        CoverageStatus.NOT_TESTED.value: 0,
        CoverageStatus.TESTED.value: 1,
        CoverageStatus.SECURE.value: 2,
        CoverageStatus.INCONCLUSIVE.value: 3,
        CoverageStatus.VULNERABLE.value: 4,
    }
    
    for endpoint_key, ep_coverage in session.endpoints.items():
        heatmap_data["endpoints"].append(endpoint_key)
        row = []
        for technique_id in TECHNIQUE_REGISTRY:
            status = ep_coverage.techniques_tested.get(technique_id, CoverageStatus.NOT_TESTED)
            if isinstance(status, CoverageStatus):
                status = status.value
            row.append(status_values.get(status, 0))
        heatmap_data["matrix"].append(row)
    
    return heatmap_data


def export_coverage_report(session: CoverageSession, format: str = "markdown") -> str:
    """Export coverage report in specified format."""
    if format == "markdown":
        md = f"""# 📊 Security Testing Coverage Report

**Session ID:** {session.session_id}
**Target:** {session.target_base_url}
**Generated:** {datetime.utcnow().isoformat()}

---

## 📈 Overall Coverage

| Metric | Value |
|--------|-------|
| Total Endpoints | {session.overall_stats['total_endpoints']} |
| Techniques Tested | {session.overall_stats['techniques_tested']}/{session.overall_stats['total_techniques']} |
| Coverage | {session.overall_stats['coverage_percent']}% |
| Total Findings | {session.overall_stats['total_findings']} |
| Critical | {session.overall_stats['critical_findings']} |
| High | {session.overall_stats['high_findings']} |
| Medium | {session.overall_stats['medium_findings']} |

---

## 🔒 OWASP Top 10 Coverage

| Category | Coverage | Findings |
|----------|----------|----------|
"""
        for owasp_id, info in session.owasp_coverage.items():
            emoji = "✅" if info['coverage_percent'] >= 75 else "⚠️" if info['coverage_percent'] >= 50 else "❌"
            md += f"| {emoji} {owasp_id} - {info['name']} | {info['coverage_percent']}% | {info['findings_count']} |\n"
        
        md += """
---

## 🎯 Technique Coverage

"""
        # Group by category
        by_category: Dict[str, List[str]] = {}
        for technique_id, metadata in TECHNIQUE_REGISTRY.items():
            by_category.setdefault(metadata.category, []).append(technique_id)
        
        for category, techniques in by_category.items():
            md += f"### {category.replace('_', ' ').title()}\n\n"
            md += "| Technique | Status | Findings |\n"
            md += "|-----------|--------|----------|\n"
            
            for technique_id in techniques:
                coverage = session.technique_coverage[technique_id]
                status = coverage['status']
                emoji = "🔴" if status == "vulnerable" else "✅" if status == "tested" else "⚪"
                md += f"| {TECHNIQUE_REGISTRY[technique_id].name} | {emoji} {status} | {coverage['findings_count']} |\n"
            md += "\n"
        
        # Add gaps
        gaps = get_coverage_gaps(session)
        if gaps["recommendations"]:
            md += """
---

## ⚠️ Coverage Gaps & Recommendations

"""
            for rec in gaps["recommendations"]:
                priority_emoji = "🔴" if rec['priority'] == 'critical' else "🟠" if rec['priority'] == 'high' else "🟡"
                md += f"- {priority_emoji} **{rec['priority'].upper()}**: {rec['message']}\n"
        
        md += "\n---\n*Generated by VRAgent Security Fuzzer*\n"
        return md
    
    elif format == "json":
        return json.dumps(session.to_dict(), indent=2)
    
    return ""
