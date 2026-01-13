"""
Smart Detection Service

Provides intelligent vulnerability detection, anomaly analysis, and 
automatic categorization of fuzzing results.
"""

import re
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import statistics

logger = logging.getLogger(__name__)


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities that can be detected."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    INFORMATION_DISCLOSURE = "information_disclosure"
    ERROR_BASED = "error_based"
    AUTH_BYPASS = "auth_bypass"
    BUSINESS_LOGIC = "business_logic"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectionSignature:
    """A signature for detecting vulnerabilities."""
    name: str
    vuln_type: VulnerabilityType
    severity: Severity
    patterns: List[str]  # Regex patterns
    description: str
    false_positive_indicators: List[str] = field(default_factory=list)
    context_required: bool = False  # Needs payload context
    min_confidence: float = 0.7


@dataclass
class SmartFinding:
    """A finding detected by the smart detection engine."""
    id: str
    vuln_type: VulnerabilityType
    severity: Severity
    confidence: float
    title: str
    description: str
    evidence: List[str]
    payload: str
    response_id: str
    indicators: List[str]
    recommendation: str
    false_positive_likelihood: str  # low, medium, high
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "payload": self.payload,
            "response_id": self.response_id,
            "indicators": self.indicators,
            "recommendation": self.recommendation,
            "false_positive_likelihood": self.false_positive_likelihood,
        }


@dataclass 
class AnomalyResult:
    """Result of anomaly detection."""
    response_id: str
    anomaly_type: str  # time, length, status, content
    score: float  # 0-1, higher = more anomalous
    baseline_value: Any
    actual_value: Any
    deviation: float
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "response_id": self.response_id,
            "anomaly_type": self.anomaly_type,
            "score": self.score,
            "baseline_value": self.baseline_value,
            "actual_value": self.actual_value,
            "deviation": self.deviation,
            "description": self.description,
        }


# =============================================================================
# Detection Signatures Database
# =============================================================================

SQL_INJECTION_SIGNATURES = [
    DetectionSignature(
        name="SQL Error - MySQL",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
        ],
        description="MySQL database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - PostgreSQL",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
        ],
        description="PostgreSQL database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - MSSQL",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"mssql_query\(\)",
        ],
        description="Microsoft SQL Server error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - Oracle",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"quoted string not properly terminated",
            r"oracle\.jdbc\.driver",
        ],
        description="Oracle database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - SQLite",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLITE_ERROR",
        ],
        description="SQLite database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - Generic",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.MEDIUM,
        patterns=[
            r"SQL syntax error",
            r"syntax error.*SQL",
            r"Syntax error in string in query expression",
            r"Incorrect syntax near",
            r"Unexpected end of command in statement",
            r"ODBC.*Driver.*Error",
        ],
        description="Generic SQL error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Injection - Boolean Based",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[],  # Detected by differential analysis
        description="Response difference suggests boolean-based SQL injection",
        context_required=True,
    ),
]

XSS_SIGNATURES = [
    DetectionSignature(
        name="XSS - Reflected Script",
        vuln_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        patterns=[
            r"<script[^>]*>[^<]*</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"onfocus\s*=",
            r"onblur\s*=",
        ],
        description="Reflected XSS payload detected in response",
        context_required=True,  # Need to verify payload is reflected
    ),
    DetectionSignature(
        name="XSS - SVG Injection",
        vuln_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        patterns=[
            r"<svg[^>]*onload\s*=",
            r"<svg[^>]*onerror\s*=",
        ],
        description="SVG-based XSS vector detected in response",
        context_required=True,
    ),
    DetectionSignature(
        name="XSS - IMG Tag Injection",
        vuln_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        patterns=[
            r"<img[^>]*onerror\s*=",
            r"<img[^>]*onload\s*=",
            r'<img[^>]*src\s*=\s*["\']?javascript:',
        ],
        description="IMG tag-based XSS vector detected in response",
        context_required=True,
    ),
]

COMMAND_INJECTION_SIGNATURES = [
    DetectionSignature(
        name="Command Injection - Linux",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        patterns=[
            r"root:.*:0:0:",  # /etc/passwd content
            r"uid=\d+.*gid=\d+",  # id command output
            r"Linux\s+\S+\s+\d+\.\d+",  # uname output
            r"/bin/(?:ba)?sh",
            r"drwx[-rwx]{9}",  # ls -la output
        ],
        description="Linux command execution output detected in response",
    ),
    DetectionSignature(
        name="Command Injection - Windows",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        patterns=[
            r"Volume Serial Number",
            r"Directory of [A-Z]:\\",
            r"Microsoft Windows \[Version",
            r"Windows IP Configuration",
            r"\[Font\]|\[Extensions\]",  # win.ini
        ],
        description="Windows command execution output detected in response",
    ),
]

PATH_TRAVERSAL_SIGNATURES = [
    DetectionSignature(
        name="Path Traversal - Linux Files",
        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        patterns=[
            r"root:.*:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # boot.ini
            r"# /etc/hosts",
            r"localhost\s+127\.0\.0\.1",
        ],
        description="Sensitive Linux file content detected in response",
    ),
    DetectionSignature(
        name="Path Traversal - Windows Files",
        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        patterns=[
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"\[fonts\]",
            r"for 16-bit app support",
        ],
        description="Sensitive Windows file content detected in response",
    ),
]

SSTI_SIGNATURES = [
    DetectionSignature(
        name="SSTI - Template Evaluation",
        vuln_type=VulnerabilityType.SSTI,
        severity=Severity.CRITICAL,
        patterns=[
            r"49",  # 7*7 = 49
            r"7777777",  # 7*'7'
        ],
        description="Server-side template injection confirmed via math evaluation",
        context_required=True,  # Only valid if payload was {{7*7}}
    ),
    DetectionSignature(
        name="SSTI - Error Messages",
        vuln_type=VulnerabilityType.SSTI,
        severity=Severity.MEDIUM,
        patterns=[
            r"jinja2\.exceptions",
            r"mako\.exceptions",
            r"Twig_Error",
            r"freemarker\.core",
            r"velocity\.exception",
            r"TemplateError",
            r"TemplateSyntaxError",
        ],
        description="Template engine error message detected",
    ),
]

INFORMATION_DISCLOSURE_SIGNATURES = [
    DetectionSignature(
        name="Stack Trace Disclosure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.MEDIUM,
        patterns=[
            r"Traceback \(most recent call last\)",
            r"at \S+\.java:\d+",
            r"at \S+\.cs:\d+",
            r"File \"[^\"]+\", line \d+",
            r"#\d+ \S+\.php\(\d+\):",
            r"Stack trace:",
            r"Exception in thread",
        ],
        description="Application stack trace leaked in response",
    ),
    DetectionSignature(
        name="Debug Information",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.LOW,
        patterns=[
            r"DEBUG\s*[:=]\s*True",
            r"debug\s*mode\s*enabled",
            r"DJANGO_SETTINGS_MODULE",
            r"APP_ENV\s*[:=]\s*(?:dev|development)",
            r"phpinfo\(\)",
        ],
        description="Debug mode or configuration information detected",
    ),
    DetectionSignature(
        name="Sensitive Data Exposure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.HIGH,
        patterns=[
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"(?:secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----",
            r"(?:aws_)?(?:access_key|secret_key)\s*[:=]",
        ],
        description="Sensitive credentials or keys detected in response",
    ),
    DetectionSignature(
        name="Internal IP Disclosure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.LOW,
        patterns=[
            r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
        ],
        description="Internal IP address detected in response",
        false_positive_indicators=["documentation", "example", "10.0.0.1"],
    ),
    DetectionSignature(
        name="Version Disclosure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.INFO,
        patterns=[
            r"(?:Apache|nginx|IIS|Tomcat)/[\d.]+",
            r"PHP/[\d.]+",
            r"X-Powered-By:\s*\S+",
            r"Server:\s*\S+",
        ],
        description="Server version information disclosed",
    ),
]

OPEN_REDIRECT_SIGNATURES = [
    DetectionSignature(
        name="Open Redirect",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        patterns=[
            r"(?:Location|Refresh):\s*https?://(?:evil\.com|attacker\.com|google\.com)",
        ],
        description="Open redirect detected via Location header",
        context_required=True,
    ),
]

XXE_SIGNATURES = [
    DetectionSignature(
        name="XXE - File Disclosure",
        vuln_type=VulnerabilityType.XXE,
        severity=Severity.CRITICAL,
        patterns=[
            r"root:.*:0:0:",  # /etc/passwd via XXE
        ],
        description="XXE vulnerability confirmed via file disclosure",
        context_required=True,
    ),
    DetectionSignature(
        name="XXE - Error Based",
        vuln_type=VulnerabilityType.XXE,
        severity=Severity.HIGH,
        patterns=[
            r"XMLParseError",
            r"SAXParseException",
            r"XML Parsing Error",
            r"Start tag expected",
            r"DTD.*not allowed",
        ],
        description="XML parsing error may indicate XXE testing vector",
    ),
]

LDAP_INJECTION_SIGNATURES = [
    DetectionSignature(
        name="LDAP Injection Error",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"Invalid DN syntax",
            r"LdapErr:",
            r"LDAP.*error",
            r"javax\.naming\.directory",
            r"supplied argument is not a valid ldap",
        ],
        description="LDAP error message detected",
    ),
]


# =============================================================================
# OFFENSIVE SECURITY SIGNATURES
# For analyzing sandboxed software, malware, and C2 communication
# =============================================================================

class OffensiveType(str, Enum):
    """Types of offensive security indicators that can be detected."""
    C2_COMMUNICATION = "c2_communication"
    MALWARE_BEHAVIOR = "malware_behavior"
    SANDBOX_EVASION = "sandbox_evasion"
    PROCESS_INJECTION = "process_injection"
    CREDENTIAL_THEFT = "credential_theft"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    CRYPTOMINER = "cryptominer"
    RANSOMWARE = "ransomware"
    RAT_TROJAN = "rat_trojan"
    BOTNET = "botnet"


@dataclass
class OffensiveSignature:
    """A signature for detecting offensive security indicators."""
    name: str
    offensive_type: OffensiveType
    severity: Severity
    patterns: List[str]
    description: str
    mitre_id: Optional[str] = None  # MITRE ATT&CK ID
    mitre_tactic: Optional[str] = None
    false_positive_indicators: List[str] = field(default_factory=list)
    min_confidence: float = 0.7


# C2 Communication Signatures
C2_SIGNATURES = [
    OffensiveSignature(
        name="Cobalt Strike Beacon",
        offensive_type=OffensiveType.C2_COMMUNICATION,
        severity=Severity.CRITICAL,
        patterns=[
            r"beacon\s*payload",
            r"malleable\s*c2",
            r"watermark\s*=\s*\d+",
            r"spawn\s*to",
            r"process[-_]inject",
            r"jump\s*psexec",
            r"mimikatz",
            r"logonpasswords",
            r"hashdump",
        ],
        description="Cobalt Strike beacon indicators detected",
        mitre_id="S0154",
        mitre_tactic="Command and Control",
    ),
    OffensiveSignature(
        name="Metasploit Framework",
        offensive_type=OffensiveType.C2_COMMUNICATION,
        severity=Severity.CRITICAL,
        patterns=[
            r"meterpreter",
            r"reverse_tcp",
            r"reverse_http",
            r"bind_tcp",
            r"multi/handler",
            r"exploit/multi",
            r"post/windows",
            r"payload/windows",
            r"staged\s*payload",
        ],
        description="Metasploit framework indicators detected",
        mitre_id="S0081",
        mitre_tactic="Command and Control",
    ),
    OffensiveSignature(
        name="Empire Framework",
        offensive_type=OffensiveType.C2_COMMUNICATION,
        severity=Severity.CRITICAL,
        patterns=[
            r"empire\s*agent",
            r"invoke-empire",
            r"powershell\s*empire",
            r"launcher\.bat",
            r"stager",
        ],
        description="Empire framework indicators detected",
        mitre_id="S0363",
        mitre_tactic="Command and Control",
    ),
    OffensiveSignature(
        name="Sliver C2",
        offensive_type=OffensiveType.C2_COMMUNICATION,
        severity=Severity.CRITICAL,
        patterns=[
            r"sliver\s*implant",
            r"mtls\s*listener",
            r"wg\s*listener",
            r"dns\s*canary",
        ],
        description="Sliver C2 framework indicators detected",
        mitre_tactic="Command and Control",
    ),
    OffensiveSignature(
        name="DNS Tunneling C2",
        offensive_type=OffensiveType.C2_COMMUNICATION,
        severity=Severity.HIGH,
        patterns=[
            r"dns\s*tunnel",
            r"iodine",
            r"dnscat",
            r"dns2tcp",
            r"\.duckdns\.org",
            r"\.no-ip\.",
            r"\.ddns\.net",
        ],
        description="DNS tunneling for C2 communication detected",
        mitre_id="T1071.004",
        mitre_tactic="Command and Control",
    ),
    OffensiveSignature(
        name="Beacon Sleep/Jitter",
        offensive_type=OffensiveType.C2_COMMUNICATION,
        severity=Severity.HIGH,
        patterns=[
            r"sleep\s*[=:]\s*\d+",
            r"jitter\s*[=:]\s*\d+",
            r"callback\s*interval",
            r"checkin",
            r"heartbeat",
        ],
        description="C2 beacon timing configuration detected",
        mitre_id="T1573",
        mitre_tactic="Command and Control",
    ),
]

# Malware Behavior Signatures
MALWARE_SIGNATURES = [
    OffensiveSignature(
        name="Process Injection - CreateRemoteThread",
        offensive_type=OffensiveType.PROCESS_INJECTION,
        severity=Severity.CRITICAL,
        patterns=[
            r"CreateRemoteThread",
            r"NtCreateThreadEx",
            r"RtlCreateUserThread",
            r"WriteProcessMemory",
            r"VirtualAllocEx",
        ],
        description="Process injection via CreateRemoteThread detected",
        mitre_id="T1055",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="DLL Injection",
        offensive_type=OffensiveType.PROCESS_INJECTION,
        severity=Severity.CRITICAL,
        patterns=[
            r"LoadLibrary.*inject",
            r"reflective\s*dll",
            r"manual\s*map",
            r"SetWindowsHookEx",
            r"QueueUserAPC",
        ],
        description="DLL injection technique detected",
        mitre_id="T1055.001",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="Process Hollowing",
        offensive_type=OffensiveType.PROCESS_INJECTION,
        severity=Severity.CRITICAL,
        patterns=[
            r"NtUnmapViewOfSection",
            r"process\s*hollow",
            r"doppelgang",
            r"transacted\s*hollow",
        ],
        description="Process hollowing technique detected",
        mitre_id="T1055.012",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="Credential Dumping - Mimikatz",
        offensive_type=OffensiveType.CREDENTIAL_THEFT,
        severity=Severity.CRITICAL,
        patterns=[
            r"mimikatz",
            r"sekurlsa",
            r"logonpasswords",
            r"wdigest",
            r"kerberos.*ticket",
            r"dcsync",
            r"golden\s*ticket",
            r"silver\s*ticket",
        ],
        description="Mimikatz credential dumping detected",
        mitre_id="T1003",
        mitre_tactic="Credential Access",
    ),
    OffensiveSignature(
        name="LSASS Memory Dump",
        offensive_type=OffensiveType.CREDENTIAL_THEFT,
        severity=Severity.CRITICAL,
        patterns=[
            r"lsass.*dump",
            r"procdump.*lsass",
            r"comsvcs.*MiniDump",
            r"MiniDumpWriteDump",
            r"nanodump",
        ],
        description="LSASS memory dumping detected",
        mitre_id="T1003.001",
        mitre_tactic="Credential Access",
    ),
    OffensiveSignature(
        name="Registry Persistence",
        offensive_type=OffensiveType.PERSISTENCE,
        severity=Severity.HIGH,
        patterns=[
            r"HKLM\\.*\\Run",
            r"HKCU\\.*\\Run",
            r"CurrentVersion\\Run",
            r"Winlogon\\Shell",
            r"Userinit",
        ],
        description="Registry-based persistence mechanism detected",
        mitre_id="T1547.001",
        mitre_tactic="Persistence",
    ),
    OffensiveSignature(
        name="Scheduled Task Persistence",
        offensive_type=OffensiveType.PERSISTENCE,
        severity=Severity.HIGH,
        patterns=[
            r"schtasks\s*/create",
            r"New-ScheduledTask",
            r"Register-ScheduledTask",
            r"at\s+\d+:\d+",
        ],
        description="Scheduled task persistence detected",
        mitre_id="T1053.005",
        mitre_tactic="Persistence",
    ),
    OffensiveSignature(
        name="Service Persistence",
        offensive_type=OffensiveType.PERSISTENCE,
        severity=Severity.HIGH,
        patterns=[
            r"sc\s+create",
            r"New-Service",
            r"CreateService",
            r"ServiceInstall",
        ],
        description="Service-based persistence detected",
        mitre_id="T1543.003",
        mitre_tactic="Persistence",
    ),
]

# Sandbox Evasion Signatures
SANDBOX_EVASION_SIGNATURES = [
    OffensiveSignature(
        name="VM Detection",
        offensive_type=OffensiveType.SANDBOX_EVASION,
        severity=Severity.MEDIUM,
        patterns=[
            r"vmware",
            r"virtualbox",
            r"vbox",
            r"qemu",
            r"hyperv",
            r"xen",
            r"kvm",
            r"virtual\s*machine",
        ],
        description="Virtual machine detection technique",
        mitre_id="T1497.001",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="Sandbox Detection",
        offensive_type=OffensiveType.SANDBOX_EVASION,
        severity=Severity.MEDIUM,
        patterns=[
            r"sandbox",
            r"cuckoo",
            r"any\.run",
            r"hybrid-analysis",
            r"virustotal",
            r"joe\s*sandbox",
        ],
        description="Sandbox environment detection",
        mitre_id="T1497.001",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="Debugger Detection",
        offensive_type=OffensiveType.SANDBOX_EVASION,
        severity=Severity.MEDIUM,
        patterns=[
            r"IsDebuggerPresent",
            r"CheckRemoteDebugger",
            r"NtQueryInformationProcess",
            r"OutputDebugString",
            r"int\s*2dh",
        ],
        description="Debugger detection anti-analysis technique",
        mitre_id="T1622",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="Timing-based Evasion",
        offensive_type=OffensiveType.SANDBOX_EVASION,
        severity=Severity.MEDIUM,
        patterns=[
            r"rdtsc",
            r"GetTickCount",
            r"QueryPerformanceCounter",
            r"sleep\s*\(\s*\d{5,}",
            r"NtDelayExecution",
        ],
        description="Timing-based sandbox evasion",
        mitre_id="T1497.003",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="AMSI Bypass",
        offensive_type=OffensiveType.SANDBOX_EVASION,
        severity=Severity.HIGH,
        patterns=[
            r"amsi.*bypass",
            r"AmsiScanBuffer",
            r"amsi\.dll",
            r"AmsiInitialize",
            r"amsiContext",
        ],
        description="AMSI bypass technique detected",
        mitre_id="T1562.001",
        mitre_tactic="Defense Evasion",
    ),
    OffensiveSignature(
        name="ETW Bypass",
        offensive_type=OffensiveType.SANDBOX_EVASION,
        severity=Severity.HIGH,
        patterns=[
            r"etw.*bypass",
            r"EtwEventWrite",
            r"NtTraceEvent",
            r"etw.*patch",
        ],
        description="ETW bypass technique detected",
        mitre_id="T1562.006",
        mitre_tactic="Defense Evasion",
    ),
]

# Lateral Movement Signatures
LATERAL_MOVEMENT_SIGNATURES = [
    OffensiveSignature(
        name="PsExec",
        offensive_type=OffensiveType.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        patterns=[
            r"psexec",
            r"PSEXESVC",
            r"remcom",
            r"remote\s*execution",
        ],
        description="PsExec-style remote execution detected",
        mitre_id="T1570",
        mitre_tactic="Lateral Movement",
    ),
    OffensiveSignature(
        name="WMI Execution",
        offensive_type=OffensiveType.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        patterns=[
            r"wmic.*process.*call.*create",
            r"Win32_Process.*Create",
            r"Invoke-WmiMethod",
            r"WMI.*remote",
        ],
        description="WMI-based remote execution detected",
        mitre_id="T1047",
        mitre_tactic="Execution",
    ),
    OffensiveSignature(
        name="Pass-the-Hash",
        offensive_type=OffensiveType.LATERAL_MOVEMENT,
        severity=Severity.CRITICAL,
        patterns=[
            r"pass.*the.*hash",
            r"pth",
            r"ntlm.*relay",
            r"sekurlsa.*pth",
        ],
        description="Pass-the-Hash attack technique detected",
        mitre_id="T1550.002",
        mitre_tactic="Lateral Movement",
    ),
    OffensiveSignature(
        name="SMB Lateral Movement",
        offensive_type=OffensiveType.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        patterns=[
            r"smb.*exec",
            r"smbclient",
            r"admin\$",
            r"c\$",
            r"ipc\$",
        ],
        description="SMB-based lateral movement detected",
        mitre_id="T1021.002",
        mitre_tactic="Lateral Movement",
    ),
]

# Exfiltration Signatures
EXFILTRATION_SIGNATURES = [
    OffensiveSignature(
        name="DNS Exfiltration",
        offensive_type=OffensiveType.EXFILTRATION,
        severity=Severity.HIGH,
        patterns=[
            r"dns.*exfil",
            r"dns.*tunnel.*data",
            r"base64.*subdomain",
            r"hex.*encode.*domain",
        ],
        description="DNS-based data exfiltration detected",
        mitre_id="T1048.003",
        mitre_tactic="Exfiltration",
    ),
    OffensiveSignature(
        name="Cloud Service Exfiltration",
        offensive_type=OffensiveType.EXFILTRATION,
        severity=Severity.HIGH,
        patterns=[
            r"telegram.*bot",
            r"discord.*webhook",
            r"slack.*webhook",
            r"pastebin",
            r"transfer\.sh",
            r"file\.io",
        ],
        description="Cloud service-based data exfiltration detected",
        mitre_id="T1567",
        mitre_tactic="Exfiltration",
    ),
    OffensiveSignature(
        name="HTTP POST Exfiltration",
        offensive_type=OffensiveType.EXFILTRATION,
        severity=Severity.MEDIUM,
        patterns=[
            r"http.*post.*exfil",
            r"upload.*loot",
            r"send.*stolen",
            r"exfil.*data",
        ],
        description="HTTP-based data exfiltration detected",
        mitre_id="T1048.002",
        mitre_tactic="Exfiltration",
    ),
]

# Cryptominer Signatures
CRYPTOMINER_SIGNATURES = [
    OffensiveSignature(
        name="Mining Pool Connection",
        offensive_type=OffensiveType.CRYPTOMINER,
        severity=Severity.HIGH,
        patterns=[
            r"stratum\+tcp",
            r"stratum\+ssl",
            r"mining.*pool",
            r"pool\.minexmr",
            r"xmr-eu",
            r"moneropool",
        ],
        description="Cryptocurrency mining pool connection detected",
        mitre_id="T1496",
        mitre_tactic="Impact",
    ),
    OffensiveSignature(
        name="XMRig Miner",
        offensive_type=OffensiveType.CRYPTOMINER,
        severity=Severity.HIGH,
        patterns=[
            r"xmrig",
            r"xmr-stak",
            r"ccminer",
            r"cgminer",
            r"bfgminer",
        ],
        description="Known cryptocurrency miner detected",
        mitre_id="T1496",
        mitre_tactic="Impact",
    ),
    OffensiveSignature(
        name="Browser-based Miner",
        offensive_type=OffensiveType.CRYPTOMINER,
        severity=Severity.MEDIUM,
        patterns=[
            r"coinhive",
            r"cryptoloot",
            r"coin-hive",
            r"miner\.start",
            r"webminer",
        ],
        description="Browser-based cryptocurrency miner detected",
        mitre_id="T1496",
        mitre_tactic="Impact",
    ),
]

# Ransomware Signatures
RANSOMWARE_SIGNATURES = [
    OffensiveSignature(
        name="Ransomware Encryption",
        offensive_type=OffensiveType.RANSOMWARE,
        severity=Severity.CRITICAL,
        patterns=[
            r"ransomware",
            r"encrypt.*files",
            r"\.encrypted",
            r"\.locked",
            r"\.crypto",
            r"ransom.*note",
            r"decrypt.*payment",
            r"bitcoin.*wallet",
        ],
        description="Ransomware indicators detected",
        mitre_id="T1486",
        mitre_tactic="Impact",
    ),
    OffensiveSignature(
        name="Shadow Copy Deletion",
        offensive_type=OffensiveType.RANSOMWARE,
        severity=Severity.CRITICAL,
        patterns=[
            r"vssadmin.*delete",
            r"wmic.*shadowcopy.*delete",
            r"bcdedit.*recoveryenabled.*no",
            r"wbadmin.*delete",
        ],
        description="Shadow copy deletion (ransomware behavior) detected",
        mitre_id="T1490",
        mitre_tactic="Impact",
    ),
]

# RAT/Trojan Signatures
RAT_SIGNATURES = [
    OffensiveSignature(
        name="Remote Access Trojan",
        offensive_type=OffensiveType.RAT_TROJAN,
        severity=Severity.CRITICAL,
        patterns=[
            r"rat\s*server",
            r"remote.*admin.*tool",
            r"njrat",
            r"darkcomet",
            r"asyncrat",
            r"quasar.*rat",
            r"nanocore",
            r"remcos",
        ],
        description="Remote Access Trojan indicators detected",
        mitre_tactic="Command and Control",
    ),
    OffensiveSignature(
        name="Keylogger",
        offensive_type=OffensiveType.RAT_TROJAN,
        severity=Severity.HIGH,
        patterns=[
            r"keylog",
            r"GetAsyncKeyState",
            r"SetWindowsHookEx.*WH_KEYBOARD",
            r"keyboard.*hook",
            r"keystroke.*capture",
        ],
        description="Keylogger functionality detected",
        mitre_id="T1056.001",
        mitre_tactic="Collection",
    ),
    OffensiveSignature(
        name="Screen Capture",
        offensive_type=OffensiveType.RAT_TROJAN,
        severity=Severity.MEDIUM,
        patterns=[
            r"screenshot",
            r"screen.*capture",
            r"BitBlt",
            r"GetWindowDC",
            r"desktop.*capture",
        ],
        description="Screen capture functionality detected",
        mitre_id="T1113",
        mitre_tactic="Collection",
    ),
]

# Botnet Signatures
BOTNET_SIGNATURES = [
    OffensiveSignature(
        name="DDoS Bot Commands",
        offensive_type=OffensiveType.BOTNET,
        severity=Severity.HIGH,
        patterns=[
            r"ddos",
            r"syn\s*flood",
            r"udp\s*flood",
            r"http\s*flood",
            r"slowloris",
            r"layer\s*7\s*attack",
        ],
        description="DDoS botnet command indicators detected",
        mitre_id="T1498",
        mitre_tactic="Impact",
    ),
    OffensiveSignature(
        name="IRC Bot",
        offensive_type=OffensiveType.BOTNET,
        severity=Severity.HIGH,
        patterns=[
            r"irc.*bot",
            r"join\s*#",
            r"privmsg",
            r"irc\..*:\d+",
            r"pong\s*:",
        ],
        description="IRC-based botnet communication detected",
        mitre_id="T1071.001",
        mitre_tactic="Command and Control",
    ),
    OffensiveSignature(
        name="Mirai-style Bot",
        offensive_type=OffensiveType.BOTNET,
        severity=Severity.CRITICAL,
        patterns=[
            r"mirai",
            r"telnet.*brute",
            r"busybox",
            r"echo.*'.*'.*>.*\/dev\/",
            r"\/bin\/sh.*-c",
        ],
        description="Mirai-style IoT botnet indicators detected",
        mitre_tactic="Initial Access",
    ),
]

# Combine all offensive signatures
ALL_OFFENSIVE_SIGNATURES: List[OffensiveSignature] = (
    C2_SIGNATURES +
    MALWARE_SIGNATURES +
    SANDBOX_EVASION_SIGNATURES +
    LATERAL_MOVEMENT_SIGNATURES +
    EXFILTRATION_SIGNATURES +
    CRYPTOMINER_SIGNATURES +
    RANSOMWARE_SIGNATURES +
    RAT_SIGNATURES +
    BOTNET_SIGNATURES
)

# Combine all signatures
ALL_SIGNATURES: List[DetectionSignature] = (
    SQL_INJECTION_SIGNATURES +
    XSS_SIGNATURES +
    COMMAND_INJECTION_SIGNATURES +
    PATH_TRAVERSAL_SIGNATURES +
    SSTI_SIGNATURES +
    INFORMATION_DISCLOSURE_SIGNATURES +
    OPEN_REDIRECT_SIGNATURES +
    XXE_SIGNATURES +
    LDAP_INJECTION_SIGNATURES
)


# =============================================================================
# Smart Detection Engine
# =============================================================================

class SmartDetectionEngine:
    """
    Intelligent detection engine for analyzing fuzzing responses.
    """
    
    def __init__(self):
        self.signatures = ALL_SIGNATURES
        self.offensive_signatures = ALL_OFFENSIVE_SIGNATURES
        self.compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self.compiled_offensive_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()
        self._compile_offensive_patterns()
        
    def _compile_patterns(self):
        """Pre-compile all regex patterns for performance."""
        for sig in self.signatures:
            self.compiled_patterns[sig.name] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in sig.patterns
            ]
    
    def _compile_offensive_patterns(self):
        """Pre-compile all offensive regex patterns for performance."""
        for sig in self.offensive_signatures:
            self.compiled_offensive_patterns[sig.name] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in sig.patterns
            ]
    
    def detect_vulnerabilities(
        self,
        responses: List[Dict[str, Any]],
        baseline_response: Optional[Dict[str, Any]] = None,
    ) -> List[SmartFinding]:
        """
        Analyze responses for vulnerability indicators.
        
        Args:
            responses: List of fuzzing response dicts
            baseline_response: Optional baseline for comparison
            
        Returns:
            List of detected findings
        """
        findings: List[SmartFinding] = []
        finding_hashes: Set[str] = set()  # Deduplicate
        
        for response in responses:
            body = response.get("body", "")
            headers = response.get("headers", {})
            payload = response.get("payload", "")
            response_id = response.get("id", "unknown")
            
            # Combine body and headers for analysis
            full_response = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
            
            # Check each signature
            for sig in self.signatures:
                # Skip context-required signatures if payload doesn't match
                if sig.context_required and not self._payload_matches_context(payload, sig):
                    continue
                
                matches = self._check_signature(sig, full_response)
                if matches:
                    # Check for false positives
                    fp_likelihood = self._assess_false_positive(sig, full_response, payload)
                    
                    # Create finding hash for deduplication
                    finding_hash = hashlib.md5(
                        f"{sig.name}:{response_id}:{matches[0]}".encode()
                    ).hexdigest()
                    
                    if finding_hash not in finding_hashes:
                        finding_hashes.add(finding_hash)
                        
                        confidence = self._calculate_confidence(sig, matches, fp_likelihood)
                        
                        findings.append(SmartFinding(
                            id=finding_hash[:12],
                            vuln_type=sig.vuln_type,
                            severity=sig.severity,
                            confidence=confidence,
                            title=sig.name,
                            description=sig.description,
                            evidence=matches[:5],  # Limit evidence
                            payload=payload,
                            response_id=response_id,
                            indicators=[m[:100] for m in matches[:3]],
                            recommendation=self._get_recommendation(sig.vuln_type),
                            false_positive_likelihood=fp_likelihood,
                        ))
        
        # Sort by severity and confidence
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda f: (severity_order[f.severity], -f.confidence))
        
        return findings
    
    def _check_signature(self, sig: DetectionSignature, content: str) -> List[str]:
        """Check if signature matches content."""
        matches = []
        for pattern in self.compiled_patterns.get(sig.name, []):
            for match in pattern.finditer(content):
                matches.append(match.group(0))
        return matches
    
    def _payload_matches_context(self, payload: str, sig: DetectionSignature) -> bool:
        """Check if payload is relevant for context-required signature."""
        payload_lower = payload.lower()
        
        if sig.vuln_type == VulnerabilityType.XSS:
            return any(x in payload_lower for x in ["<script", "onerror", "onload", "javascript:"])
        elif sig.vuln_type == VulnerabilityType.SSTI:
            return any(x in payload for x in ["{{", "${", "<%", "{%"])
        elif sig.vuln_type == VulnerabilityType.OPEN_REDIRECT:
            return any(x in payload_lower for x in ["http://", "https://", "//"])
        elif sig.vuln_type == VulnerabilityType.XXE:
            return any(x in payload for x in ["<!ENTITY", "<!DOCTYPE", "SYSTEM"])
        
        return True
    
    def _assess_false_positive(
        self,
        sig: DetectionSignature,
        content: str,
        payload: str
    ) -> str:
        """Assess likelihood of false positive."""
        content_lower = content.lower()
        
        # Check false positive indicators
        fp_matches = sum(
            1 for indicator in sig.false_positive_indicators
            if indicator.lower() in content_lower
        )
        
        if fp_matches >= 2:
            return "high"
        elif fp_matches == 1:
            return "medium"
        
        # Additional heuristics
        if sig.vuln_type == VulnerabilityType.XSS:
            # If payload isn't reflected, likely FP
            if payload and payload not in content:
                return "high"
        
        return "low"
    
    def _calculate_confidence(
        self,
        sig: DetectionSignature,
        matches: List[str],
        fp_likelihood: str
    ) -> float:
        """Calculate confidence score for finding."""
        base_confidence = sig.min_confidence
        
        # More matches = higher confidence
        match_bonus = min(len(matches) * 0.05, 0.2)
        
        # Reduce for false positive likelihood
        fp_penalty = {"low": 0, "medium": 0.15, "high": 0.3}.get(fp_likelihood, 0)
        
        confidence = base_confidence + match_bonus - fp_penalty
        return max(0.1, min(1.0, confidence))
    
    def _get_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Get remediation recommendation for vulnerability type."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            VulnerabilityType.XSS: "Encode output based on context (HTML, JavaScript, URL). Use Content-Security-Policy headers.",
            VulnerabilityType.COMMAND_INJECTION: "Avoid system commands with user input. Use safe APIs and input validation.",
            VulnerabilityType.PATH_TRAVERSAL: "Validate and sanitize file paths. Use a whitelist of allowed files.",
            VulnerabilityType.SSRF: "Validate and whitelist URLs. Block internal IP ranges.",
            VulnerabilityType.XXE: "Disable external entity processing in XML parsers.",
            VulnerabilityType.SSTI: "Avoid passing user input to template engines. Use sandboxed templates.",
            VulnerabilityType.LDAP_INJECTION: "Escape special LDAP characters in user input.",
            VulnerabilityType.XPATH_INJECTION: "Use parameterized XPath queries.",
            VulnerabilityType.OPEN_REDIRECT: "Validate redirect URLs against a whitelist.",
            VulnerabilityType.IDOR: "Implement proper access controls and authorization checks.",
            VulnerabilityType.INFORMATION_DISCLOSURE: "Disable debug mode in production. Remove verbose error messages.",
            VulnerabilityType.ERROR_BASED: "Implement custom error handlers that don't leak information.",
            VulnerabilityType.AUTH_BYPASS: "Review authentication logic and implement proper session management.",
            VulnerabilityType.BUSINESS_LOGIC: "Review business logic for edge cases and implement proper validation.",
        }
        return recommendations.get(vuln_type, "Review the application logic and implement proper input validation.")
    
    def detect_anomalies(
        self,
        responses: List[Dict[str, Any]],
        baseline_responses: Optional[List[Dict[str, Any]]] = None,
    ) -> List[AnomalyResult]:
        """
        Detect anomalous responses using statistical analysis.
        
        Args:
            responses: List of fuzzing response dicts
            baseline_responses: Optional baseline responses for comparison
            
        Returns:
            List of anomaly results
        """
        anomalies: List[AnomalyResult] = []
        
        if len(responses) < 3:
            return anomalies
        
        # Calculate baselines
        response_times = [r.get("response_time", 0) for r in responses]
        response_lengths = [r.get("response_length", 0) for r in responses]
        status_codes = [r.get("status_code", 0) for r in responses]
        
        # Statistical baselines
        time_mean = statistics.mean(response_times) if response_times else 0
        time_stdev = statistics.stdev(response_times) if len(response_times) > 1 else 0
        
        length_mean = statistics.mean(response_lengths) if response_lengths else 0
        length_stdev = statistics.stdev(response_lengths) if len(response_lengths) > 1 else 0
        
        # Most common status code
        status_counts = defaultdict(int)
        for code in status_codes:
            status_counts[code] += 1
        baseline_status = max(status_counts.keys(), key=lambda k: status_counts[k]) if status_counts else 200
        
        # Content hash baseline
        content_hashes = defaultdict(int)
        for r in responses:
            body = r.get("body", "")
            content_hash = hashlib.md5(body.encode()).hexdigest()[:8]
            content_hashes[content_hash] += 1
        baseline_hash = max(content_hashes.keys(), key=lambda k: content_hashes[k]) if content_hashes else ""
        
        # Detect anomalies
        for response in responses:
            response_id = response.get("id", "unknown")
            
            # Time anomaly (z-score > 2)
            if time_stdev > 0:
                time_val = response.get("response_time", 0)
                z_score = abs(time_val - time_mean) / time_stdev
                if z_score > 2:
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="time",
                        score=min(z_score / 4, 1.0),
                        baseline_value=round(time_mean, 2),
                        actual_value=time_val,
                        deviation=round(z_score, 2),
                        description=f"Response time ({time_val}ms) is {z_score:.1f} standard deviations from mean ({time_mean:.0f}ms)",
                    ))
            
            # Length anomaly (z-score > 2)
            if length_stdev > 0:
                length_val = response.get("response_length", 0)
                z_score = abs(length_val - length_mean) / length_stdev
                if z_score > 2:
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="length",
                        score=min(z_score / 4, 1.0),
                        baseline_value=int(length_mean),
                        actual_value=length_val,
                        deviation=round(z_score, 2),
                        description=f"Response length ({length_val}) is {z_score:.1f} standard deviations from mean ({length_mean:.0f})",
                    ))
            
            # Status code anomaly
            status = response.get("status_code", 200)
            if status != baseline_status:
                # Calculate rarity
                status_ratio = status_counts.get(status, 0) / len(responses)
                if status_ratio < 0.1:  # Less than 10% of responses
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="status",
                        score=1 - status_ratio,
                        baseline_value=baseline_status,
                        actual_value=status,
                        deviation=0,
                        description=f"Uncommon status code {status} (only {status_ratio*100:.1f}% of responses)",
                    ))
            
            # Content anomaly
            body = response.get("body", "")
            content_hash = hashlib.md5(body.encode()).hexdigest()[:8]
            if content_hash != baseline_hash:
                hash_ratio = content_hashes.get(content_hash, 0) / len(responses)
                if hash_ratio < 0.1:  # Less than 10% of responses
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="content",
                        score=1 - hash_ratio,
                        baseline_value=baseline_hash,
                        actual_value=content_hash,
                        deviation=0,
                        description=f"Unique response content (only {hash_ratio*100:.1f}% of responses have similar content)",
                    ))
        
        # Sort by score
        anomalies.sort(key=lambda a: -a.score)
        
        return anomalies
    
    def differential_analysis(
        self,
        baseline_response: Dict[str, Any],
        test_responses: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Perform differential analysis comparing responses to a baseline.
        
        Useful for detecting:
        - Boolean-based SQL injection
        - Authentication bypass
        - Access control issues
        """
        results = []
        
        baseline_length = baseline_response.get("response_length", 0)
        baseline_status = baseline_response.get("status_code", 200)
        baseline_body = baseline_response.get("body", "")
        baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()
        
        for response in test_responses:
            diff_result = {
                "response_id": response.get("id"),
                "payload": response.get("payload"),
                "differences": [],
                "similarity_score": 0.0,
                "potentially_interesting": False,
            }
            
            # Status code difference
            status = response.get("status_code", 200)
            if status != baseline_status:
                diff_result["differences"].append({
                    "type": "status_code",
                    "baseline": baseline_status,
                    "current": status,
                })
            
            # Length difference
            length = response.get("response_length", 0)
            length_diff_pct = abs(length - baseline_length) / max(baseline_length, 1) * 100
            if length_diff_pct > 10:  # More than 10% difference
                diff_result["differences"].append({
                    "type": "length",
                    "baseline": baseline_length,
                    "current": length,
                    "difference_percent": round(length_diff_pct, 1),
                })
            
            # Content difference
            body = response.get("body", "")
            body_hash = hashlib.md5(body.encode()).hexdigest()
            if body_hash != baseline_hash:
                # Calculate similarity using set of words
                baseline_words = set(baseline_body.lower().split())
                current_words = set(body.lower().split())
                if baseline_words or current_words:
                    intersection = baseline_words & current_words
                    union = baseline_words | current_words
                    similarity = len(intersection) / len(union) if union else 1.0
                    diff_result["similarity_score"] = round(similarity, 3)
                    
                    if similarity < 0.9:  # Less than 90% similar
                        diff_result["differences"].append({
                            "type": "content",
                            "similarity": round(similarity, 3),
                        })
            else:
                diff_result["similarity_score"] = 1.0
            
            # Mark as interesting if significant differences
            if diff_result["differences"]:
                diff_result["potentially_interesting"] = True
            
            results.append(diff_result)
        
        # Sort by number of differences (more = more interesting)
        results.sort(key=lambda r: -len(r["differences"]))
        
        return results
    
    def detect_offensive_indicators(
        self,
        responses: List[Dict[str, Any]],
        include_c2: bool = True,
        include_malware: bool = True,
        include_evasion: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Analyze responses for offensive security indicators.
        
        Args:
            responses: List of fuzzing response dicts
            include_c2: Include C2 communication detection
            include_malware: Include malware behavior detection  
            include_evasion: Include sandbox evasion detection
            
        Returns:
            List of detected offensive indicators
        """
        findings: List[Dict[str, Any]] = []
        finding_hashes: Set[str] = set()
        
        # Filter signatures based on options
        signatures_to_check = []
        for sig in self.offensive_signatures:
            if include_c2 and sig.offensive_type == OffensiveType.C2_COMMUNICATION:
                signatures_to_check.append(sig)
            elif include_malware and sig.offensive_type in [
                OffensiveType.MALWARE_BEHAVIOR, OffensiveType.PROCESS_INJECTION,
                OffensiveType.CREDENTIAL_THEFT, OffensiveType.PERSISTENCE,
                OffensiveType.LATERAL_MOVEMENT, OffensiveType.CRYPTOMINER,
                OffensiveType.RANSOMWARE, OffensiveType.RAT_TROJAN, OffensiveType.BOTNET
            ]:
                signatures_to_check.append(sig)
            elif include_evasion and sig.offensive_type == OffensiveType.SANDBOX_EVASION:
                signatures_to_check.append(sig)
            elif sig.offensive_type == OffensiveType.EXFILTRATION:
                signatures_to_check.append(sig)  # Always check exfil
        
        for response in responses:
            body = response.get("body", "")
            headers = response.get("headers", {})
            payload = response.get("payload", "")
            response_id = response.get("id", "unknown")
            
            full_response = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
            
            for sig in signatures_to_check:
                matches = self._check_offensive_signature(sig, full_response)
                if matches:
                    finding_hash = hashlib.md5(
                        f"{sig.name}:{response_id}:{matches[0]}".encode()
                    ).hexdigest()
                    
                    if finding_hash not in finding_hashes:
                        finding_hashes.add(finding_hash)
                        
                        findings.append({
                            "id": finding_hash[:12],
                            "name": sig.name,
                            "type": sig.offensive_type.value,
                            "severity": sig.severity.value,
                            "description": sig.description,
                            "mitre_id": sig.mitre_id,
                            "mitre_tactic": sig.mitre_tactic,
                            "evidence": matches[:5],
                            "payload": payload,
                            "response_id": response_id,
                            "confidence": sig.min_confidence + min(len(matches) * 0.05, 0.2),
                        })
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (severity_order.get(f["severity"], 5), -f["confidence"]))
        
        return findings
    
    def _check_offensive_signature(self, sig: OffensiveSignature, content: str) -> List[str]:
        """Check if offensive signature matches content."""
        matches = []
        for pattern in self.compiled_offensive_patterns.get(sig.name, []):
            for match in pattern.finditer(content):
                matches.append(match.group(0))
        return matches
    
    def generate_offensive_report(
        self,
        responses: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Generate comprehensive offensive security analysis report.
        
        Args:
            responses: List of fuzzing response dicts
            
        Returns:
            Comprehensive offensive analysis report
        """
        # Detect all offensive indicators
        indicators = self.detect_offensive_indicators(responses)
        
        # Group by type
        by_type = defaultdict(list)
        for indicator in indicators:
            by_type[indicator["type"]].append(indicator)
        
        # Count by severity
        severity_counts = defaultdict(int)
        for indicator in indicators:
            severity_counts[indicator["severity"]] += 1
        
        # Extract unique MITRE ATT&CK IDs
        mitre_ids = set()
        mitre_tactics = set()
        for indicator in indicators:
            if indicator.get("mitre_id"):
                mitre_ids.add(indicator["mitre_id"])
            if indicator.get("mitre_tactic"):
                mitre_tactics.add(indicator["mitre_tactic"])
        
        # Calculate threat score
        threat_score = 0
        threat_score += severity_counts.get("critical", 0) * 25
        threat_score += severity_counts.get("high", 0) * 15
        threat_score += severity_counts.get("medium", 0) * 5
        threat_score += severity_counts.get("low", 0) * 2
        threat_score = min(100, threat_score)
        
        # Determine threat level
        if threat_score >= 70:
            threat_level = "critical"
        elif threat_score >= 50:
            threat_level = "high"
        elif threat_score >= 25:
            threat_level = "medium"
        elif threat_score > 0:
            threat_level = "low"
        else:
            threat_level = "none"
        
        return {
            "summary": {
                "total_indicators": len(indicators),
                "threat_score": threat_score,
                "threat_level": threat_level,
                "severity_breakdown": dict(severity_counts),
            },
            "mitre_attack": {
                "techniques": list(mitre_ids),
                "tactics": list(mitre_tactics),
                "technique_count": len(mitre_ids),
            },
            "indicators_by_type": {
                "c2_communication": by_type.get("c2_communication", []),
                "process_injection": by_type.get("process_injection", []),
                "credential_theft": by_type.get("credential_theft", []),
                "persistence": by_type.get("persistence", []),
                "sandbox_evasion": by_type.get("sandbox_evasion", []),
                "lateral_movement": by_type.get("lateral_movement", []),
                "exfiltration": by_type.get("exfiltration", []),
                "cryptominer": by_type.get("cryptominer", []),
                "ransomware": by_type.get("ransomware", []),
                "rat_trojan": by_type.get("rat_trojan", []),
                "botnet": by_type.get("botnet", []),
            },
            "all_indicators": indicators,
            "recommendations": self._generate_offensive_recommendations(indicators),
        }
    
    def _generate_offensive_recommendations(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on offensive indicators."""
        recommendations = []
        
        types_found = set(i["type"] for i in indicators)
        
        if "c2_communication" in types_found:
            recommendations.append(
                "C2 communication detected - Isolate affected systems and investigate "
                "network traffic. Block identified C2 domains/IPs at the firewall."
            )
        
        if "process_injection" in types_found:
            recommendations.append(
                "Process injection techniques detected - Enable memory protection policies "
                "and review process creation monitoring. Consider EDR solutions."
            )
        
        if "credential_theft" in types_found:
            recommendations.append(
                "Credential theft indicators detected - Reset potentially compromised "
                "credentials. Enable MFA and review privileged access."
            )
        
        if "persistence" in types_found:
            recommendations.append(
                "Persistence mechanisms detected - Review scheduled tasks, services, "
                "and registry run keys. Implement application whitelisting."
            )
        
        if "sandbox_evasion" in types_found:
            recommendations.append(
                "Sandbox evasion techniques detected - Use advanced behavioral analysis "
                "and consider extended detonation times in sandbox environments."
            )
        
        if "lateral_movement" in types_found:
            recommendations.append(
                "Lateral movement indicators detected - Implement network segmentation "
                "and review remote execution policies. Enable SMB signing."
            )
        
        if "exfiltration" in types_found:
            recommendations.append(
                "Data exfiltration indicators detected - Review DLP policies and "
                "monitor unusual outbound traffic patterns."
            )
        
        if "cryptominer" in types_found:
            recommendations.append(
                "Cryptominer detected - Block mining pool domains and investigate "
                "unauthorized resource usage."
            )
        
        if "ransomware" in types_found:
            recommendations.append(
                "Ransomware indicators detected - Isolate systems immediately, "
                "preserve evidence, and initiate incident response procedures."
            )
        
        if "rat_trojan" in types_found:
            recommendations.append(
                "Remote Access Trojan indicators detected - Investigate initial "
                "infection vector and check for additional persistence mechanisms."
            )
        
        if "botnet" in types_found:
            recommendations.append(
                "Botnet indicators detected - Block C2 channels, clean affected "
                "systems, and review network for other compromised hosts."
            )
        
        return recommendations
    
    def categorize_responses(
        self,
        responses: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """
        Automatically categorize responses into groups.
        
        Returns categories like:
        - success: 2xx responses
        - redirect: 3xx responses  
        - client_error: 4xx responses
        - server_error: 5xx responses
        - interesting: Flagged as potentially vulnerable
        - timeout: Timed out requests
        - blocked: Potentially blocked by WAF
        """
        categories = defaultdict(list)
        
        for response in responses:
            response_id = response.get("id", "unknown")
            status = response.get("status_code", 0)
            flags = response.get("flags", [])
            error = response.get("error", "")
            body = response.get("body", "").lower()
            
            # Status-based categorization
            if 200 <= status < 300:
                categories["success"].append(response_id)
            elif 300 <= status < 400:
                categories["redirect"].append(response_id)
            elif 400 <= status < 500:
                categories["client_error"].append(response_id)
                if status == 401:
                    categories["auth_required"].append(response_id)
                elif status == 403:
                    categories["forbidden"].append(response_id)
                elif status == 429:
                    categories["rate_limited"].append(response_id)
            elif status >= 500:
                categories["server_error"].append(response_id)
            
            # Flag-based categorization
            if "interesting" in flags or response.get("interesting"):
                categories["interesting"].append(response_id)
            
            # Error-based categorization
            if "timeout" in error.lower():
                categories["timeout"].append(response_id)
            
            # WAF detection
            waf_indicators = [
                "blocked", "forbidden", "access denied",
                "security", "waf", "firewall", "cloudflare",
                "request rejected", "not acceptable",
            ]
            if any(ind in body for ind in waf_indicators):
                categories["blocked"].append(response_id)
        
        return dict(categories)


# =============================================================================
# Session Management Functions
# =============================================================================

def create_session_summary(
    session_data: Dict[str, Any],
    findings: List[SmartFinding],
    anomalies: List[AnomalyResult],
) -> Dict[str, Any]:
    """Create a summary for a fuzzing session."""
    
    # Count findings by severity
    severity_counts = defaultdict(int)
    vuln_type_counts = defaultdict(int)
    for finding in findings:
        severity_counts[finding.severity.value] += 1
        vuln_type_counts[finding.vuln_type.value] += 1
    
    # Calculate risk score
    severity_weights = {
        "critical": 40,
        "high": 25,
        "medium": 10,
        "low": 3,
        "info": 1,
    }
    risk_score = sum(
        severity_weights.get(sev, 0) * count
        for sev, count in severity_counts.items()
    )
    risk_score = min(100, risk_score)  # Cap at 100
    
    return {
        "total_requests": session_data.get("total_requests", 0),
        "success_count": session_data.get("success_count", 0),
        "error_count": session_data.get("error_count", 0),
        "interesting_count": session_data.get("interesting_count", 0),
        "findings_count": len(findings),
        "anomalies_count": len(anomalies),
        "severity_breakdown": dict(severity_counts),
        "vulnerability_types": dict(vuln_type_counts),
        "risk_score": risk_score,
        "risk_level": (
            "critical" if risk_score >= 70 else
            "high" if risk_score >= 40 else
            "medium" if risk_score >= 20 else
            "low" if risk_score >= 5 else
            "info"
        ),
    }


# Create singleton instance
detection_engine = SmartDetectionEngine()


# Convenience functions
def detect_vulnerabilities(
    responses: List[Dict[str, Any]],
    baseline_response: Optional[Dict[str, Any]] = None,
) -> List[SmartFinding]:
    """Detect vulnerabilities in responses."""
    return detection_engine.detect_vulnerabilities(responses, baseline_response)


def detect_anomalies(
    responses: List[Dict[str, Any]],
    baseline_responses: Optional[List[Dict[str, Any]]] = None,
) -> List[AnomalyResult]:
    """Detect anomalous responses."""
    return detection_engine.detect_anomalies(responses, baseline_responses)


def differential_analysis(
    baseline_response: Dict[str, Any],
    test_responses: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Perform differential analysis."""
    return detection_engine.differential_analysis(baseline_response, test_responses)


def categorize_responses(responses: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Categorize responses into groups."""
    return detection_engine.categorize_responses(responses)


def detect_offensive_indicators(
    responses: List[Dict[str, Any]],
    include_c2: bool = True,
    include_malware: bool = True,
    include_evasion: bool = True,
) -> List[Dict[str, Any]]:
    """Detect offensive security indicators in responses."""
    return detection_engine.detect_offensive_indicators(
        responses, include_c2, include_malware, include_evasion
    )


def generate_offensive_report(responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate comprehensive offensive security analysis report."""
    return detection_engine.generate_offensive_report(responses)
