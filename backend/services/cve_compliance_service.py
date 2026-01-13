"""
CVE & Compliance Service - Part 1: CWE Database & Technique Mappings

Provides:
- Comprehensive CWE database with full details
- Technique-to-CWE mappings for all fuzzing techniques
- CWE lookup and enrichment functions

Future parts will add:
- Part 2: CVSS 3.1 Calculator
- Part 3: Compliance Framework Mappings (OWASP, PCI-DSS, HIPAA)
- Part 4: CVE Lookup via NVD API
- Part 5: Integration functions
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# PART 1: CWE DATABASE
# =============================================================================

@dataclass
class CWEEntry:
    """Complete CWE (Common Weakness Enumeration) entry."""
    cwe_id: str  # e.g., "CWE-89"
    name: str
    description: str
    extended_description: Optional[str] = None
    likelihood_of_exploit: str = "Medium"  # Low, Medium, High
    typical_severity: str = "Medium"  # Low, Medium, High, Critical
    detection_methods: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    related_cwes: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "extended_description": self.extended_description,
            "likelihood_of_exploit": self.likelihood_of_exploit,
            "typical_severity": self.typical_severity,
            "detection_methods": self.detection_methods,
            "mitigations": self.mitigations,
            "related_cwes": self.related_cwes,
            "references": self.references,
        }


# Comprehensive CWE Database
CWE_DATABASE: Dict[str, CWEEntry] = {
    # SQL Injection
    "CWE-89": CWEEntry(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="The software constructs all or part of an SQL command using externally-influenced input, but does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        extended_description="SQL injection vulnerabilities occur when user input is incorporated into SQL queries without proper validation or sanitization. Attackers can manipulate queries to access, modify, or delete data.",
        likelihood_of_exploit="High",
        typical_severity="Critical",
        detection_methods=[
            "Static analysis with taint tracking",
            "Dynamic testing with SQL payloads",
            "Code review for parameterized queries",
            "Database query logging analysis",
        ],
        mitigations=[
            "Use parameterized queries or prepared statements",
            "Apply input validation with allowlists",
            "Escape special characters in user input",
            "Use stored procedures",
            "Apply least privilege to database accounts",
            "Implement Web Application Firewall (WAF)",
        ],
        related_cwes=["CWE-564", "CWE-943", "CWE-20"],
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ],
    ),
    
    # XSS
    "CWE-79": CWEEntry(
        cwe_id="CWE-79",
        name="Cross-site Scripting (XSS)",
        description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page served to other users.",
        extended_description="XSS allows attackers to inject client-side scripts into web pages viewed by other users. This can lead to session hijacking, defacement, or redirecting users to malicious sites.",
        likelihood_of_exploit="High",
        typical_severity="High",
        detection_methods=[
            "Static analysis for output encoding",
            "Dynamic testing with script injection",
            "Browser-based XSS detection tools",
            "Content Security Policy violation monitoring",
        ],
        mitigations=[
            "Encode output based on context (HTML, JavaScript, URL, CSS)",
            "Use Content Security Policy (CSP) headers",
            "Apply input validation",
            "Use modern frameworks with auto-escaping",
            "Implement HTTPOnly and Secure cookie flags",
            "Sanitize HTML input with allowlist-based sanitizers",
        ],
        related_cwes=["CWE-80", "CWE-81", "CWE-83", "CWE-87"],
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/attacks/xss/",
        ],
    ),
    
    # Command Injection
    "CWE-78": CWEEntry(
        cwe_id="CWE-78",
        name="OS Command Injection",
        description="The software constructs all or part of an OS command using externally-influenced input, but does not neutralize or incorrectly neutralizes special elements that could modify the intended command.",
        extended_description="Command injection allows attackers to execute arbitrary commands on the host operating system. This often leads to full system compromise.",
        likelihood_of_exploit="High",
        typical_severity="Critical",
        detection_methods=[
            "Static analysis for system call tracking",
            "Dynamic testing with command separators",
            "Process monitoring during testing",
            "Code review for shell invocations",
        ],
        mitigations=[
            "Avoid system calls with user input",
            "Use language-specific APIs instead of shell commands",
            "Apply strict input validation with allowlists",
            "Use parameterized command execution",
            "Run with minimal privileges",
            "Implement sandboxing/containerization",
        ],
        related_cwes=["CWE-77", "CWE-88", "CWE-20"],
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
    ),
    
    # Path Traversal
    "CWE-22": CWEEntry(
        cwe_id="CWE-22",
        name="Path Traversal",
        description="The software uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize sequences like '..' that can resolve to a location outside of that directory.",
        extended_description="Path traversal allows attackers to access files and directories outside the intended scope, potentially exposing sensitive configuration files, credentials, or system files.",
        likelihood_of_exploit="High",
        typical_severity="High",
        detection_methods=[
            "Static analysis for file path construction",
            "Dynamic testing with traversal sequences",
            "Fuzzing with encoded path variations",
            "File access monitoring",
        ],
        mitigations=[
            "Use a safe path canonicalization function",
            "Validate the final path is within allowed directory",
            "Use chroot jails or containers",
            "Apply allowlist for accessible files/directories",
            "Avoid using user input in file paths",
        ],
        related_cwes=["CWE-23", "CWE-36", "CWE-73"],
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
    ),
    
    # IDOR
    "CWE-639": CWEEntry(
        cwe_id="CWE-639",
        name="Insecure Direct Object Reference (IDOR)",
        description="The system's authorization functionality does not prevent one user from accessing another user's data or functionality by modifying key request parameters.",
        extended_description="IDOR occurs when an application exposes internal implementation objects directly to users without proper access control, allowing unauthorized access to other users' data.",
        likelihood_of_exploit="High",
        typical_severity="High",
        detection_methods=[
            "Manual testing with different user sessions",
            "Automated parameter manipulation testing",
            "Access control matrix analysis",
            "Horizontal privilege escalation testing",
        ],
        mitigations=[
            "Implement proper access control checks",
            "Use indirect references (mapping to internal objects)",
            "Validate user authorization for each request",
            "Log and monitor access attempts",
            "Use UUIDs instead of sequential IDs",
        ],
        related_cwes=["CWE-284", "CWE-285", "CWE-862"],
        references=[
            "https://cwe.mitre.org/data/definitions/639.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        ],
    ),
    
    # SSRF
    "CWE-918": CWEEntry(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        description="The web server receives a URL from an upstream component and retrieves the contents of that URL, but does not sufficiently ensure that the request is being sent to the expected destination.",
        extended_description="SSRF allows attackers to make requests from the server to internal resources, potentially accessing cloud metadata, internal services, or bypassing firewalls.",
        likelihood_of_exploit="Medium",
        typical_severity="High",
        detection_methods=[
            "Testing with internal IP addresses",
            "Cloud metadata endpoint probing",
            "DNS rebinding detection",
            "Out-of-band callback testing",
        ],
        mitigations=[
            "Validate and sanitize all URLs",
            "Use allowlists for permitted destinations",
            "Block requests to private IP ranges",
            "Disable unused URL schemes",
            "Use network segmentation",
            "Implement egress filtering",
        ],
        related_cwes=["CWE-611", "CWE-441"],
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        ],
    ),
    
    # SSTI
    "CWE-1336": CWEEntry(
        cwe_id="CWE-1336",
        name="Server-Side Template Injection (SSTI)",
        description="The software uses a template engine to process user-controllable input, but does not properly sanitize the input, allowing attackers to inject template directives.",
        extended_description="SSTI can lead to remote code execution by injecting malicious template code that gets executed on the server. Different template engines have different exploitation techniques.",
        likelihood_of_exploit="Medium",
        typical_severity="Critical",
        detection_methods=[
            "Template syntax fuzzing",
            "Mathematical expression injection",
            "Template engine fingerprinting",
            "Code execution payload testing",
        ],
        mitigations=[
            "Use logic-less templates when possible",
            "Sandbox template execution",
            "Never pass raw user input to templates",
            "Use template engine security features",
            "Apply strict input validation",
        ],
        related_cwes=["CWE-94", "CWE-95"],
        references=[
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://portswigger.net/research/server-side-template-injection",
        ],
    ),
    
    # XXE
    "CWE-611": CWEEntry(
        cwe_id="CWE-611",
        name="XML External Entity (XXE) Injection",
        description="The software processes XML documents that contain references to external entities, which can be exploited to disclose internal files, perform SSRF attacks, or cause denial of service.",
        extended_description="XXE occurs when XML parsers process external entity references, allowing attackers to read local files, perform SSRF, or execute denial of service attacks through entity expansion.",
        likelihood_of_exploit="Medium",
        typical_severity="High",
        detection_methods=[
            "XML payload injection testing",
            "Entity expansion testing",
            "Out-of-band XXE detection",
            "Parser configuration review",
        ],
        mitigations=[
            "Disable external entity processing",
            "Disable DTD processing if not needed",
            "Use less complex data formats (JSON)",
            "Update XML parsers to latest versions",
            "Implement input validation for XML",
        ],
        related_cwes=["CWE-776", "CWE-827"],
        references=[
            "https://cwe.mitre.org/data/definitions/611.html",
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        ],
    ),
    
    # Authentication Bypass
    "CWE-287": CWEEntry(
        cwe_id="CWE-287",
        name="Improper Authentication",
        description="When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        extended_description="Authentication bypass vulnerabilities allow attackers to access protected resources without valid credentials, through logic flaws, default credentials, or implementation errors.",
        likelihood_of_exploit="High",
        typical_severity="Critical",
        detection_methods=[
            "Authentication flow analysis",
            "Session management testing",
            "Default credential checking",
            "Logic flaw testing",
        ],
        mitigations=[
            "Use established authentication frameworks",
            "Implement multi-factor authentication",
            "Enforce strong password policies",
            "Properly validate all authentication paths",
            "Log and monitor authentication attempts",
        ],
        related_cwes=["CWE-288", "CWE-289", "CWE-290", "CWE-306"],
        references=[
            "https://cwe.mitre.org/data/definitions/287.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
        ],
    ),
    
    # Header Injection
    "CWE-113": CWEEntry(
        cwe_id="CWE-113",
        name="HTTP Response Splitting",
        description="The software receives data from an upstream component, but does not neutralize CR and LF characters before the data is included in outgoing HTTP headers.",
        extended_description="HTTP header injection allows attackers to inject arbitrary HTTP headers, potentially leading to cache poisoning, XSS, or session fixation attacks.",
        likelihood_of_exploit="Medium",
        typical_severity="Medium",
        detection_methods=[
            "CRLF injection testing",
            "Header reflection analysis",
            "Response splitting detection",
        ],
        mitigations=[
            "Validate and sanitize header values",
            "Remove CR and LF characters from header input",
            "Use framework-provided header setting methods",
            "Encode special characters",
        ],
        related_cwes=["CWE-93", "CWE-74"],
        references=[
            "https://cwe.mitre.org/data/definitions/113.html",
        ],
    ),
    
    # Business Logic
    "CWE-840": CWEEntry(
        cwe_id="CWE-840",
        name="Business Logic Errors",
        description="The software does not properly implement business rules, or the rules are improperly designed, allowing attackers to perform unauthorized actions.",
        extended_description="Business logic vulnerabilities arise from flaws in application design or implementation that allow users to perform unintended actions or bypass intended workflows.",
        likelihood_of_exploit="Medium",
        typical_severity="High",
        detection_methods=[
            "Manual workflow testing",
            "State machine analysis",
            "Boundary condition testing",
            "Race condition testing",
        ],
        mitigations=[
            "Document and review business rules",
            "Implement proper state management",
            "Validate all workflow transitions",
            "Use atomic transactions",
            "Test edge cases thoroughly",
        ],
        related_cwes=["CWE-841"],
        references=[
            "https://cwe.mitre.org/data/definitions/840.html",
        ],
    ),
    
    # API Abuse
    "CWE-799": CWEEntry(
        cwe_id="CWE-799",
        name="Improper Control of Interaction Frequency",
        description="The software does not properly limit the number or frequency of interactions that it has with other components, leading to resource exhaustion or abuse.",
        extended_description="API abuse vulnerabilities allow attackers to overwhelm services through excessive requests, or exploit rate limiting gaps to abuse functionality.",
        likelihood_of_exploit="High",
        typical_severity="Medium",
        detection_methods=[
            "Rate limiting analysis",
            "Resource exhaustion testing",
            "API fuzzing",
            "Load testing",
        ],
        mitigations=[
            "Implement rate limiting",
            "Use API quotas",
            "Implement CAPTCHA for sensitive operations",
            "Monitor and alert on unusual patterns",
            "Use API gateways",
        ],
        related_cwes=["CWE-770", "CWE-400"],
        references=[
            "https://cwe.mitre.org/data/definitions/799.html",
        ],
    ),
    
    # Parameter Pollution
    "CWE-235": CWEEntry(
        cwe_id="CWE-235",
        name="HTTP Parameter Pollution",
        description="The software receives multiple values for the same parameter, but processes them in a way that leads to unexpected behavior.",
        extended_description="HPP occurs when applications handle duplicate parameters differently, potentially bypassing input validation or WAF rules.",
        likelihood_of_exploit="Medium",
        typical_severity="Medium",
        detection_methods=[
            "Duplicate parameter testing",
            "Array parameter testing",
            "Backend behavior analysis",
        ],
        mitigations=[
            "Define parameter handling behavior",
            "Use only first or last parameter value",
            "Validate all parameter instances",
            "Test with multiple parameters",
        ],
        related_cwes=["CWE-20"],
        references=[
            "https://cwe.mitre.org/data/definitions/235.html",
        ],
    ),
    
    # Race Condition
    "CWE-362": CWEEntry(
        cwe_id="CWE-362",
        name="Race Condition",
        description="The program contains a code sequence that runs concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the resource can be modified by another code sequence.",
        extended_description="Race conditions occur when multiple processes access shared resources concurrently, leading to unexpected behavior like double-spend or TOCTOU vulnerabilities.",
        likelihood_of_exploit="Medium",
        typical_severity="High",
        detection_methods=[
            "Concurrent request testing",
            "Timing analysis",
            "Thread safety analysis",
            "State consistency testing",
        ],
        mitigations=[
            "Use proper locking mechanisms",
            "Implement atomic operations",
            "Use database transactions",
            "Apply optimistic locking",
            "Design for concurrent access",
        ],
        related_cwes=["CWE-367", "CWE-366"],
        references=[
            "https://cwe.mitre.org/data/definitions/362.html",
        ],
    ),
    
    # Insecure Deserialization
    "CWE-502": CWEEntry(
        cwe_id="CWE-502",
        name="Deserialization of Untrusted Data",
        description="The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid and safe.",
        extended_description="Insecure deserialization can lead to remote code execution, authentication bypass, or denial of service when applications process serialized objects from untrusted sources.",
        likelihood_of_exploit="Medium",
        typical_severity="Critical",
        detection_methods=[
            "Serialization format detection",
            "Known gadget chain testing",
            "Custom object injection testing",
        ],
        mitigations=[
            "Avoid deserializing untrusted data",
            "Use type-safe serialization",
            "Implement integrity checks",
            "Isolate deserialization code",
            "Use allowlists for deserialized types",
        ],
        related_cwes=["CWE-915"],
        references=[
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests",
        ],
    ),
    
    # Denial of Service
    "CWE-400": CWEEntry(
        cwe_id="CWE-400",
        name="Uncontrolled Resource Consumption",
        description="The software does not properly control the allocation and maintenance of a limited resource, allowing an actor to influence the amount of resources consumed, eventually causing resource exhaustion.",
        extended_description="DoS vulnerabilities allow attackers to consume server resources (CPU, memory, connections) to make the service unavailable to legitimate users.",
        likelihood_of_exploit="High",
        typical_severity="Medium",
        detection_methods=[
            "Resource consumption testing",
            "Memory leak detection",
            "Connection exhaustion testing",
            "Algorithmic complexity analysis",
        ],
        mitigations=[
            "Implement resource limits",
            "Use timeouts for operations",
            "Apply rate limiting",
            "Monitor resource usage",
            "Design for graceful degradation",
        ],
        related_cwes=["CWE-770", "CWE-799"],
        references=[
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
    ),
    
    # Broken Access Control
    "CWE-284": CWEEntry(
        cwe_id="CWE-284",
        name="Improper Access Control",
        description="The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.",
        extended_description="Access control vulnerabilities allow users to access resources or perform actions beyond their authorized permissions.",
        likelihood_of_exploit="High",
        typical_severity="High",
        detection_methods=[
            "Privilege escalation testing",
            "Role-based access testing",
            "Forced browsing",
            "Access control matrix analysis",
        ],
        mitigations=[
            "Implement least privilege principle",
            "Use role-based access control",
            "Deny by default",
            "Log access control failures",
            "Centralize access control logic",
        ],
        related_cwes=["CWE-285", "CWE-639", "CWE-862"],
        references=[
            "https://cwe.mitre.org/data/definitions/284.html",
        ],
    ),
    
    # Missing Authorization
    "CWE-862": CWEEntry(
        cwe_id="CWE-862",
        name="Missing Authorization",
        description="The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        extended_description="Missing authorization allows any authenticated (or unauthenticated) user to access protected resources or functionality.",
        likelihood_of_exploit="High",
        typical_severity="High",
        detection_methods=[
            "Endpoint enumeration",
            "Authorization header removal testing",
            "Direct URL access testing",
        ],
        mitigations=[
            "Implement authorization for all endpoints",
            "Use centralized authorization framework",
            "Apply deny-by-default policy",
            "Audit all access points",
        ],
        related_cwes=["CWE-284", "CWE-863"],
        references=[
            "https://cwe.mitre.org/data/definitions/862.html",
        ],
    ),
    
    # Prototype Pollution
    "CWE-1321": CWEEntry(
        cwe_id="CWE-1321",
        name="Prototype Pollution",
        description="The software receives input from an upstream component that specifies attributes to initialize or update an object, but does not properly filter special keys like __proto__.",
        extended_description="Prototype pollution in JavaScript allows attackers to modify object prototypes, potentially leading to denial of service, property injection, or remote code execution.",
        likelihood_of_exploit="Medium",
        typical_severity="High",
        detection_methods=[
            "__proto__ injection testing",
            "Constructor pollution testing",
            "Property reflection analysis",
        ],
        mitigations=[
            "Validate object keys against allowlist",
            "Use Object.create(null) for dictionaries",
            "Freeze Object.prototype",
            "Use Map instead of plain objects",
            "Sanitize __proto__ and constructor keys",
        ],
        related_cwes=["CWE-915"],
        references=[
            "https://cwe.mitre.org/data/definitions/1321.html",
        ],
    ),
    
    # GraphQL specific
    "CWE-200": CWEEntry(
        cwe_id="CWE-200",
        name="Exposure of Sensitive Information",
        description="The software exposes sensitive information to an actor not explicitly authorized to have access.",
        extended_description="Information disclosure can occur through error messages, API responses, introspection queries, or verbose logging.",
        likelihood_of_exploit="High",
        typical_severity="Medium",
        detection_methods=[
            "Error message analysis",
            "API response inspection",
            "Schema introspection",
            "Debug mode detection",
        ],
        mitigations=[
            "Disable verbose error messages in production",
            "Implement proper error handling",
            "Review API responses for sensitive data",
            "Disable introspection in production",
        ],
        related_cwes=["CWE-209", "CWE-532"],
        references=[
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    ),
    
    # Cache Poisoning
    "CWE-444": CWEEntry(
        cwe_id="CWE-444",
        name="HTTP Request/Response Smuggling",
        description="When malformed or unusual HTTP requests are received, the software does not properly process them, leading to inconsistent interpretation between components.",
        extended_description="Request smuggling exploits differences in how front-end and back-end servers process HTTP requests, enabling cache poisoning, request hijacking, and security bypass.",
        likelihood_of_exploit="Medium",
        typical_severity="High",
        detection_methods=[
            "CL.TE and TE.CL detection",
            "Desync testing",
            "Timing-based detection",
        ],
        mitigations=[
            "Use HTTP/2 end-to-end",
            "Normalize requests at the edge",
            "Disable connection reuse",
            "Use consistent HTTP parsing",
        ],
        related_cwes=["CWE-436"],
        references=[
            "https://cwe.mitre.org/data/definitions/444.html",
            "https://portswigger.net/web-security/request-smuggling",
        ],
    ),
}


# =============================================================================
# TECHNIQUE TO CWE MAPPINGS
# =============================================================================

# Maps fuzzing technique names to relevant CWE IDs
TECHNIQUE_CWE_MAPPING: Dict[str, List[str]] = {
    "sql_injection": ["CWE-89"],
    "xss": ["CWE-79"],
    "command_injection": ["CWE-78"],
    "path_traversal": ["CWE-22"],
    "idor": ["CWE-639", "CWE-284"],
    "ssrf": ["CWE-918"],
    "ssti": ["CWE-1336"],
    "xxe": ["CWE-611"],
    "auth_bypass": ["CWE-287", "CWE-862"],
    "header_injection": ["CWE-113"],
    "business_logic": ["CWE-840"],
    "api_abuse": ["CWE-799", "CWE-400"],
    "parameter_pollution": ["CWE-235"],
    "race_condition": ["CWE-362"],
    "deserialization": ["CWE-502"],
    "dos": ["CWE-400"],
    "prototype_pollution": ["CWE-1321"],
    "graphql": ["CWE-200", "CWE-799"],
    "cache_poisoning": ["CWE-444"],
    "c2_detection": ["CWE-200"],
    "malware_analysis": ["CWE-200"],
    "evasion_testing": ["CWE-693"],  # Protection Mechanism Failure
}


# =============================================================================
# CWE LOOKUP FUNCTIONS
# =============================================================================

def get_cwe_details(cwe_id: str) -> Optional[CWEEntry]:
    """
    Get full details for a CWE by ID.
    
    Args:
        cwe_id: CWE identifier (e.g., "CWE-89" or "89")
        
    Returns:
        CWEEntry with full details or None if not found
    """
    # Normalize CWE ID format
    if not cwe_id.upper().startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    cwe_id = cwe_id.upper()
    
    return CWE_DATABASE.get(cwe_id)


def get_cwes_for_technique(technique: str) -> List[CWEEntry]:
    """
    Get all CWE details for a fuzzing technique.
    
    Args:
        technique: Technique name (e.g., "sql_injection")
        
    Returns:
        List of CWEEntry objects
    """
    technique = technique.lower().replace(" ", "_").replace("-", "_")
    cwe_ids = TECHNIQUE_CWE_MAPPING.get(technique, [])
    
    return [
        cwe for cwe_id in cwe_ids 
        if (cwe := CWE_DATABASE.get(cwe_id))
    ]


def get_all_cwes_for_techniques(techniques: List[str]) -> Dict[str, List[Dict]]:
    """
    Get all CWE details for multiple techniques.
    
    Args:
        techniques: List of technique names
        
    Returns:
        Dict mapping technique names to list of CWE details
    """
    result = {}
    for tech in techniques:
        cwes = get_cwes_for_technique(tech)
        result[tech] = [cwe.to_dict() for cwe in cwes]
    return result


def get_mitigations_for_technique(technique: str) -> List[str]:
    """
    Get consolidated mitigations for a technique.
    
    Args:
        technique: Technique name
        
    Returns:
        List of unique mitigation recommendations
    """
    cwes = get_cwes_for_technique(technique)
    all_mitigations: Set[str] = set()
    
    for cwe in cwes:
        all_mitigations.update(cwe.mitigations)
    
    return sorted(list(all_mitigations))


def enrich_finding_with_cwe(finding: Dict, technique: str) -> Dict:
    """
    Enrich a finding dictionary with CWE information.
    
    Args:
        finding: Finding dictionary to enrich
        technique: Technique that found this issue
        
    Returns:
        Enriched finding dictionary
    """
    cwes = get_cwes_for_technique(technique)
    
    if cwes:
        primary_cwe = cwes[0]
        finding["cwe"] = {
            "primary": primary_cwe.to_dict(),
            "related": [cwe.to_dict() for cwe in cwes[1:]],
        }
        finding["mitigations"] = get_mitigations_for_technique(technique)
    
    return finding


def search_cwes(query: str) -> List[CWEEntry]:
    """
    Search CWEs by name or description.
    
    Args:
        query: Search string
        
    Returns:
        List of matching CWE entries
    """
    query_lower = query.lower()
    matches = []
    
    for cwe in CWE_DATABASE.values():
        if (query_lower in cwe.name.lower() or 
            query_lower in cwe.description.lower() or
            query_lower in cwe.cwe_id.lower()):
            matches.append(cwe)
    
    return matches


def get_high_severity_cwes() -> List[CWEEntry]:
    """Get all CWEs with High or Critical typical severity."""
    return [
        cwe for cwe in CWE_DATABASE.values()
        if cwe.typical_severity in ("High", "Critical")
    ]


# =============================================================================
# STATISTICS
# =============================================================================

def get_cwe_statistics() -> Dict:
    """Get statistics about the CWE database."""
    severities = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    likelihoods = {"Low": 0, "Medium": 0, "High": 0}
    
    for cwe in CWE_DATABASE.values():
        severities[cwe.typical_severity] = severities.get(cwe.typical_severity, 0) + 1
        likelihoods[cwe.likelihood_of_exploit] = likelihoods.get(cwe.likelihood_of_exploit, 0) + 1
    
    return {
        "total_cwes": len(CWE_DATABASE),
        "mapped_techniques": len(TECHNIQUE_CWE_MAPPING),
        "severity_distribution": severities,
        "likelihood_distribution": likelihoods,
    }


# =============================================================================
# PART 2: CVSS 3.1 CALCULATOR
# =============================================================================

class CVSSv31AttackVector(Enum):
    """CVSS 3.1 Attack Vector metric."""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class CVSSv31AttackComplexity(Enum):
    """CVSS 3.1 Attack Complexity metric."""
    LOW = "L"
    HIGH = "H"


class CVSSv31PrivilegesRequired(Enum):
    """CVSS 3.1 Privileges Required metric."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class CVSSv31UserInteraction(Enum):
    """CVSS 3.1 User Interaction metric."""
    NONE = "N"
    REQUIRED = "R"


class CVSSv31Scope(Enum):
    """CVSS 3.1 Scope metric."""
    UNCHANGED = "U"
    CHANGED = "C"


class CVSSv31Impact(Enum):
    """CVSS 3.1 Impact metric (Confidentiality, Integrity, Availability)."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class CVSSv31Vector:
    """Complete CVSS 3.1 vector with all metrics."""
    # Base metrics (required)
    attack_vector: CVSSv31AttackVector = CVSSv31AttackVector.NETWORK
    attack_complexity: CVSSv31AttackComplexity = CVSSv31AttackComplexity.LOW
    privileges_required: CVSSv31PrivilegesRequired = CVSSv31PrivilegesRequired.NONE
    user_interaction: CVSSv31UserInteraction = CVSSv31UserInteraction.NONE
    scope: CVSSv31Scope = CVSSv31Scope.UNCHANGED
    confidentiality_impact: CVSSv31Impact = CVSSv31Impact.NONE
    integrity_impact: CVSSv31Impact = CVSSv31Impact.NONE
    availability_impact: CVSSv31Impact = CVSSv31Impact.NONE
    
    def to_vector_string(self) -> str:
        """Generate CVSS 3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"S:{self.scope.value}/"
            f"C:{self.confidentiality_impact.value}/"
            f"I:{self.integrity_impact.value}/"
            f"A:{self.availability_impact.value}"
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        score = calculate_cvss_score(self)
        return {
            "vector_string": self.to_vector_string(),
            "attack_vector": self.attack_vector.name,
            "attack_complexity": self.attack_complexity.name,
            "privileges_required": self.privileges_required.name,
            "user_interaction": self.user_interaction.name,
            "scope": self.scope.name,
            "confidentiality_impact": self.confidentiality_impact.name,
            "integrity_impact": self.integrity_impact.name,
            "availability_impact": self.availability_impact.name,
            "base_score": score["base_score"],
            "severity": score["severity"],
        }


# CVSS 3.1 metric weights
CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},  # Scope Changed
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0, "L": 0.22, "H": 0.56},
    "I": {"N": 0, "L": 0.22, "H": 0.56},
    "A": {"N": 0, "L": 0.22, "H": 0.56},
}


def calculate_cvss_score(vector: CVSSv31Vector) -> Dict:
    """
    Calculate CVSS 3.1 base score from vector.
    
    Args:
        vector: CVSSv31Vector with all metrics
        
    Returns:
        Dict with base_score, exploitability, impact, and severity
    """
    # Get metric values
    av = CVSS_WEIGHTS["AV"][vector.attack_vector.value]
    ac = CVSS_WEIGHTS["AC"][vector.attack_complexity.value]
    
    # PR depends on scope
    scope_key = vector.scope.value
    pr = CVSS_WEIGHTS["PR"][scope_key][vector.privileges_required.value]
    
    ui = CVSS_WEIGHTS["UI"][vector.user_interaction.value]
    
    c = CVSS_WEIGHTS["C"][vector.confidentiality_impact.value]
    i = CVSS_WEIGHTS["I"][vector.integrity_impact.value]
    a = CVSS_WEIGHTS["A"][vector.availability_impact.value]
    
    # Calculate Exploitability
    exploitability = 8.22 * av * ac * pr * ui
    
    # Calculate Impact
    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    if vector.scope == CVSSv31Scope.UNCHANGED:
        impact = 6.42 * isc_base
    else:  # Scope Changed
        impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
    
    # Calculate Base Score
    if impact <= 0:
        base_score = 0.0
    else:
        if vector.scope == CVSSv31Scope.UNCHANGED:
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
    
    # Round to 1 decimal place (round up)
    import math
    base_score = math.ceil(base_score * 10) / 10
    
    # Determine severity rating
    if base_score == 0:
        severity = "None"
    elif base_score < 4.0:
        severity = "Low"
    elif base_score < 7.0:
        severity = "Medium"
    elif base_score < 9.0:
        severity = "High"
    else:
        severity = "Critical"
    
    return {
        "base_score": base_score,
        "exploitability_score": round(exploitability, 1),
        "impact_score": round(max(impact, 0), 1),
        "severity": severity,
    }


def parse_cvss_vector(vector_string: str) -> Optional[CVSSv31Vector]:
    """
    Parse a CVSS 3.1 vector string into a CVSSv31Vector object.
    
    Args:
        vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        
    Returns:
        CVSSv31Vector object or None if parsing fails
    """
    try:
        # Remove prefix
        if vector_string.startswith("CVSS:3.1/"):
            vector_string = vector_string[9:]
        elif vector_string.startswith("CVSS:3.0/"):
            vector_string = vector_string[9:]
        
        # Parse metrics
        metrics = {}
        for part in vector_string.split("/"):
            if ":" in part:
                key, value = part.split(":")
                metrics[key] = value
        
        # Map to enums
        av_map = {"N": CVSSv31AttackVector.NETWORK, "A": CVSSv31AttackVector.ADJACENT,
                  "L": CVSSv31AttackVector.LOCAL, "P": CVSSv31AttackVector.PHYSICAL}
        ac_map = {"L": CVSSv31AttackComplexity.LOW, "H": CVSSv31AttackComplexity.HIGH}
        pr_map = {"N": CVSSv31PrivilegesRequired.NONE, "L": CVSSv31PrivilegesRequired.LOW,
                  "H": CVSSv31PrivilegesRequired.HIGH}
        ui_map = {"N": CVSSv31UserInteraction.NONE, "R": CVSSv31UserInteraction.REQUIRED}
        s_map = {"U": CVSSv31Scope.UNCHANGED, "C": CVSSv31Scope.CHANGED}
        impact_map = {"N": CVSSv31Impact.NONE, "L": CVSSv31Impact.LOW, "H": CVSSv31Impact.HIGH}
        
        return CVSSv31Vector(
            attack_vector=av_map.get(metrics.get("AV", "N"), CVSSv31AttackVector.NETWORK),
            attack_complexity=ac_map.get(metrics.get("AC", "L"), CVSSv31AttackComplexity.LOW),
            privileges_required=pr_map.get(metrics.get("PR", "N"), CVSSv31PrivilegesRequired.NONE),
            user_interaction=ui_map.get(metrics.get("UI", "N"), CVSSv31UserInteraction.NONE),
            scope=s_map.get(metrics.get("S", "U"), CVSSv31Scope.UNCHANGED),
            confidentiality_impact=impact_map.get(metrics.get("C", "N"), CVSSv31Impact.NONE),
            integrity_impact=impact_map.get(metrics.get("I", "N"), CVSSv31Impact.NONE),
            availability_impact=impact_map.get(metrics.get("A", "N"), CVSSv31Impact.NONE),
        )
    except Exception as e:
        logger.warning(f"Failed to parse CVSS vector '{vector_string}': {e}")
        return None


# Default CVSS vectors for common vulnerability types
TECHNIQUE_CVSS_DEFAULTS: Dict[str, CVSSv31Vector] = {
    "sql_injection": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.HIGH,
        availability_impact=CVSSv31Impact.HIGH,
    ),
    "xss": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.REQUIRED,
        scope=CVSSv31Scope.CHANGED,
        confidentiality_impact=CVSSv31Impact.LOW,
        integrity_impact=CVSSv31Impact.LOW,
        availability_impact=CVSSv31Impact.NONE,
    ),
    "command_injection": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.HIGH,
        availability_impact=CVSSv31Impact.HIGH,
    ),
    "path_traversal": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.NONE,
        availability_impact=CVSSv31Impact.NONE,
    ),
    "idor": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.LOW,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.LOW,
        availability_impact=CVSSv31Impact.NONE,
    ),
    "ssrf": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.CHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.LOW,
        availability_impact=CVSSv31Impact.NONE,
    ),
    "ssti": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.HIGH,
        availability_impact=CVSSv31Impact.HIGH,
    ),
    "xxe": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.NONE,
        availability_impact=CVSSv31Impact.LOW,
    ),
    "auth_bypass": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.LOW,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.HIGH,
        availability_impact=CVSSv31Impact.NONE,
    ),
    "deserialization": CVSSv31Vector(
        attack_vector=CVSSv31AttackVector.NETWORK,
        attack_complexity=CVSSv31AttackComplexity.HIGH,
        privileges_required=CVSSv31PrivilegesRequired.NONE,
        user_interaction=CVSSv31UserInteraction.NONE,
        scope=CVSSv31Scope.UNCHANGED,
        confidentiality_impact=CVSSv31Impact.HIGH,
        integrity_impact=CVSSv31Impact.HIGH,
        availability_impact=CVSSv31Impact.HIGH,
    ),
}


def get_default_cvss_for_technique(technique: str) -> Optional[CVSSv31Vector]:
    """
    Get default CVSS vector for a fuzzing technique.
    
    Args:
        technique: Technique name (e.g., "sql_injection")
        
    Returns:
        CVSSv31Vector with sensible defaults or None
    """
    technique = technique.lower().replace(" ", "_").replace("-", "_")
    return TECHNIQUE_CVSS_DEFAULTS.get(technique)


def calculate_cvss_for_finding(
    technique: str,
    requires_auth: bool = False,
    requires_user_interaction: bool = False,
    local_only: bool = False,
) -> Dict:
    """
    Calculate CVSS score for a finding with adjustments.
    
    Args:
        technique: Technique that found the vulnerability
        requires_auth: True if exploitation requires authentication
        requires_user_interaction: True if user interaction needed
        local_only: True if only exploitable locally
        
    Returns:
        Dict with CVSS details
    """
    vector = get_default_cvss_for_technique(technique)
    
    if not vector:
        # Create a generic medium-severity vector
        vector = CVSSv31Vector(
            attack_vector=CVSSv31AttackVector.NETWORK,
            attack_complexity=CVSSv31AttackComplexity.LOW,
            privileges_required=CVSSv31PrivilegesRequired.NONE,
            user_interaction=CVSSv31UserInteraction.NONE,
            scope=CVSSv31Scope.UNCHANGED,
            confidentiality_impact=CVSSv31Impact.LOW,
            integrity_impact=CVSSv31Impact.LOW,
            availability_impact=CVSSv31Impact.NONE,
        )
    
    # Apply adjustments
    if requires_auth:
        vector.privileges_required = CVSSv31PrivilegesRequired.LOW
    
    if requires_user_interaction:
        vector.user_interaction = CVSSv31UserInteraction.REQUIRED
    
    if local_only:
        vector.attack_vector = CVSSv31AttackVector.LOCAL
    
    return vector.to_dict()


# =============================================================================
# PART 3: COMPLIANCE FRAMEWORK MAPPINGS
# =============================================================================

@dataclass
class ComplianceRequirement:
    """A specific compliance framework requirement."""
    requirement_id: str  # e.g., "6.5.1" for PCI-DSS
    title: str
    description: str
    framework: str  # "OWASP", "PCI-DSS", "HIPAA"
    category: Optional[str] = None
    verification_steps: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "requirement_id": self.requirement_id,
            "title": self.title,
            "description": self.description,
            "framework": self.framework,
            "category": self.category,
            "verification_steps": self.verification_steps,
        }


# =============================================================================
# OWASP TOP 10 (2021)
# =============================================================================

OWASP_TOP_10_2021: Dict[str, ComplianceRequirement] = {
    "A01": ComplianceRequirement(
        requirement_id="A01:2021",
        title="Broken Access Control",
        description="Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data.",
        framework="OWASP",
        category="Access Control",
        verification_steps=[
            "Test for IDOR vulnerabilities",
            "Verify authorization checks on all endpoints",
            "Test for privilege escalation",
            "Check for missing access controls on functions",
            "Verify CORS configuration",
        ],
    ),
    "A02": ComplianceRequirement(
        requirement_id="A02:2021",
        title="Cryptographic Failures",
        description="Failures related to cryptography which often lead to sensitive data exposure. This includes using weak algorithms, improper key management, or transmitting data in clear text.",
        framework="OWASP",
        category="Data Protection",
        verification_steps=[
            "Verify TLS configuration",
            "Check for sensitive data in URLs",
            "Verify encryption of sensitive data at rest",
            "Check for deprecated crypto algorithms",
            "Verify proper key management",
        ],
    ),
    "A03": ComplianceRequirement(
        requirement_id="A03:2021",
        title="Injection",
        description="Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Common injection types include SQL, NoSQL, OS command, LDAP, and XPath injection.",
        framework="OWASP",
        category="Input Validation",
        verification_steps=[
            "Test for SQL injection",
            "Test for command injection",
            "Test for LDAP injection",
            "Test for XPath injection",
            "Verify use of parameterized queries",
            "Check input validation and sanitization",
        ],
    ),
    "A04": ComplianceRequirement(
        requirement_id="A04:2021",
        title="Insecure Design",
        description="Insecure design represents different weaknesses characterized as missing or ineffective control design. Secure design requires threat modeling, secure design patterns, and reference architectures.",
        framework="OWASP",
        category="Design",
        verification_steps=[
            "Review threat model",
            "Verify security requirements",
            "Check for secure design patterns",
            "Review business logic flows",
            "Verify defense in depth",
        ],
    ),
    "A05": ComplianceRequirement(
        requirement_id="A05:2021",
        title="Security Misconfiguration",
        description="The application might be vulnerable if it is missing appropriate security hardening, has improperly configured permissions, or has unnecessary features enabled.",
        framework="OWASP",
        category="Configuration",
        verification_steps=[
            "Check for default credentials",
            "Verify security headers",
            "Check error handling configuration",
            "Verify unnecessary features are disabled",
            "Check cloud storage permissions",
        ],
    ),
    "A06": ComplianceRequirement(
        requirement_id="A06:2021",
        title="Vulnerable and Outdated Components",
        description="Components such as libraries, frameworks, and software modules run with the same privileges as the application. If a vulnerable component is exploited, it can facilitate serious data loss or server takeover.",
        framework="OWASP",
        category="Supply Chain",
        verification_steps=[
            "Inventory all components and versions",
            "Check for known vulnerabilities",
            "Verify components are from official sources",
            "Monitor for security advisories",
            "Verify update/patching process",
        ],
    ),
    "A07": ComplianceRequirement(
        requirement_id="A07:2021",
        title="Identification and Authentication Failures",
        description="Confirmation of the user's identity, authentication, and session management is critical. Authentication weaknesses can allow attackers to assume other users' identities.",
        framework="OWASP",
        category="Authentication",
        verification_steps=[
            "Test for credential stuffing protection",
            "Verify password policies",
            "Check session management",
            "Test for authentication bypass",
            "Verify MFA implementation",
        ],
    ),
    "A08": ComplianceRequirement(
        requirement_id="A08:2021",
        title="Software and Data Integrity Failures",
        description="Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization and CI/CD pipeline vulnerabilities.",
        framework="OWASP",
        category="Integrity",
        verification_steps=[
            "Test for insecure deserialization",
            "Verify code signing",
            "Check CI/CD pipeline security",
            "Verify integrity checks on updates",
            "Check for unsigned/unverified data",
        ],
    ),
    "A09": ComplianceRequirement(
        requirement_id="A09:2021",
        title="Security Logging and Monitoring Failures",
        description="Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response allows attackers to further attack systems.",
        framework="OWASP",
        category="Logging",
        verification_steps=[
            "Verify security event logging",
            "Check log integrity protection",
            "Verify alerting mechanisms",
            "Test incident response procedures",
            "Check log retention policies",
        ],
    ),
    "A10": ComplianceRequirement(
        requirement_id="A10:2021",
        title="Server-Side Request Forgery (SSRF)",
        description="SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. It allows attackers to send requests to unexpected destinations.",
        framework="OWASP",
        category="Input Validation",
        verification_steps=[
            "Test for SSRF vulnerabilities",
            "Verify URL validation",
            "Check network segmentation",
            "Verify allowlist for destinations",
            "Test with internal IP addresses",
        ],
    ),
}


# =============================================================================
# PCI-DSS 4.0 REQUIREMENTS
# =============================================================================

PCI_DSS_REQUIREMENTS: Dict[str, ComplianceRequirement] = {
    "6.2.4": ComplianceRequirement(
        requirement_id="6.2.4",
        title="Software Engineering Techniques",
        description="Software engineering techniques or other methods are defined and in use by software development personnel to prevent or mitigate common software attacks.",
        framework="PCI-DSS",
        category="Secure Development",
        verification_steps=[
            "Review secure coding standards",
            "Verify developer training",
            "Check code review process",
            "Verify use of security tools",
        ],
    ),
    "6.3.1": ComplianceRequirement(
        requirement_id="6.3.1",
        title="Security Vulnerabilities Identification",
        description="Security vulnerabilities are identified and managed through a defined process.",
        framework="PCI-DSS",
        category="Vulnerability Management",
        verification_steps=[
            "Review vulnerability identification process",
            "Check vulnerability database usage",
            "Verify risk ranking methodology",
        ],
    ),
    "6.4.1": ComplianceRequirement(
        requirement_id="6.4.1",
        title="Public-Facing Web Application Protection",
        description="For public-facing web applications, new threats and vulnerabilities are addressed on an ongoing basis.",
        framework="PCI-DSS",
        category="Web Application Security",
        verification_steps=[
            "Verify WAF deployment",
            "Check vulnerability scanning",
            "Review penetration testing results",
        ],
    ),
    "6.5.1": ComplianceRequirement(
        requirement_id="6.5.1",
        title="Injection Flaws Prevention",
        description="Injection flaws, particularly SQL injection, are addressed in software development to prevent them.",
        framework="PCI-DSS",
        category="Input Validation",
        verification_steps=[
            "Test for SQL injection",
            "Verify parameterized queries",
            "Check input validation",
        ],
    ),
    "6.5.2": ComplianceRequirement(
        requirement_id="6.5.2",
        title="Buffer Overflow Prevention",
        description="Buffer overflows are addressed in software development practices.",
        framework="PCI-DSS",
        category="Memory Safety",
        verification_steps=[
            "Verify safe string functions",
            "Check bounds checking",
            "Review memory allocation",
        ],
    ),
    "6.5.3": ComplianceRequirement(
        requirement_id="6.5.3",
        title="Insecure Cryptographic Storage",
        description="Insecure cryptographic storage is addressed to protect cardholder data.",
        framework="PCI-DSS",
        category="Data Protection",
        verification_steps=[
            "Verify encryption algorithms",
            "Check key management",
            "Test data at rest encryption",
        ],
    ),
    "6.5.4": ComplianceRequirement(
        requirement_id="6.5.4",
        title="Insecure Communications",
        description="Insecure communications are addressed to protect cardholder data in transit.",
        framework="PCI-DSS",
        category="Data Protection",
        verification_steps=[
            "Verify TLS configuration",
            "Check certificate validation",
            "Test for downgrade attacks",
        ],
    ),
    "6.5.5": ComplianceRequirement(
        requirement_id="6.5.5",
        title="Improper Error Handling",
        description="Improper error handling is addressed to prevent information disclosure.",
        framework="PCI-DSS",
        category="Error Handling",
        verification_steps=[
            "Check error messages",
            "Verify stack traces not exposed",
            "Test error handling paths",
        ],
    ),
    "6.5.7": ComplianceRequirement(
        requirement_id="6.5.7",
        title="Cross-Site Scripting (XSS)",
        description="Cross-site scripting (XSS) vulnerabilities are addressed in software development.",
        framework="PCI-DSS",
        category="Input Validation",
        verification_steps=[
            "Test for reflected XSS",
            "Test for stored XSS",
            "Test for DOM-based XSS",
            "Verify output encoding",
        ],
    ),
    "6.5.8": ComplianceRequirement(
        requirement_id="6.5.8",
        title="Improper Access Control",
        description="Improper access control is addressed including insecure direct object references and failure to restrict URL access.",
        framework="PCI-DSS",
        category="Access Control",
        verification_steps=[
            "Test for IDOR",
            "Verify authorization checks",
            "Test for privilege escalation",
        ],
    ),
    "6.5.9": ComplianceRequirement(
        requirement_id="6.5.9",
        title="Cross-Site Request Forgery (CSRF)",
        description="Cross-site request forgery (CSRF) vulnerabilities are addressed.",
        framework="PCI-DSS",
        category="Session Management",
        verification_steps=[
            "Test for CSRF vulnerabilities",
            "Verify CSRF tokens",
            "Check SameSite cookie attribute",
        ],
    ),
    "6.5.10": ComplianceRequirement(
        requirement_id="6.5.10",
        title="Broken Authentication and Session Management",
        description="Broken authentication and session management are addressed.",
        framework="PCI-DSS",
        category="Authentication",
        verification_steps=[
            "Test session management",
            "Verify authentication mechanisms",
            "Check session timeout",
        ],
    ),
}


# =============================================================================
# HIPAA SECURITY RULE
# =============================================================================

HIPAA_REQUIREMENTS: Dict[str, ComplianceRequirement] = {
    "164.308(a)(1)": ComplianceRequirement(
        requirement_id="164.308(a)(1)",
        title="Security Management Process",
        description="Implement policies and procedures to prevent, detect, contain, and correct security violations.",
        framework="HIPAA",
        category="Administrative Safeguards",
        verification_steps=[
            "Review risk analysis process",
            "Check risk management program",
            "Verify sanction policy",
            "Review information system activity review",
        ],
    ),
    "164.308(a)(3)": ComplianceRequirement(
        requirement_id="164.308(a)(3)",
        title="Workforce Security",
        description="Implement policies and procedures to ensure appropriate access to ePHI by workforce members.",
        framework="HIPAA",
        category="Administrative Safeguards",
        verification_steps=[
            "Verify authorization/supervision procedures",
            "Check workforce clearance procedures",
            "Review termination procedures",
        ],
    ),
    "164.308(a)(4)": ComplianceRequirement(
        requirement_id="164.308(a)(4)",
        title="Information Access Management",
        description="Implement policies and procedures for authorizing access to ePHI.",
        framework="HIPAA",
        category="Administrative Safeguards",
        verification_steps=[
            "Review access authorization policies",
            "Verify access establishment procedures",
            "Check access modification procedures",
        ],
    ),
    "164.308(a)(5)": ComplianceRequirement(
        requirement_id="164.308(a)(5)",
        title="Security Awareness and Training",
        description="Implement a security awareness and training program for all workforce members.",
        framework="HIPAA",
        category="Administrative Safeguards",
        verification_steps=[
            "Review training program",
            "Check security reminders",
            "Verify malware protection training",
            "Review login monitoring procedures",
        ],
    ),
    "164.312(a)(1)": ComplianceRequirement(
        requirement_id="164.312(a)(1)",
        title="Access Control",
        description="Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.",
        framework="HIPAA",
        category="Technical Safeguards",
        verification_steps=[
            "Verify unique user identification",
            "Check emergency access procedures",
            "Test automatic logoff",
            "Verify encryption and decryption",
        ],
    ),
    "164.312(b)": ComplianceRequirement(
        requirement_id="164.312(b)",
        title="Audit Controls",
        description="Implement hardware, software, and/or procedural mechanisms to record and examine activity in information systems that contain or use ePHI.",
        framework="HIPAA",
        category="Technical Safeguards",
        verification_steps=[
            "Verify audit logging",
            "Check log review procedures",
            "Test audit trail integrity",
        ],
    ),
    "164.312(c)(1)": ComplianceRequirement(
        requirement_id="164.312(c)(1)",
        title="Integrity",
        description="Implement policies and procedures to protect ePHI from improper alteration or destruction.",
        framework="HIPAA",
        category="Technical Safeguards",
        verification_steps=[
            "Verify integrity controls",
            "Check checksums/digital signatures",
            "Test data validation",
        ],
    ),
    "164.312(d)": ComplianceRequirement(
        requirement_id="164.312(d)",
        title="Person or Entity Authentication",
        description="Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.",
        framework="HIPAA",
        category="Technical Safeguards",
        verification_steps=[
            "Verify authentication mechanisms",
            "Check multi-factor authentication",
            "Test authentication bypass",
        ],
    ),
    "164.312(e)(1)": ComplianceRequirement(
        requirement_id="164.312(e)(1)",
        title="Transmission Security",
        description="Implement technical security measures to guard against unauthorized access to ePHI transmitted over electronic communications networks.",
        framework="HIPAA",
        category="Technical Safeguards",
        verification_steps=[
            "Verify encryption in transit",
            "Check TLS configuration",
            "Test integrity controls",
        ],
    ),
}


# =============================================================================
# TECHNIQUE TO COMPLIANCE MAPPINGS
# =============================================================================

TECHNIQUE_OWASP_MAPPING: Dict[str, List[str]] = {
    "sql_injection": ["A03"],
    "xss": ["A03"],
    "command_injection": ["A03"],
    "path_traversal": ["A01", "A03"],
    "idor": ["A01"],
    "ssrf": ["A10"],
    "ssti": ["A03"],
    "xxe": ["A03", "A05"],
    "auth_bypass": ["A01", "A07"],
    "header_injection": ["A03"],
    "business_logic": ["A04"],
    "api_abuse": ["A01", "A05"],
    "parameter_pollution": ["A03"],
    "race_condition": ["A04"],
    "deserialization": ["A08"],
    "dos": ["A05"],
    "prototype_pollution": ["A03"],
    "graphql": ["A01", "A03", "A05"],
    "cache_poisoning": ["A05"],
}

TECHNIQUE_PCI_DSS_MAPPING: Dict[str, List[str]] = {
    "sql_injection": ["6.5.1"],
    "xss": ["6.5.7"],
    "command_injection": ["6.5.1"],
    "path_traversal": ["6.5.8"],
    "idor": ["6.5.8"],
    "ssrf": ["6.4.1"],
    "auth_bypass": ["6.5.10"],
    "deserialization": ["6.2.4"],
    "header_injection": ["6.5.1"],
    "business_logic": ["6.2.4"],
}

TECHNIQUE_HIPAA_MAPPING: Dict[str, List[str]] = {
    "sql_injection": ["164.312(a)(1)", "164.312(c)(1)"],
    "xss": ["164.312(a)(1)"],
    "auth_bypass": ["164.312(d)", "164.312(a)(1)"],
    "idor": ["164.312(a)(1)", "164.308(a)(4)"],
    "path_traversal": ["164.312(a)(1)", "164.312(c)(1)"],
    "ssrf": ["164.312(a)(1)"],
    "command_injection": ["164.312(a)(1)", "164.312(c)(1)"],
}


# =============================================================================
# COMPLIANCE LOOKUP FUNCTIONS
# =============================================================================

def get_owasp_requirement(requirement_id: str) -> Optional[ComplianceRequirement]:
    """Get OWASP Top 10 requirement by ID."""
    # Handle both "A01" and "A01:2021" formats
    key = requirement_id.split(":")[0] if ":" in requirement_id else requirement_id
    return OWASP_TOP_10_2021.get(key)


def get_pci_dss_requirement(requirement_id: str) -> Optional[ComplianceRequirement]:
    """Get PCI-DSS requirement by ID."""
    return PCI_DSS_REQUIREMENTS.get(requirement_id)


def get_hipaa_requirement(requirement_id: str) -> Optional[ComplianceRequirement]:
    """Get HIPAA requirement by ID."""
    return HIPAA_REQUIREMENTS.get(requirement_id)


def get_compliance_for_technique(technique: str) -> Dict[str, List[Dict]]:
    """
    Get all compliance requirements for a fuzzing technique.
    
    Args:
        technique: Technique name (e.g., "sql_injection")
        
    Returns:
        Dict with OWASP, PCI-DSS, and HIPAA requirements
    """
    technique = technique.lower().replace(" ", "_").replace("-", "_")
    
    result = {
        "OWASP": [],
        "PCI-DSS": [],
        "HIPAA": [],
    }
    
    # OWASP mappings
    owasp_ids = TECHNIQUE_OWASP_MAPPING.get(technique, [])
    for oid in owasp_ids:
        if req := OWASP_TOP_10_2021.get(oid):
            result["OWASP"].append(req.to_dict())
    
    # PCI-DSS mappings
    pci_ids = TECHNIQUE_PCI_DSS_MAPPING.get(technique, [])
    for pid in pci_ids:
        if req := PCI_DSS_REQUIREMENTS.get(pid):
            result["PCI-DSS"].append(req.to_dict())
    
    # HIPAA mappings
    hipaa_ids = TECHNIQUE_HIPAA_MAPPING.get(technique, [])
    for hid in hipaa_ids:
        if req := HIPAA_REQUIREMENTS.get(hid):
            result["HIPAA"].append(req.to_dict())
    
    return result


def get_all_compliance_for_techniques(techniques: List[str]) -> Dict[str, Dict]:
    """
    Get all compliance requirements for multiple techniques.
    
    Args:
        techniques: List of technique names
        
    Returns:
        Dict mapping technique names to compliance requirements
    """
    return {tech: get_compliance_for_technique(tech) for tech in techniques}


def get_compliance_summary_for_findings(findings: List[Dict]) -> Dict:
    """
    Generate compliance summary from a list of findings.
    
    Args:
        findings: List of finding dictionaries with 'technique' field
        
    Returns:
        Summary of compliance violations
    """
    owasp_violations: Set[str] = set()
    pci_violations: Set[str] = set()
    hipaa_violations: Set[str] = set()
    
    for finding in findings:
        technique = finding.get("technique", "").lower().replace(" ", "_")
        
        owasp_ids = TECHNIQUE_OWASP_MAPPING.get(technique, [])
        owasp_violations.update(owasp_ids)
        
        pci_ids = TECHNIQUE_PCI_DSS_MAPPING.get(technique, [])
        pci_violations.update(pci_ids)
        
        hipaa_ids = TECHNIQUE_HIPAA_MAPPING.get(technique, [])
        hipaa_violations.update(hipaa_ids)
    
    return {
        "OWASP": {
            "violations": list(owasp_violations),
            "count": len(owasp_violations),
            "details": [
                OWASP_TOP_10_2021[oid].to_dict() 
                for oid in owasp_violations 
                if oid in OWASP_TOP_10_2021
            ],
        },
        "PCI-DSS": {
            "violations": list(pci_violations),
            "count": len(pci_violations),
            "details": [
                PCI_DSS_REQUIREMENTS[pid].to_dict() 
                for pid in pci_violations 
                if pid in PCI_DSS_REQUIREMENTS
            ],
        },
        "HIPAA": {
            "violations": list(hipaa_violations),
            "count": len(hipaa_violations),
            "details": [
                HIPAA_REQUIREMENTS[hid].to_dict() 
                for hid in hipaa_violations 
                if hid in HIPAA_REQUIREMENTS
            ],
        },
        "total_frameworks_affected": sum([
            1 if owasp_violations else 0,
            1 if pci_violations else 0,
            1 if hipaa_violations else 0,
        ]),
    }


def get_all_compliance_frameworks() -> Dict[str, Dict]:
    """Get all compliance frameworks with their requirements."""
    return {
        "OWASP_Top_10_2021": {
            "name": "OWASP Top 10 2021",
            "description": "The most critical security risks to web applications",
            "requirements": {k: v.to_dict() for k, v in OWASP_TOP_10_2021.items()},
            "count": len(OWASP_TOP_10_2021),
        },
        "PCI_DSS_4_0": {
            "name": "PCI-DSS 4.0",
            "description": "Payment Card Industry Data Security Standard",
            "requirements": {k: v.to_dict() for k, v in PCI_DSS_REQUIREMENTS.items()},
            "count": len(PCI_DSS_REQUIREMENTS),
        },
        "HIPAA": {
            "name": "HIPAA Security Rule",
            "description": "Health Insurance Portability and Accountability Act",
            "requirements": {k: v.to_dict() for k, v in HIPAA_REQUIREMENTS.items()},
            "count": len(HIPAA_REQUIREMENTS),
        },
    }


# =============================================================================
# PART 4: CVE LOOKUP SERVICE (NVD API)
# =============================================================================

import aiohttp
import asyncio
from datetime import datetime, timedelta
from functools import lru_cache


@dataclass
class CVEEntry:
    """CVE (Common Vulnerabilities and Exposures) entry."""
    cve_id: str  # e.g., "CVE-2021-44228"
    description: str
    published_date: str
    last_modified: str
    cvss_v31_score: Optional[float] = None
    cvss_v31_vector: Optional[str] = None
    cvss_v31_severity: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "published_date": self.published_date,
            "last_modified": self.last_modified,
            "cvss_v31_score": self.cvss_v31_score,
            "cvss_v31_vector": self.cvss_v31_vector,
            "cvss_v31_severity": self.cvss_v31_severity,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
            "affected_products": self.affected_products,
        }


# CVE Cache to avoid excessive API calls
_cve_cache: Dict[str, CVEEntry] = {}
_cve_cache_expiry: Dict[str, datetime] = {}
CVE_CACHE_TTL = timedelta(hours=24)


# Known CVEs for common vulnerability types (fallback when API unavailable)
KNOWN_CVES_BY_TECHNIQUE: Dict[str, List[Dict]] = {
    "sql_injection": [
        {
            "cve_id": "CVE-2019-9193",
            "description": "PostgreSQL 9.3-11.2: SQL injection via pg_read_server_files",
            "cvss_score": 9.8,
        },
        {
            "cve_id": "CVE-2017-5689",
            "description": "Intel AMT SQL injection vulnerability",
            "cvss_score": 9.8,
        },
    ],
    "xss": [
        {
            "cve_id": "CVE-2020-11022",
            "description": "jQuery XSS vulnerability in HTML parsing",
            "cvss_score": 6.1,
        },
        {
            "cve_id": "CVE-2021-41174",
            "description": "Grafana XSS via URL manipulation",
            "cvss_score": 6.1,
        },
    ],
    "command_injection": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Log4j RCE (Log4Shell)",
            "cvss_score": 10.0,
        },
        {
            "cve_id": "CVE-2014-6271",
            "description": "Shellshock Bash command injection",
            "cvss_score": 9.8,
        },
    ],
    "ssrf": [
        {
            "cve_id": "CVE-2019-17571",
            "description": "Apache Log4j SSRF",
            "cvss_score": 9.8,
        },
        {
            "cve_id": "CVE-2021-21975",
            "description": "VMware vRealize Operations SSRF",
            "cvss_score": 7.5,
        },
    ],
    "path_traversal": [
        {
            "cve_id": "CVE-2021-41773",
            "description": "Apache HTTP Server path traversal",
            "cvss_score": 7.5,
        },
        {
            "cve_id": "CVE-2020-5902",
            "description": "F5 BIG-IP path traversal RCE",
            "cvss_score": 9.8,
        },
    ],
    "xxe": [
        {
            "cve_id": "CVE-2014-3529",
            "description": "Apache POI XXE vulnerability",
            "cvss_score": 7.5,
        },
        {
            "cve_id": "CVE-2019-0227",
            "description": "Apache Axis 1.4 XXE",
            "cvss_score": 7.5,
        },
    ],
    "deserialization": [
        {
            "cve_id": "CVE-2017-9805",
            "description": "Apache Struts 2 REST plugin RCE",
            "cvss_score": 8.1,
        },
        {
            "cve_id": "CVE-2015-4852",
            "description": "Oracle WebLogic Java deserialization",
            "cvss_score": 9.8,
        },
    ],
    "auth_bypass": [
        {
            "cve_id": "CVE-2020-1472",
            "description": "Zerologon - Netlogon authentication bypass",
            "cvss_score": 10.0,
        },
        {
            "cve_id": "CVE-2021-22205",
            "description": "GitLab authentication bypass RCE",
            "cvss_score": 10.0,
        },
    ],
    "ssti": [
        {
            "cve_id": "CVE-2019-6340",
            "description": "Drupal SSTI RCE",
            "cvss_score": 9.8,
        },
        {
            "cve_id": "CVE-2020-17530",
            "description": "Apache Struts 2 OGNL injection",
            "cvss_score": 9.8,
        },
    ],
}


class NVDAPIClient:
    """
    Client for NIST National Vulnerability Database (NVD) API.
    
    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD API client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self._last_request_time = 0
        # Rate limit: 5 requests per 30 seconds without key, 50 with key
        self._min_request_interval = 6.0 if not api_key else 0.6
    
    async def _rate_limit(self):
        """Enforce rate limiting."""
        import time
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            await asyncio.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()
    
    async def search_cves(
        self,
        keyword: Optional[str] = None,
        cwe_id: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        results_per_page: int = 10,
    ) -> List[CVEEntry]:
        """
        Search for CVEs using NVD API.
        
        Args:
            keyword: Search keyword
            cwe_id: Filter by CWE ID
            cvss_v3_severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
            results_per_page: Number of results to return
            
        Returns:
            List of CVE entries
        """
        await self._rate_limit()
        
        params = {"resultsPerPage": results_per_page}
        
        if keyword:
            params["keywordSearch"] = keyword
        if cwe_id:
            # Format: CWE-89 or just 89
            cwe_num = cwe_id.replace("CWE-", "")
            params["cweId"] = f"CWE-{cwe_num}"
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status != 200:
                        logger.warning(f"NVD API returned status {response.status}")
                        return []
                    
                    data = await response.json()
                    return self._parse_cve_response(data)
        except Exception as e:
            logger.error(f"NVD API request failed: {e}")
            return []
    
    async def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """
        Get a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            
        Returns:
            CVE entry or None if not found
        """
        # Check cache first
        if cve_id in _cve_cache:
            if datetime.now() < _cve_cache_expiry.get(cve_id, datetime.min):
                return _cve_cache[cve_id]
        
        await self._rate_limit()
        
        # Normalize CVE ID format
        if not cve_id.upper().startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        cve_id = cve_id.upper()
        
        params = {"cveId": cve_id}
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status != 200:
                        logger.warning(f"NVD API returned status {response.status} for {cve_id}")
                        return None
                    
                    data = await response.json()
                    entries = self._parse_cve_response(data)
                    
                    if entries:
                        # Cache the result
                        _cve_cache[cve_id] = entries[0]
                        _cve_cache_expiry[cve_id] = datetime.now() + CVE_CACHE_TTL
                        return entries[0]
                    return None
        except Exception as e:
            logger.error(f"NVD API request failed for {cve_id}: {e}")
            return None
    
    def _parse_cve_response(self, data: Dict) -> List[CVEEntry]:
        """Parse NVD API response into CVE entries."""
        entries = []
        
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Get CVSS v3.1 metrics
            cvss_score = None
            cvss_vector = None
            cvss_severity = None
            
            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                primary = cvss_v31[0].get("cvssData", {})
                cvss_score = primary.get("baseScore")
                cvss_vector = primary.get("vectorString")
                cvss_severity = primary.get("baseSeverity")
            
            # Get CWE IDs
            cwe_ids = []
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwe_ids.append(cwe_value)
            
            # Get references
            references = []
            for ref in cve_data.get("references", [])[:5]:  # Limit to 5 refs
                references.append(ref.get("url", ""))
            
            entries.append(CVEEntry(
                cve_id=cve_data.get("id", ""),
                description=description,
                published_date=cve_data.get("published", ""),
                last_modified=cve_data.get("lastModified", ""),
                cvss_v31_score=cvss_score,
                cvss_v31_vector=cvss_vector,
                cvss_v31_severity=cvss_severity,
                cwe_ids=cwe_ids,
                references=references,
            ))
        
        return entries


# Global NVD client instance
_nvd_client: Optional[NVDAPIClient] = None


def get_nvd_client(api_key: Optional[str] = None) -> NVDAPIClient:
    """Get or create NVD API client."""
    global _nvd_client
    if _nvd_client is None:
        _nvd_client = NVDAPIClient(api_key)
    return _nvd_client


async def search_cves_for_technique(
    technique: str,
    use_api: bool = True,
    api_key: Optional[str] = None,
) -> List[Dict]:
    """
    Search for CVEs related to a fuzzing technique.
    
    Args:
        technique: Technique name (e.g., "sql_injection")
        use_api: Whether to query NVD API (False = use local cache only)
        api_key: Optional NVD API key
        
    Returns:
        List of CVE details
    """
    technique = technique.lower().replace(" ", "_").replace("-", "_")
    
    # Start with known CVEs
    results = KNOWN_CVES_BY_TECHNIQUE.get(technique, []).copy()
    
    if use_api:
        # Get CWEs for this technique to search by
        cwe_ids = TECHNIQUE_CWE_MAPPING.get(technique, [])
        
        if cwe_ids:
            client = get_nvd_client(api_key)
            
            # Search by primary CWE
            try:
                api_results = await client.search_cves(
                    cwe_id=cwe_ids[0],
                    cvss_v3_severity="HIGH",
                    results_per_page=5,
                )
                for cve in api_results:
                    results.append(cve.to_dict())
            except Exception as e:
                logger.warning(f"NVD API search failed: {e}")
    
    # Deduplicate by CVE ID
    seen = set()
    unique_results = []
    for r in results:
        cve_id = r.get("cve_id")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique_results.append(r)
    
    return unique_results


async def get_cve_details(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict]:
    """
    Get detailed CVE information.
    
    Args:
        cve_id: CVE identifier
        api_key: Optional NVD API key
        
    Returns:
        CVE details or None
    """
    client = get_nvd_client(api_key)
    cve = await client.get_cve(cve_id)
    return cve.to_dict() if cve else None


def get_known_cves_for_technique(technique: str) -> List[Dict]:
    """
    Get known CVEs for a technique (no API call).
    
    Args:
        technique: Technique name
        
    Returns:
        List of known CVEs
    """
    technique = technique.lower().replace(" ", "_").replace("-", "_")
    return KNOWN_CVES_BY_TECHNIQUE.get(technique, [])


# =============================================================================
# PART 5: FINDING ENRICHMENT & INTEGRATION
# =============================================================================

@dataclass
class EnrichedFinding:
    """A finding enriched with CVE, CWE, CVSS, and compliance data."""
    original_finding: Dict
    technique: str
    cwes: List[Dict]
    cvss: Dict
    compliance: Dict[str, List[Dict]]
    cves: List[Dict]
    mitigations: List[str]
    
    def to_dict(self) -> Dict:
        enriched = self.original_finding.copy()
        enriched.update({
            "cwe_data": self.cwes,
            "cvss_data": self.cvss,
            "compliance_data": self.compliance,
            "related_cves": self.cves,
            "recommended_mitigations": self.mitigations,
        })
        return enriched


async def enrich_finding(
    finding: Dict,
    technique: str,
    include_cves: bool = True,
    api_key: Optional[str] = None,
) -> EnrichedFinding:
    """
    Fully enrich a finding with all available security data.
    
    Args:
        finding: Original finding dictionary
        technique: Technique that found this issue
        include_cves: Whether to fetch CVE data
        api_key: Optional NVD API key
        
    Returns:
        EnrichedFinding with all data
    """
    technique = technique.lower().replace(" ", "_").replace("-", "_")
    
    # Get CWE data
    cwe_entries = get_cwes_for_technique(technique)
    cwes = [cwe.to_dict() for cwe in cwe_entries]
    
    # Calculate CVSS
    requires_auth = finding.get("requires_authentication", False)
    requires_ui = finding.get("requires_user_interaction", False)
    cvss = calculate_cvss_for_finding(
        technique,
        requires_auth=requires_auth,
        requires_user_interaction=requires_ui,
    )
    
    # Get compliance mappings
    compliance = get_compliance_for_technique(technique)
    
    # Get CVE data
    cves = []
    if include_cves:
        cves = await search_cves_for_technique(
            technique, 
            use_api=True, 
            api_key=api_key
        )
    else:
        cves = get_known_cves_for_technique(technique)
    
    # Get mitigations
    mitigations = get_mitigations_for_technique(technique)
    
    return EnrichedFinding(
        original_finding=finding,
        technique=technique,
        cwes=cwes,
        cvss=cvss,
        compliance=compliance,
        cves=cves,
        mitigations=mitigations,
    )


def enrich_finding_sync(
    finding: Dict,
    technique: str,
) -> Dict:
    """
    Synchronously enrich a finding (no CVE API calls).
    
    Args:
        finding: Original finding dictionary
        technique: Technique that found this issue
        
    Returns:
        Enriched finding dictionary
    """
    technique = technique.lower().replace(" ", "_").replace("-", "_")
    
    # Get CWE data
    cwe_entries = get_cwes_for_technique(technique)
    cwes = [cwe.to_dict() for cwe in cwe_entries]
    
    # Calculate CVSS
    requires_auth = finding.get("requires_authentication", False)
    requires_ui = finding.get("requires_user_interaction", False)
    cvss = calculate_cvss_for_finding(
        technique,
        requires_auth=requires_auth,
        requires_user_interaction=requires_ui,
    )
    
    # Get compliance mappings
    compliance = get_compliance_for_technique(technique)
    
    # Get known CVEs (no API call)
    cves = get_known_cves_for_technique(technique)
    
    # Get mitigations
    mitigations = get_mitigations_for_technique(technique)
    
    # Return enriched finding
    enriched = finding.copy()
    enriched.update({
        "cwe_data": cwes,
        "cvss_data": cvss,
        "compliance_data": compliance,
        "related_cves": cves,
        "recommended_mitigations": mitigations,
    })
    return enriched


async def enrich_findings_batch(
    findings: List[Dict],
    include_cves: bool = True,
    api_key: Optional[str] = None,
) -> List[Dict]:
    """
    Enrich multiple findings with security data.
    
    Args:
        findings: List of finding dictionaries
        include_cves: Whether to fetch CVE data
        api_key: Optional NVD API key
        
    Returns:
        List of enriched findings
    """
    enriched_findings = []
    
    for finding in findings:
        technique = finding.get("technique", "")
        if not technique:
            enriched_findings.append(finding)
            continue
        
        try:
            if include_cves:
                enriched = await enrich_finding(
                    finding, 
                    technique, 
                    include_cves=True,
                    api_key=api_key
                )
                enriched_findings.append(enriched.to_dict())
            else:
                enriched_findings.append(enrich_finding_sync(finding, technique))
        except Exception as e:
            logger.warning(f"Failed to enrich finding: {e}")
            enriched_findings.append(finding)
    
    return enriched_findings


def generate_security_report(
    findings: List[Dict],
    include_compliance: bool = True,
) -> Dict:
    """
    Generate a comprehensive security report from findings.
    
    Args:
        findings: List of finding dictionaries
        include_compliance: Whether to include compliance summary
        
    Returns:
        Security report dictionary
    """
    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = finding.get("severity", "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Techniques used
    techniques = set()
    for finding in findings:
        tech = finding.get("technique", "")
        if tech:
            techniques.add(tech)
    
    # Build report
    report = {
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "techniques_detected": list(techniques),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
        },
        "findings": findings,
    }
    
    # Add compliance summary if requested
    if include_compliance:
        report["compliance_summary"] = get_compliance_summary_for_findings(findings)
    
    # Add CWE statistics
    cwe_counts: Dict[str, int] = {}
    for finding in findings:
        cwe_data = finding.get("cwe_data", [])
        for cwe in cwe_data:
            cwe_id = cwe.get("cwe_id", "")
            if cwe_id:
                cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
    
    report["cwe_summary"] = {
        "unique_cwes": len(cwe_counts),
        "cwe_counts": cwe_counts,
    }
    
    return report


# =============================================================================
# SERVICE EXPORTS
# =============================================================================

__all__ = [
    # CWE
    "CWEEntry",
    "CWE_DATABASE",
    "TECHNIQUE_CWE_MAPPING",
    "get_cwe_details",
    "get_cwes_for_technique",
    "get_all_cwes_for_techniques",
    "get_mitigations_for_technique",
    "enrich_finding_with_cwe",
    "search_cwes",
    "get_high_severity_cwes",
    "get_cwe_statistics",
    
    # CVSS
    "CVSSv31Vector",
    "CVSSv31AttackVector",
    "CVSSv31AttackComplexity",
    "CVSSv31PrivilegesRequired",
    "CVSSv31UserInteraction",
    "CVSSv31Scope",
    "CVSSv31Impact",
    "calculate_cvss_score",
    "parse_cvss_vector",
    "get_default_cvss_for_technique",
    "calculate_cvss_for_finding",
    "TECHNIQUE_CVSS_DEFAULTS",
    
    # Compliance
    "ComplianceRequirement",
    "OWASP_TOP_10_2021",
    "PCI_DSS_REQUIREMENTS",
    "HIPAA_REQUIREMENTS",
    "get_owasp_requirement",
    "get_pci_dss_requirement",
    "get_hipaa_requirement",
    "get_compliance_for_technique",
    "get_all_compliance_for_techniques",
    "get_compliance_summary_for_findings",
    "get_all_compliance_frameworks",
    
    # CVE
    "CVEEntry",
    "NVDAPIClient",
    "get_nvd_client",
    "search_cves_for_technique",
    "get_cve_details",
    "get_known_cves_for_technique",
    "KNOWN_CVES_BY_TECHNIQUE",
    
    # Integration
    "EnrichedFinding",
    "enrich_finding",
    "enrich_finding_sync",
    "enrich_findings_batch",
    "generate_security_report",
]
