"""
AI-Enhanced Vulnerability Analysis Service

Provides intelligent analysis of scan findings using LLM:
1. False Positive Detection - Identify likely false positives
2. Data Flow Analysis - Trace how tainted data flows
3. Severity Adjustment - Re-assess severity based on context
4. Attack Chain Discovery - Find chained vulnerabilities
5. Custom Remediation - Generate tailored fix code
6. Agentic Corroboration - Cross-reference SAST findings with Agentic AI findings

Optimized for minimal LLM calls by batching findings.

Large Codebase Optimizations:
- Smart finding prioritization to focus LLM on highest-value findings
- Adaptive batch sizes based on total findings
- Caching of analysis results for identical patterns
- Progressive analysis with early termination for resource limits

Agentic AI Corroboration:
- Scanner findings without matching agentic findings are more likely false positives
- Scanner findings WITH matching agentic findings are more likely genuine
- AI Analysis acts as the final judge on vulnerability validity
"""

import json
import re
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from pathlib import Path

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Large codebase configuration
MAX_FINDINGS_FOR_FULL_ANALYSIS = settings.max_findings_for_ai if hasattr(settings, 'max_findings_for_ai') else 500
MAX_FINDINGS_FOR_LLM = settings.max_findings_for_llm if hasattr(settings, 'max_findings_for_llm') else 50
SIMILAR_FINDING_THRESHOLD = 0.8  # Dedupe findings this similar
MAX_FINDINGS_PER_TYPE = 10  # Limit findings per vulnerability type for diversity

# Use google-genai SDK (new unified SDK)
genai_client = None
if settings.gemini_api_key:
    try:
        from google import genai
        genai_client = genai.Client(api_key=settings.gemini_api_key)
    except ImportError:
        logger.warning("google-genai not installed, AI analysis disabled")


@dataclass
class AIAnalysisResult:
    """Result of AI analysis for a finding."""
    finding_id: int
    false_positive_score: float = 0.0  # 0-1, higher = more likely false positive
    false_positive_reason: Optional[str] = None
    adjusted_severity: Optional[str] = None
    severity_reason: Optional[str] = None
    data_flow: Optional[str] = None
    remediation_code: Optional[str] = None
    related_findings: List[int] = field(default_factory=list)  # IDs of related findings


@dataclass 
class AttackChain:
    """A potential attack chain combining multiple vulnerabilities."""
    title: str
    severity: str
    finding_ids: List[int]
    chain_description: str
    impact: str
    likelihood: str  # low, medium, high


@dataclass
class AIAnalysisSummary:
    """Complete AI analysis for a scan."""
    findings_analyzed: int
    false_positives_detected: int
    severity_adjustments: int
    attack_chains: List[AttackChain]
    analysis_results: Dict[int, AIAnalysisResult]  # finding_id -> result
    agentic_corroborated: int = 0  # Findings confirmed by agentic AI
    filtered_out: int = 0  # Findings filtered as likely false positives
    uncertain_findings: int = 0  # Findings with FP score 0.5-0.6 (gray zone)


# FP Score Thresholds
FP_THRESHOLD_FILTERED = 0.6  # Score >= this AND not corroborated = filtered_out
FP_THRESHOLD_UNCERTAIN = 0.5  # Score >= this but < 0.6 = uncertain (needs review)
FP_THRESHOLD_LIKELY = 0.3  # Score >= this but < 0.5 = possibly FP but included


# ============================================================================
# Agentic AI Corroboration
# ============================================================================

def _is_agentic_finding(finding: dict) -> bool:
    """Check if a finding is from the Agentic AI scan."""
    finding_type = finding.get("type", "")
    details = finding.get("details", {}) or {}
    
    # Check type prefix or source field
    return (
        finding_type.startswith("agentic-") or 
        details.get("source") == "agentic_ai"
    )


def _normalize_vuln_type(finding_type: str) -> str:
    """Normalize vulnerability type for comparison."""
    # Strip agentic prefix
    if finding_type.startswith("agentic-"):
        finding_type = finding_type.replace("agentic-", "")
    
    # Normalize common variations
    finding_type = finding_type.lower().strip()
    finding_type = finding_type.replace("_", " ").replace("-", " ")
    
    # Map common SAST types to normalized names
    type_mappings = {
        "sql injection": "sql injection",
        "sqli": "sql injection",
        "sql": "sql injection",
        "cross site scripting": "xss",
        "cross-site scripting": "xss",
        "xss": "xss",
        "reflected xss": "xss",
        "stored xss": "xss",
        "dom xss": "xss",
        "command injection": "command injection",
        "os command injection": "command injection",
        "shell injection": "command injection",
        "path traversal": "path traversal",
        "directory traversal": "path traversal",
        "lfi": "path traversal",
        "rfi": "path traversal",
        "ssrf": "ssrf",
        "server side request forgery": "ssrf",
        "idor": "idor",
        "insecure direct object reference": "idor",
        "hardcoded secret": "secret",
        "hardcoded password": "secret",
        "hardcoded credential": "secret",
        "hardcoded api key": "secret",
        "secret": "secret",
        "authentication bypass": "auth",
        "broken authentication": "auth",
        "weak authentication": "auth",
        "xxe": "xxe",
        "xml external entity": "xxe",
        "deserialization": "deserialization",
        "insecure deserialization": "deserialization",
        "open redirect": "open redirect",
        "url redirect": "open redirect",
        "csrf": "csrf",
        "cross site request forgery": "csrf",
        "log injection": "log injection",
        "header injection": "header injection",
        "http response splitting": "header injection",
    }
    
    # Check for mapping
    for key, normalized in type_mappings.items():
        if key in finding_type:
            return normalized
    
    return finding_type


def _findings_match(scanner_finding: dict, agentic_finding: dict) -> bool:
    """
    Check if a scanner finding matches an agentic finding.
    
    Matching criteria:
    1. Same or similar vulnerability type
    2. Same or nearby file location
    3. Similar summary/description
    
    Returns True if findings likely refer to the same vulnerability.
    """
    # Normalize types
    scanner_type = _normalize_vuln_type(scanner_finding.get("type", ""))
    agentic_type = _normalize_vuln_type(agentic_finding.get("type", ""))
    
    # Type match
    type_match = (
        scanner_type == agentic_type or
        scanner_type in agentic_type or
        agentic_type in scanner_type
    )
    
    if not type_match:
        return False
    
    # File match (same file or in same directory)
    scanner_file = Path(scanner_finding.get("file_path", "")).resolve() if scanner_finding.get("file_path") else None
    agentic_file = Path(agentic_finding.get("file_path", "")).resolve() if agentic_finding.get("file_path") else None
    
    if scanner_file and agentic_file:
        # Exact file match
        if scanner_file == agentic_file:
            # Check line proximity (within 50 lines)
            scanner_line = scanner_finding.get("start_line", 0) or 0
            agentic_line = agentic_finding.get("start_line", 0) or 0
            if abs(scanner_line - agentic_line) <= 50:
                return True
        
        # Same directory, check if file names are similar
        if scanner_file.parent == agentic_file.parent:
            scanner_line = scanner_finding.get("start_line", 0) or 0
            agentic_line = agentic_finding.get("start_line", 0) or 0
            if abs(scanner_line - agentic_line) <= 20:
                return True
    
    # Summary similarity check (basic)
    scanner_summary = scanner_finding.get("summary", "").lower()
    agentic_summary = agentic_finding.get("summary", "").lower()
    
    # Check for key word overlap
    scanner_words = set(scanner_summary.split())
    agentic_words = set(agentic_summary.split())
    
    common_words = scanner_words & agentic_words
    # Filter out common stop words
    stop_words = {"the", "a", "an", "is", "are", "in", "to", "of", "and", "or", "for", "with"}
    meaningful_common = common_words - stop_words
    
    if len(meaningful_common) >= 3:
        return True
    
    return False


def _separate_findings(findings: List[dict]) -> Tuple[List[dict], List[dict]]:
    """
    Separate findings into scanner findings and agentic findings.
    
    Returns:
        Tuple of (scanner_findings, agentic_findings)
    """
    scanner_findings = []
    agentic_findings = []
    
    for f in findings:
        if _is_agentic_finding(f):
            agentic_findings.append(f)
        else:
            scanner_findings.append(f)
    
    return scanner_findings, agentic_findings


def _check_agentic_corroboration(
    scanner_finding: dict, 
    agentic_findings: List[dict]
) -> Tuple[bool, Optional[dict]]:
    """
    Check if a scanner finding is corroborated by any agentic finding.
    
    Returns:
        Tuple of (is_corroborated, matching_agentic_finding)
    """
    for agentic_finding in agentic_findings:
        if _findings_match(scanner_finding, agentic_finding):
            return True, agentic_finding
    return False, None


# ============================================================================
# False Positive Detection Patterns
# ============================================================================
FALSE_POSITIVE_PATTERNS = [
    (r'test[_/]|_test\.py|\.test\.[jt]sx?|spec\.[jt]sx?', 'Test file'),
    (r'mock|stub|fake|dummy', 'Mock/test code'),
    (r'example|sample|demo|tutorial', 'Example/demo code'),
    (r'\.min\.js|vendor[/\\]|node_modules', 'Vendored/minified code'),
    (r'# nosec|// nosec|NOSONAR|@SuppressWarnings', 'Explicitly suppressed'),
]

# Context patterns that might reduce severity
SEVERITY_REDUCTION_PATTERNS = [
    (r'@require[sd]?_?auth|@login_required|@authenticated', 'Requires authentication'),
    (r'@admin[_]?only|@require[sd]?_?admin|is_superuser', 'Admin-only access'),
    (r'internal[_]?only|private[_]?api|localhost|127\.0\.0\.1', 'Internal/private endpoint'),
    (r'if\s+.*\.is_authenticated|if\s+request\.user', 'Auth check present'),
]


def _quick_false_positive_check(finding: dict, code_snippet: str = "") -> Tuple[float, Optional[str]]:
    """
    Quick heuristic check for false positives without LLM.
    Returns (score, reason) where score is 0-1.
    """
    file_path = finding.get("file_path", "").lower()
    summary = finding.get("summary", "").lower()
    code = code_snippet.lower()
    
    for pattern, reason in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return 0.7, f"Likely false positive: {reason}"
        if re.search(pattern, code, re.IGNORECASE):
            return 0.5, f"Possible false positive: {reason} in code"
    
    # Check for placeholder values
    if any(x in code for x in ['xxx', 'your_', 'example_', 'changeme', 'placeholder']):
        if finding.get("type") == "secret":
            return 0.8, "Placeholder/example secret value"
    
    return 0.0, None


def _quick_severity_adjustment(finding: dict, code_snippet: str = "") -> Tuple[Optional[str], Optional[str]]:
    """
    Quick heuristic severity adjustment without LLM.
    Returns (new_severity, reason) or (None, None) if no change.
    """
    current_severity = finding.get("severity", "medium")
    code = code_snippet.lower()
    
    for pattern, reason in SEVERITY_REDUCTION_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            # Reduce severity by one level
            severity_order = ["critical", "high", "medium", "low"]
            try:
                idx = severity_order.index(current_severity)
                if idx < len(severity_order) - 1:
                    new_severity = severity_order[idx + 1]
                    return new_severity, f"Reduced: {reason}"
            except ValueError:
                pass
    
    return None, None


def _group_related_findings(findings: List[dict]) -> Dict[str, List[dict]]:
    """
    Group findings that might be related (same root cause).
    Groups by: same file, same rule type, similar code patterns.
    """
    groups: Dict[str, List[dict]] = {}
    
    for f in findings:
        # Group by rule_id/test_id + similar file path patterns
        rule_id = (
            f.get("details", {}).get("rule_id") or 
            f.get("details", {}).get("test_id") or
            f.get("type", "unknown")
        )
        
        # Extract function/class context from file path
        file_path = f.get("file_path", "")
        path_parts = Path(file_path).parts[-2:] if file_path else ("unknown",)
        group_key = f"{rule_id}:{'/'.join(path_parts)}"
        
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(f)
    
    return groups


def _identify_attack_chains_heuristic(findings: List[dict]) -> List[AttackChain]:
    """
    Identify potential attack chains using heuristics.
    Look for common patterns like IDOR -> data leak, SQLi -> auth bypass, etc.
    """
    chains = []
    
    # Index findings by type
    by_type: Dict[str, List[dict]] = {}
    for f in findings:
        finding_type = f.get("type", "")
        summary = f.get("summary", "").lower()
        details = f.get("details", {})
        
        # Categorize by vulnerability class
        vuln_class = "other"
        if any(x in summary for x in ["sql", "injection", "sqli"]):
            vuln_class = "sqli"
        elif any(x in summary for x in ["xss", "cross-site", "script"]):
            vuln_class = "xss"
        elif any(x in summary for x in ["idor", "insecure direct", "authorization"]):
            vuln_class = "idor"
        elif any(x in summary for x in ["ssrf", "server-side request"]):
            vuln_class = "ssrf"
        elif any(x in summary for x in ["auth", "password", "credential", "session"]):
            vuln_class = "auth"
        elif any(x in summary for x in ["path traversal", "directory", "lfi", "rfi"]):
            vuln_class = "path_traversal"
        elif any(x in summary for x in ["command", "exec", "shell", "rce"]):
            vuln_class = "command_injection"
        elif finding_type == "secret":
            vuln_class = "secret"
        elif finding_type == "dependency_vuln":
            vuln_class = "dependency"
        
        if vuln_class not in by_type:
            by_type[vuln_class] = []
        by_type[vuln_class].append(f)
    
    # Look for known chain patterns
    chain_patterns = [
        {
            "requires": ["sqli"],
            "title": "SQL Injection to Data Exfiltration",
            "description": "SQL injection can be exploited to extract sensitive data from the database, potentially including user credentials, PII, or business-critical information.",
            "impact": "Complete database compromise, data breach, credential theft",
            "likelihood": "high",
        },
        {
            "requires": ["sqli", "auth"],
            "title": "SQL Injection + Auth Bypass Chain",
            "description": "SQL injection combined with weak authentication can allow attackers to bypass login, escalate privileges, or impersonate other users.",
            "impact": "Full authentication bypass, account takeover, privilege escalation",
            "likelihood": "high",
        },
        {
            "requires": ["idor", "auth"],
            "title": "IDOR + Broken Auth to Account Takeover",
            "description": "Insecure direct object references combined with authentication weaknesses can enable attackers to access or modify other users' data.",
            "impact": "Unauthorized data access, account takeover, data manipulation",
            "likelihood": "medium",
        },
        {
            "requires": ["xss", "auth"],
            "title": "XSS to Session Hijacking",
            "description": "Cross-site scripting can be used to steal session tokens, leading to account compromise.",
            "impact": "Session hijacking, account takeover, credential theft",
            "likelihood": "medium",
        },
        {
            "requires": ["ssrf"],
            "title": "SSRF to Internal Service Access",
            "description": "Server-side request forgery can be exploited to access internal services, cloud metadata endpoints, or pivot to internal networks.",
            "impact": "Internal network access, cloud credential theft, lateral movement",
            "likelihood": "high",
        },
        {
            "requires": ["secret"],
            "title": "Exposed Secrets to System Compromise",
            "description": "Hardcoded secrets (API keys, passwords, tokens) can provide direct access to external services or internal systems.",
            "impact": "Direct system access, data breach, service abuse",
            "likelihood": "high",
        },
        {
            "requires": ["command_injection"],
            "title": "Command Injection to Remote Code Execution",
            "description": "Command injection vulnerabilities can be exploited to execute arbitrary commands on the server, leading to full system compromise.",
            "impact": "Remote code execution, full server compromise, lateral movement",
            "likelihood": "critical",
        },
        {
            "requires": ["path_traversal"],
            "title": "Path Traversal to Sensitive File Access",
            "description": "Path traversal can be exploited to read sensitive files like /etc/passwd, configuration files, or source code.",
            "impact": "Sensitive file disclosure, credential theft, source code leak",
            "likelihood": "medium",
        },
    ]
    
    for pattern in chain_patterns:
        required_types = pattern["requires"]
        matching_findings = []
        
        for req_type in required_types:
            if req_type in by_type and by_type[req_type]:
                matching_findings.extend(by_type[req_type][:3])  # Max 3 per type
        
        if len([r for r in required_types if r in by_type]) >= len(required_types):
            # All required types are present
            finding_ids = [f.get("id") for f in matching_findings if f.get("id")]
            if finding_ids:
                chains.append(AttackChain(
                    title=pattern["title"],
                    severity="critical" if pattern["likelihood"] == "critical" else "high",
                    finding_ids=finding_ids,
                    chain_description=pattern["description"],
                    impact=pattern["impact"],
                    likelihood=pattern["likelihood"],
                ))
    
    return chains


async def _call_llm_batch_analysis(
    findings_batch: List[dict],
    code_snippets: Dict[int, str],
    analysis_types: List[str] = None,
    agentic_findings: List[dict] = None,
    corroboration_map: Dict[int, dict] = None,
    external_intel: Any = None
) -> Dict[int, AIAnalysisResult]:
    """
    Call LLM once for a batch of findings.
    Returns analysis results keyed by finding ID.
    
    analysis_types can include: 'false_positive', 'severity', 'data_flow', 'remediation'
    
    agentic_findings: List of findings from the Agentic AI scan for context
    corroboration_map: Map of scanner finding IDs to matching agentic findings
    external_intel: ExternalIntelligence with CVE, dependency, and import context
    """
    if not genai_client or not settings.gemini_api_key:
        logger.info("Gemini API not configured, skipping LLM analysis")
        return {}
    
    if analysis_types is None:
        analysis_types = ['false_positive', 'severity', 'remediation']
    
    if agentic_findings is None:
        agentic_findings = []
    
    if corroboration_map is None:
        corroboration_map = {}
    
    if not findings_batch:
        return {}
    
    # Build prompt with all findings
    findings_text = []
    for i, f in enumerate(findings_batch[:15]):  # Max 15 findings per batch
        snippet = code_snippets.get(f.get("id"), "")[:500]  # Truncate snippets
        finding_id = f.get('id')
        
        # Check if this finding is corroborated
        corroboration_note = ""
        if finding_id in corroboration_map:
            matching = corroboration_map[finding_id]
            corroboration_note = f"\n⚠️ CORROBORATED: This finding was ALSO found by the Agentic AI deep scan with confidence {matching.get('details', {}).get('confidence', 0.8):.0%}. This strongly suggests it's a real vulnerability."
        elif agentic_findings:
            corroboration_note = "\n⚡ Note: Agentic AI scan ran but did NOT find this vulnerability - consider if it might be a false positive."
        
        findings_text.append(f"""
Finding #{finding_id}:
- Type: {f.get('type')}
- Severity: {f.get('severity')}
- File: {f.get('file_path')}
- Line: {f.get('start_line')}
- Summary: {f.get('summary')}{corroboration_note}
- Code snippet:
```
{snippet}
```
""")
    
    # Build agentic context section
    agentic_context = ""
    if agentic_findings:
        agentic_summary = []
        for af in agentic_findings[:5]:  # Max 5 agentic findings for context
            agentic_summary.append(f"  - {af.get('type', 'Unknown')}: {af.get('summary', '')[:100]} (File: {af.get('file_path', 'Unknown')})")
        
        agentic_context = f"""
AGENTIC AI SCAN CONTEXT:
The Agentic AI performed a deep code analysis and found {len(agentic_findings)} vulnerabilities.
Sample agentic findings:
{chr(10).join(agentic_summary)}

IMPORTANT: 
- Findings corroborated by the Agentic AI (marked with ⚠️) are LIKELY REAL vulnerabilities
- Findings NOT found by Agentic AI should be scrutinized more carefully for false positives
- The Agentic AI traces data flows and validates exploitability, so its findings are high-confidence
"""
    
    # Build external intelligence context section
    external_context = ""
    if external_intel:
        intel_parts = []
        
        # CVE/Vulnerability context
        if hasattr(external_intel, 'cve_findings') and external_intel.cve_findings:
            cve_summary = []
            for cve in external_intel.cve_findings[:10]:
                cve_summary.append(f"  - {cve.get('external_id')}: {cve.get('package')} ({cve.get('severity')}, CVSS: {cve.get('cvss_score')})")
            intel_parts.append(f"KNOWN CVEs ({len(external_intel.cve_findings)} total):\n" + chr(10).join(cve_summary))
        
        # Security findings summary
        if hasattr(external_intel, 'security_findings_summary') and external_intel.security_findings_summary:
            intel_parts.append(f"SECURITY SUMMARY: {external_intel.security_findings_summary}")
        
        # Files importing vulnerable packages
        if hasattr(external_intel, 'vulnerable_import_files') and external_intel.vulnerable_import_files:
            import_summary = []
            for imp in external_intel.vulnerable_import_files[:8]:
                import_summary.append(f"  - {imp.get('file')}: imports {imp.get('package')} (CVEs: {', '.join(imp.get('cves', []))})")
            intel_parts.append(f"FILES WITH VULNERABLE IMPORTS:\n" + chr(10).join(import_summary))
        
        # Dependencies context
        if hasattr(external_intel, 'dependencies') and external_intel.dependencies:
            dep_count = len(external_intel.dependencies)
            intel_parts.append(f"DEPENDENCIES: {dep_count} packages analyzed")
        
        if intel_parts:
            external_context = f"""
EXTERNAL INTELLIGENCE CONTEXT:
{chr(10).join(intel_parts)}

Use this context to:
- Prioritize findings in files that import vulnerable packages
- Consider if code findings relate to known CVEs
- Be more conservative (lower FP score) for findings related to vulnerable dependencies
"""
    
    analysis_instructions = []
    if 'false_positive' in analysis_types:
        analysis_instructions.append("""
- false_positive_score: 0.0-1.0 (1.0 = definitely false positive)
  * If finding is CORROBORATED by Agentic AI, score should be LOW (0.0-0.3)
  * If finding is NOT corroborated and Agentic AI ran, consider score 0.3-0.7
- false_positive_reason: Brief explanation if score > 0.3""")
    
    if 'severity' in analysis_types:
        analysis_instructions.append("""
- adjusted_severity: null or "critical"/"high"/"medium"/"low" if should change
- severity_reason: Brief explanation if adjusted""")
    
    if 'data_flow' in analysis_types:
        analysis_instructions.append("""
- data_flow: Brief description of how tainted data flows (if applicable)""")
    
    if 'remediation' in analysis_types:
        analysis_instructions.append("""
- remediation_code: Short code fix snippet (max 5 lines) if applicable""")
    
    prompt = f"""Analyze these security findings and provide structured analysis.
Be concise. Focus on actionable insights.
{agentic_context}
{external_context}
FINDINGS:
{''.join(findings_text)}

For each finding, provide JSON with:
{chr(10).join(analysis_instructions)}

Return a JSON object with finding IDs as keys:
{{
  "123": {{
    "false_positive_score": 0.2,
    "false_positive_reason": null,
    "adjusted_severity": null,
    "severity_reason": null,
    "data_flow": "User input flows from request.body to database query without sanitization",
    "remediation_code": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
  }},
  ...
}}

Only include fields that are relevant. Be conservative with false_positive_score for CORROBORATED findings."""

    try:
        if not genai_client:
            logger.warning("Gemini client not initialized, skipping LLM analysis")
            return {}
        
        from google.genai import types
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="medium"),
                max_output_tokens=4000,
            )
        )
        
        # Parse JSON response
        response_text = response.text if response else ""
        # Extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            results_json = json.loads(json_match.group())
            
            # Convert to AIAnalysisResult objects
            results = {}
            for finding_id_str, analysis in results_json.items():
                try:
                    finding_id = int(finding_id_str)
                    results[finding_id] = AIAnalysisResult(
                        finding_id=finding_id,
                        false_positive_score=float(analysis.get("false_positive_score", 0)),
                        false_positive_reason=analysis.get("false_positive_reason"),
                        adjusted_severity=analysis.get("adjusted_severity"),
                        severity_reason=analysis.get("severity_reason"),
                        data_flow=analysis.get("data_flow"),
                        remediation_code=analysis.get("remediation_code"),
                    )
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error parsing analysis for finding {finding_id_str}: {e}")
            
            return results
        else:
            logger.warning("Could not extract JSON from LLM response")
            return {}
            
    except Exception as e:
        logger.error(f"LLM batch analysis failed: {e}")
        return {}


async def _call_llm_attack_chains(
    findings: List[dict],
    heuristic_chains: List[AttackChain]
) -> List[AttackChain]:
    """
    Use LLM to refine attack chains and discover non-obvious ones.
    Single LLM call for all chain analysis.
    """
    if not genai_client or not settings.gemini_api_key:
        return heuristic_chains
    
    if not findings:
        return heuristic_chains
    
    # Summarize findings for the prompt
    findings_summary = []
    for f in findings[:30]:  # Max 30 findings
        findings_summary.append(
            f"- [{f.get('id')}] {f.get('severity').upper()}: {f.get('summary')[:100]} ({f.get('file_path')})"
        )
    
    existing_chains = []
    for chain in heuristic_chains[:5]:
        existing_chains.append(f"- {chain.title}: {chain.chain_description[:100]}...")
    
    prompt = f"""Analyze these security findings and identify attack chains (multiple vulnerabilities that can be combined).

FINDINGS:
{chr(10).join(findings_summary)}

ALREADY IDENTIFIED CHAINS:
{chr(10).join(existing_chains) if existing_chains else "None yet"}

Identify 1-3 additional attack chains NOT already listed above. Focus on:
1. Non-obvious combinations
2. Chains specific to this codebase
3. Realistic attack scenarios

Return JSON array:
[
  {{
    "title": "Chain Name",
    "severity": "critical|high|medium",
    "finding_ids": [123, 456],
    "chain_description": "Brief description of how findings combine",
    "impact": "What attacker achieves",
    "likelihood": "high|medium|low"
  }}
]

Return empty array [] if no additional chains found. Be conservative."""

    try:
        if not genai_client:
            logger.warning("Gemini client not initialized, skipping attack chain analysis")
            return heuristic_chains
        
        from google.genai import types
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="medium"),
                max_output_tokens=2000,
            )
        )
        
        # Parse JSON response
        response_text = response.text if response else ""
        json_match = re.search(r'\[[\s\S]*\]', response_text)
        if json_match:
            chains_json = json.loads(json_match.group())
            
            new_chains = []
            for chain_data in chains_json[:3]:  # Max 3 new chains
                try:
                    new_chains.append(AttackChain(
                        title=chain_data.get("title", "Unknown Chain"),
                        severity=chain_data.get("severity", "high"),
                        finding_ids=chain_data.get("finding_ids", []),
                        chain_description=chain_data.get("chain_description", ""),
                        impact=chain_data.get("impact", ""),
                        likelihood=chain_data.get("likelihood", "medium"),
                    ))
                except Exception as e:
                    logger.warning(f"Error parsing chain: {e}")
            
            return heuristic_chains + new_chains
        
        return heuristic_chains
        
    except Exception as e:
        logger.error(f"LLM attack chain analysis failed: {e}")
        return heuristic_chains


async def analyze_findings(
    findings: List[dict],
    code_snippets: Dict[int, str] = None,
    enable_llm: bool = True,
    max_llm_findings: int = 20,
    external_intel: Any = None,
) -> AIAnalysisSummary:
    """
    Main entry point for AI-enhanced analysis.
    
    Performs:
    1. Separate scanner findings from agentic findings
    2. Check agentic corroboration for scanner findings
    3. Quick heuristic checks on all findings (no LLM)
    4. LLM analysis on top priority findings (batched, 1-2 calls max)
    5. Attack chain identification (1 LLM call)
    6. Final judgment: Filter scanner findings not corroborated by agentic AI
    
    Agentic Corroboration Logic:
    - Scanner findings WITH matching agentic findings are likely genuine (reduce FP score)
    - Scanner findings WITHOUT matching agentic findings may be false positives (increase FP score)
    - Agentic findings are always trusted (they come from deep AI analysis)
    
    Args:
        findings: List of finding dicts with id, type, severity, file_path, summary, details
        code_snippets: Optional dict mapping finding_id -> code snippet
        enable_llm: Whether to use LLM (set False for fast mode)
        max_llm_findings: Max findings to send to LLM
        external_intel: ExternalIntelligence with CVE, dependency, and import context
        
    Returns:
        AIAnalysisSummary with all analysis results
    """
    if code_snippets is None:
        code_snippets = {}
    
    analysis_results: Dict[int, AIAnalysisResult] = {}
    false_positives_count = 0
    severity_adjustments_count = 0
    agentic_corroborated_count = 0
    filtered_out_count = 0
    uncertain_count = 0  # Track findings in the uncertain zone (0.5-0.6 FP score)
    
    total_findings = len(findings)
    logger.info(f"Starting AI analysis on {total_findings} findings")
    
    # Step 0: Separate agentic findings from scanner findings
    scanner_findings, agentic_findings = _separate_findings(findings)
    logger.info(f"Found {len(agentic_findings)} agentic findings and {len(scanner_findings)} scanner findings")
    
    # Build a map of corroborated scanner findings
    corroboration_map: Dict[int, dict] = {}  # scanner_finding_id -> matching_agentic_finding
    
    if agentic_findings:
        for scanner_finding in scanner_findings:
            finding_id = scanner_finding.get("id")
            if not finding_id:
                continue
            
            is_corroborated, matching_agentic = _check_agentic_corroboration(
                scanner_finding, agentic_findings
            )
            if is_corroborated:
                corroboration_map[finding_id] = matching_agentic
                agentic_corroborated_count += 1
        
        logger.info(f"Agentic corroboration: {agentic_corroborated_count}/{len(scanner_findings)} scanner findings corroborated by agentic AI")
    
    # Step 1: For large finding sets, pre-filter and deduplicate
    if total_findings > MAX_FINDINGS_FOR_FULL_ANALYSIS:
        logger.info(f"Large finding set ({total_findings}), applying aggressive prioritization")
        findings = _prioritize_findings_for_analysis(findings, MAX_FINDINGS_FOR_FULL_ANALYSIS)
        logger.info(f"Reduced to {len(findings)} priority findings for analysis")
    
    # Step 2: Quick heuristic analysis on ALL findings
    pattern_based_results = 0
    for f in findings:
        finding_id = f.get("id")
        if not finding_id:
            continue
        
        snippet = code_snippets.get(finding_id, "")
        is_agentic = _is_agentic_finding(f)
        is_corroborated = finding_id in corroboration_map
        
        # Quick false positive check
        fp_score, fp_reason = _quick_false_positive_check(f, snippet)
        
        # Quick severity adjustment
        new_severity, sev_reason = _quick_severity_adjustment(f, snippet)
        
        # Pattern-based analysis for common vulnerability types
        pattern_analysis = _analyze_by_pattern(f, snippet)
        
        # Apply agentic corroboration adjustments for scanner findings
        if not is_agentic:
            if is_corroborated:
                # Corroborated by agentic AI - reduce false positive score
                matching_agentic = corroboration_map[finding_id]
                agentic_confidence = matching_agentic.get("details", {}).get("confidence", 0.8)
                
                # Reduce FP score based on agentic confidence
                fp_reduction = min(0.4, agentic_confidence * 0.5)
                fp_score = max(0.0, fp_score - fp_reduction)
                
                # Update reason to note corroboration
                corroboration_note = f"Corroborated by Agentic AI scan (confidence: {agentic_confidence:.1%})"
                if fp_reason:
                    fp_reason = f"{fp_reason}. However: {corroboration_note}"
                else:
                    fp_reason = None  # Clear FP reason since it's corroborated
            else:
                # NOT corroborated - if agentic scan ran but didn't find this, it's more likely FP
                if agentic_findings:
                    # Increase FP score for uncorroborated findings
                    # The more agentic findings we have, the more confident we are in the corroboration
                    agentic_coverage_factor = min(0.3, len(agentic_findings) * 0.03)
                    fp_score = min(1.0, fp_score + 0.15 + agentic_coverage_factor)
                    
                    if not fp_reason:
                        fp_reason = "Not corroborated by Agentic AI scan - may be false positive"
                    else:
                        fp_reason = f"{fp_reason}. Also not corroborated by Agentic AI scan."
        
        if fp_score > 0.3 or new_severity or pattern_analysis or is_corroborated:
            result = AIAnalysisResult(
                finding_id=finding_id,
                false_positive_score=fp_score,
                false_positive_reason=fp_reason or (pattern_analysis.get("fp_reason") if pattern_analysis else None),
                adjusted_severity=new_severity or (pattern_analysis.get("adjusted_severity") if pattern_analysis else None),
                severity_reason=sev_reason or (pattern_analysis.get("severity_reason") if pattern_analysis else None),
                data_flow=pattern_analysis.get("data_flow") if pattern_analysis else None,
                remediation_code=pattern_analysis.get("remediation") if pattern_analysis else None,
            )
            analysis_results[finding_id] = result
            
            # Categorize by FP score thresholds
            if fp_score >= FP_THRESHOLD_FILTERED and not is_agentic and not is_corroborated:
                filtered_out_count += 1
            elif fp_score >= FP_THRESHOLD_UNCERTAIN:
                uncertain_count += 1
                false_positives_count += 1
            elif fp_score >= FP_THRESHOLD_LIKELY:
                false_positives_count += 1
            
            if new_severity:
                severity_adjustments_count += 1
            if pattern_analysis:
                pattern_based_results += 1
    
    logger.info(f"Heuristic analysis complete: {false_positives_count} FPs ({uncertain_count} uncertain, {filtered_out_count} filtered), {severity_adjustments_count} severity changes, {pattern_based_results} pattern matches")
    
    # Step 3: Attack chain identification (heuristic)
    attack_chains = _identify_attack_chains_heuristic(findings)
    
    # Step 4: LLM analysis (if enabled and we have API key)
    if enable_llm and genai_client and settings.gemini_api_key:
        # Prioritize findings for LLM analysis
        # Focus on high/critical that haven't been fully analyzed
        priority_findings = _select_findings_for_llm(
            findings, 
            analysis_results,
            code_snippets,
            max_llm_findings
        )
        
        if priority_findings:
            logger.info(f"Running LLM analysis on {len(priority_findings)} priority findings")
            
            # Single batched LLM call for finding analysis with agentic context
            llm_results = await _call_llm_batch_analysis(
                priority_findings,
                code_snippets,
                analysis_types=['false_positive', 'severity', 'data_flow', 'remediation'],
                agentic_findings=agentic_findings,
                corroboration_map=corroboration_map,
                external_intel=external_intel
            )
            
            for finding_id, result in llm_results.items():
                # Merge with existing heuristic results
                if finding_id in analysis_results:
                    existing = analysis_results[finding_id]
                    # LLM results take precedence but we keep higher FP scores
                    result.false_positive_score = max(result.false_positive_score, existing.false_positive_score)
                    if not result.false_positive_reason and existing.false_positive_reason:
                        result.false_positive_reason = existing.false_positive_reason
                    if not result.data_flow and existing.data_flow:
                        result.data_flow = existing.data_flow
                    if not result.remediation_code and existing.remediation_code:
                        result.remediation_code = existing.remediation_code
                
                # Apply corroboration adjustment after LLM analysis
                if finding_id in corroboration_map:
                    # LLM might have increased FP score, but corroboration reduces it
                    matching_agentic = corroboration_map[finding_id]
                    agentic_confidence = matching_agentic.get("details", {}).get("confidence", 0.8)
                    result.false_positive_score = max(0.0, result.false_positive_score - (agentic_confidence * 0.3))
                
                analysis_results[finding_id] = result
                
                if result.false_positive_score >= 0.5:
                    false_positives_count += 1
                if result.adjusted_severity:
                    severity_adjustments_count += 1
        
        # Single LLM call for attack chain refinement
        if findings:
            logger.info("Running LLM attack chain analysis")
            attack_chains = await _call_llm_attack_chains(findings, attack_chains)
    
    logger.info(f"AI analysis complete: {len(analysis_results)} findings analyzed, {len(attack_chains)} attack chains identified")
    logger.info(f"Agentic corroboration: {agentic_corroborated_count} corroborated, {filtered_out_count} filtered, {uncertain_count} uncertain")
    
    return AIAnalysisSummary(
        findings_analyzed=len(findings),
        false_positives_detected=false_positives_count,
        severity_adjustments=severity_adjustments_count,
        attack_chains=attack_chains,
        analysis_results=analysis_results,
        agentic_corroborated=agentic_corroborated_count,
        filtered_out=filtered_out_count,
        uncertain_findings=uncertain_count,
    )


def _prioritize_findings_for_analysis(findings: List[dict], max_findings: int) -> List[dict]:
    """
    Prioritize findings when there are too many for full analysis.
    
    Strategy:
    1. Critical/high severity always included
    2. Deduplicate similar findings (same rule, same file pattern)
    3. Ensure diversity across finding types
    4. Prefer findings with code context
    """
    if len(findings) <= max_findings:
        return findings
    
    # Group by priority
    critical_high = []
    medium = []
    low = []
    
    for f in findings:
        severity = f.get("severity", "medium").lower()
        if severity in ("critical", "high"):
            critical_high.append(f)
        elif severity == "medium":
            medium.append(f)
        else:
            low.append(f)
    
    # Deduplicate within each group
    critical_high = _deduplicate_findings(critical_high)
    medium = _deduplicate_findings(medium)
    low = _deduplicate_findings(low)
    
    # Build result prioritizing critical/high
    result = []
    
    # Always include all critical/high (up to limit)
    result.extend(critical_high[:max_findings])
    remaining = max_findings - len(result)
    
    # Fill with medium
    if remaining > 0:
        result.extend(medium[:remaining])
        remaining = max_findings - len(result)
    
    # Fill with low
    if remaining > 0:
        result.extend(low[:remaining])
    
    return result[:max_findings]


def _deduplicate_findings(findings: List[dict]) -> List[dict]:
    """Remove duplicate/similar findings to improve analysis diversity."""
    if len(findings) <= 5:
        return findings
    
    seen_signatures: Set[str] = set()
    type_counts: Dict[str, int] = {}
    deduplicated = []
    
    for f in findings:
        # Create a signature for deduplication
        finding_type = f.get("type", "")
        rule_id = f.get("details", {}).get("rule_id", "") or f.get("details", {}).get("test_id", "")
        summary_words = set(f.get("summary", "").lower().split()[:5])
        
        signature = f"{finding_type}:{rule_id}:{hash(frozenset(summary_words)) % 1000}"
        
        # Skip if we've seen too similar
        if signature in seen_signatures:
            continue
        
        # Limit per type
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        if type_counts[finding_type] > MAX_FINDINGS_PER_TYPE:
            continue
        
        seen_signatures.add(signature)
        deduplicated.append(f)
    
    return deduplicated


def _select_findings_for_llm(
    findings: List[dict],
    existing_results: Dict[int, AIAnalysisResult],
    code_snippets: Dict[int, str],
    max_findings: int
) -> List[dict]:
    """
    Select the best findings to send to LLM for deep analysis.
    
    Prioritizes:
    1. Critical/high severity without existing analysis
    2. Findings with code context (can analyze better)
    3. Diverse finding types (not all same rule)
    """
    # Filter to findings that would benefit from LLM
    candidates = []
    for f in findings:
        finding_id = f.get("id")
        if not finding_id:
            continue
        
        # Skip if already has good analysis
        if finding_id in existing_results:
            existing = existing_results[finding_id]
            if existing.false_positive_score > 0.7 or existing.remediation_code:
                continue
        
        # Prefer findings with code snippets
        has_code = finding_id in code_snippets and len(code_snippets[finding_id]) > 50
        severity = f.get("severity", "medium").lower()
        
        # Score for prioritization
        score = 0
        if severity == "critical":
            score += 10
        elif severity == "high":
            score += 7
        elif severity == "medium":
            score += 4
        else:
            score += 1
        
        if has_code:
            score += 3
        
        candidates.append((score, f))
    
    # Sort by score and take top
    candidates.sort(key=lambda x: x[0], reverse=True)
    
    # Ensure diversity - limit per type
    type_counts: Dict[str, int] = {}
    selected = []
    
    for score, f in candidates:
        if len(selected) >= max_findings:
            break
        
        finding_type = f.get("type", "unknown")
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        
        if type_counts[finding_type] <= 5:  # Max 5 per type in LLM batch
            selected.append(f)
    
    return selected


def _analyze_by_pattern(finding: dict, code_snippet: str) -> Optional[Dict[str, Any]]:
    """
    Pattern-based analysis for common vulnerability types.
    
    Provides instant analysis without LLM for well-known patterns.
    Returns dict with analysis fields or None if no pattern matched.
    """
    finding_type = finding.get("type", "")
    summary = finding.get("summary", "").lower()
    code = code_snippet.lower()
    
    # SQL Injection patterns
    if "sql" in summary or "injection" in summary:
        if re.search(r'parameterized|prepared|placeholder|\?|%s', code):
            return {
                "fp_reason": "Uses parameterized queries",
                "adjusted_severity": None,
                "data_flow": "Query appears to use parameterized statements",
                "remediation": None,
            }
        if re.search(r'orm|sqlalchemy|django\.db|sequelize|prisma', code):
            return {
                "fp_reason": "Uses ORM which typically prevents SQL injection",
                "adjusted_severity": "medium" if finding.get("severity") == "high" else None,
                "data_flow": "Uses ORM abstraction layer",
                "remediation": None,
            }
    
    # XSS patterns
    if "xss" in summary or "cross-site" in summary:
        if re.search(r'escape|sanitize|encode|dangerouslysetinnerhtml\s*=\s*\{[^}]*sanitize', code):
            return {
                "fp_reason": "Output appears to be sanitized/escaped",
                "adjusted_severity": None,
                "data_flow": "Data is processed through sanitization before output",
                "remediation": None,
            }
    
    # Hardcoded secrets patterns
    if finding_type == "secret":
        if re.search(r'example|test|dummy|fake|placeholder|xxx|changeme|your_|sample', code):
            return {
                "fp_reason": "Appears to be a placeholder/example value, not a real secret",
                "adjusted_severity": "low",
                "data_flow": None,
                "remediation": "Verify this is not a real credential before deployment",
            }
        if re.search(r'env\[|environ|getenv|process\.env|config\.', code):
            return {
                "fp_reason": "Secret is loaded from environment, not hardcoded",
                "adjusted_severity": "low",
                "data_flow": "Value loaded from environment variable at runtime",
                "remediation": None,
            }
    
    # Command injection patterns
    if "command" in summary or "exec" in summary or "shell" in summary:
        if re.search(r'shlex\.quote|escapeshellarg|shell=false', code):
            return {
                "fp_reason": "Uses shell escaping/quoting",
                "adjusted_severity": "medium" if finding.get("severity") == "high" else None,
                "data_flow": "Input is escaped before shell execution",
                "remediation": None,
            }
    
    return None


def analysis_result_to_dict(result: AIAnalysisResult) -> dict:
    """Convert AIAnalysisResult to dict for JSON storage."""
    return {
        "finding_id": result.finding_id,
        "false_positive_score": result.false_positive_score,
        "false_positive_reason": result.false_positive_reason,
        "adjusted_severity": result.adjusted_severity,
        "severity_reason": result.severity_reason,
        "data_flow": result.data_flow,
        "remediation_code": result.remediation_code,
        "related_findings": result.related_findings,
    }


def attack_chain_to_dict(chain: AttackChain) -> dict:
    """Convert AttackChain to dict for JSON storage."""
    return {
        "title": chain.title,
        "severity": chain.severity,
        "finding_ids": chain.finding_ids,
        "chain_description": chain.chain_description,
        "impact": chain.impact,
        "likelihood": chain.likelihood,
    }


# =============================================================================
# AI Analysis Service Class for ZAP Integration
# =============================================================================

class AIAnalysisService:
    """
    AI Analysis Service for OWASP ZAP findings.
    
    Provides intelligent analysis including:
    - Exploit chain detection
    - Remediation prioritization  
    - Business impact assessment
    - OWASP mapping
    """
    
    async def analyze_zap_findings(
        self,
        findings: List[Dict[str, Any]],
        target_url: str,
        include_exploit_chains: bool = True,
        include_remediation: bool = True,
        include_business_impact: bool = True,
        additional_context: str = None
    ) -> Dict[str, Any]:
        """
        Analyze ZAP findings using AI.
        
        Args:
            findings: List of normalized ZAP findings
            target_url: The scanned target URL
            include_exploit_chains: Whether to analyze exploit chains
            include_remediation: Whether to generate remediation plan
            include_business_impact: Whether to assess business impact
            additional_context: Additional context to provide to AI
            
        Returns:
            Dict with summary, exploit_chains, remediation_plan, business_impact, owasp_mapping
        """
        if not findings:
            return {
                "summary": "No findings to analyze.",
                "exploit_chains": [],
                "remediation_plan": [],
                "business_impact": "No security issues detected.",
                "owasp_mapping": {}
            }
        
        result = {
            "summary": "",
            "exploit_chains": [],
            "remediation_plan": [],
            "business_impact": "",
            "owasp_mapping": {}
        }
        
        # Map findings to OWASP categories
        owasp_map = self._map_to_owasp(findings)
        result["owasp_mapping"] = owasp_map
        
        # Try LLM-based analysis if available
        if genai_client:
            try:
                llm_result = await self._llm_analyze_zap(
                    findings, target_url,
                    include_exploit_chains, include_remediation, include_business_impact,
                    additional_context
                )
                if llm_result:
                    result.update(llm_result)
                    return result
            except Exception as e:
                logger.warning(f"LLM ZAP analysis failed: {e}")
        
        # Fallback to heuristic analysis
        result["summary"] = self._generate_heuristic_summary(findings, target_url)
        
        if include_exploit_chains:
            result["exploit_chains"] = self._detect_exploit_chains(findings)
        
        if include_remediation:
            result["remediation_plan"] = self._generate_remediation_plan(findings)
        
        if include_business_impact:
            result["business_impact"] = self._assess_business_impact(findings)
        
        return result
    
    def _map_to_owasp(self, findings: List[Dict]) -> Dict[str, List[str]]:
        """Map findings to OWASP Top 10 categories."""
        owasp_map = {
            "A01:2021-Broken Access Control": [],
            "A02:2021-Cryptographic Failures": [],
            "A03:2021-Injection": [],
            "A04:2021-Insecure Design": [],
            "A05:2021-Security Misconfiguration": [],
            "A06:2021-Vulnerable Components": [],
            "A07:2021-Auth Failures": [],
            "A08:2021-Integrity Failures": [],
            "A09:2021-Logging Failures": [],
            "A10:2021-SSRF": [],
        }
        
        for f in findings:
            title = f.get("title", "").lower()
            technique = f.get("technique", "").lower()
            cwe = f.get("cwe_id", "")
            
            # Map based on keywords and CWE
            if any(x in title or x in technique for x in ["sql", "ldap", "xpath", "nosql", "command", "injection"]):
                owasp_map["A03:2021-Injection"].append(f.get("title", "Unknown"))
            elif any(x in title or x in technique for x in ["xss", "cross-site", "script"]):
                owasp_map["A03:2021-Injection"].append(f.get("title", "Unknown"))
            elif any(x in title or x in technique for x in ["auth", "session", "cookie", "password"]):
                owasp_map["A07:2021-Auth Failures"].append(f.get("title", "Unknown"))
            elif any(x in title or x in technique for x in ["access", "privilege", "idor", "bola"]):
                owasp_map["A01:2021-Broken Access Control"].append(f.get("title", "Unknown"))
            elif any(x in title or x in technique for x in ["ssl", "tls", "crypto", "certificate", "encryption"]):
                owasp_map["A02:2021-Cryptographic Failures"].append(f.get("title", "Unknown"))
            elif any(x in title or x in technique for x in ["config", "header", "cors", "csp", "misconfigur"]):
                owasp_map["A05:2021-Security Misconfiguration"].append(f.get("title", "Unknown"))
            elif any(x in title or x in technique for x in ["ssrf", "server-side request"]):
                owasp_map["A10:2021-SSRF"].append(f.get("title", "Unknown"))
            elif any(x in title or x in technique for x in ["outdated", "vulnerable", "component", "library"]):
                owasp_map["A06:2021-Vulnerable Components"].append(f.get("title", "Unknown"))
        
        # Remove empty categories
        return {k: v for k, v in owasp_map.items() if v}
    
    def _detect_exploit_chains(self, findings: List[Dict]) -> List[Dict]:
        """Detect potential exploit chains in findings."""
        chains = []
        
        # Look for common chain patterns
        sqli_findings = [f for f in findings if "sql" in f.get("technique", "").lower()]
        xss_findings = [f for f in findings if "xss" in f.get("technique", "").lower() or "cross-site" in f.get("technique", "").lower()]
        auth_findings = [f for f in findings if "auth" in f.get("technique", "").lower() or "session" in f.get("technique", "").lower()]
        
        # SQLi + Auth = Account Takeover chain
        if sqli_findings and auth_findings:
            chains.append({
                "title": "Potential Account Takeover via SQL Injection",
                "description": "SQL injection combined with authentication issues could allow attackers to bypass authentication or escalate privileges.",
                "severity": "critical",
                "steps": [
                    "Exploit SQL injection to extract credentials",
                    "Use extracted credentials or session tokens",
                    "Gain unauthorized access to accounts"
                ],
                "affected_findings": [f.get("title") for f in sqli_findings[:2] + auth_findings[:2]]
            })
        
        # XSS + Session = Session Hijacking
        if xss_findings and auth_findings:
            chains.append({
                "title": "Session Hijacking via XSS",
                "description": "XSS vulnerabilities can be used to steal session cookies and hijack user sessions.",
                "severity": "high",
                "steps": [
                    "Inject malicious script via XSS",
                    "Steal session cookies or tokens",
                    "Impersonate authenticated users"
                ],
                "affected_findings": [f.get("title") for f in xss_findings[:2] + auth_findings[:2]]
            })
        
        return chains
    
    def _generate_remediation_plan(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation plan."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 4))
        
        plan = []
        seen_types = set()
        
        for f in sorted_findings:
            tech = f.get("technique", "Unknown")
            if tech in seen_types:
                continue
            seen_types.add(tech)
            
            plan.append({
                "priority": len(plan) + 1,
                "vulnerability": tech,
                "severity": f.get("severity", "info"),
                "recommendation": f.get("solution", "Review and remediate this vulnerability."),
                "affected_count": sum(1 for x in findings if x.get("technique") == tech),
                "effort": self._estimate_effort(f.get("severity", "info")),
            })
            
            if len(plan) >= 10:
                break
        
        return plan
    
    def _estimate_effort(self, severity: str) -> str:
        """Estimate remediation effort based on severity."""
        return {
            "critical": "high",
            "high": "high", 
            "medium": "medium",
            "low": "low",
            "info": "low"
        }.get(severity, "medium")
    
    def _assess_business_impact(self, findings: List[Dict]) -> str:
        """Assess business impact of findings."""
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        
        if critical_count > 0:
            return f"CRITICAL IMPACT: {critical_count} critical vulnerabilities pose immediate risk of data breach, system compromise, or regulatory violations. Immediate action required."
        elif high_count > 0:
            return f"HIGH IMPACT: {high_count} high-severity vulnerabilities could lead to unauthorized access, data exposure, or service disruption if exploited."
        else:
            return "MODERATE IMPACT: Security issues found should be addressed to maintain security posture, but no immediate critical risks detected."
    
    def _generate_heuristic_summary(self, findings: List[Dict], target_url: str) -> str:
        """Generate summary without LLM."""
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        parts = []
        for sev in ["critical", "high", "medium", "low"]:
            if severity_counts.get(sev, 0) > 0:
                parts.append(f"{severity_counts[sev]} {sev}")
        
        severity_str = ", ".join(parts) if parts else "informational"
        
        return f"DAST scan of {target_url} identified {len(findings)} security findings ({severity_str}). Review critical and high severity findings immediately."
    
    def _smart_sample_findings(self, findings: List[Dict], max_detailed: int = 100, max_per_type: int = 5) -> Tuple[List[Dict], Dict[str, Any]]:
        """
        Smart sample findings for LLM analysis.
        
        Strategy:
        1. Include ALL critical and high severity findings (up to max_detailed)
        2. Sample representative findings from each vulnerability type
        3. Create aggregated statistics for the rest
        
        Returns:
            Tuple of (sampled_findings, aggregate_stats)
        """
        # Group all findings by type and severity
        by_type: Dict[str, List[Dict]] = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for f in findings:
            ftype = f.get("title", f.get("technique", "Unknown"))
            sev = f.get("severity", "info")
            
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(f)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        sampled = []
        seen_types = set()
        
        # Priority 1: All critical findings
        for ftype, type_findings in by_type.items():
            critical = [f for f in type_findings if f.get("severity") == "critical"]
            for f in critical[:max_per_type]:
                if len(sampled) < max_detailed:
                    sampled.append(f)
                    seen_types.add(ftype)
        
        # Priority 2: All high severity findings
        for ftype, type_findings in by_type.items():
            high = [f for f in type_findings if f.get("severity") == "high"]
            for f in high[:max_per_type]:
                if len(sampled) < max_detailed:
                    sampled.append(f)
                    seen_types.add(ftype)
        
        # Priority 3: Sample from medium severity (ensure type diversity)
        for ftype, type_findings in by_type.items():
            if ftype in seen_types:
                continue
            medium = [f for f in type_findings if f.get("severity") == "medium"]
            for f in medium[:2]:  # Max 2 per type for medium
                if len(sampled) < max_detailed:
                    sampled.append(f)
                    seen_types.add(ftype)
        
        # Priority 4: Sample from low (only if space and new types)
        for ftype, type_findings in by_type.items():
            if ftype in seen_types:
                continue
            low = [f for f in type_findings if f.get("severity") == "low"]
            for f in low[:1]:  # Max 1 per type for low
                if len(sampled) < max_detailed:
                    sampled.append(f)
                    seen_types.add(ftype)
        
        # Build aggregate statistics
        type_stats = []
        for ftype, type_findings in sorted(by_type.items(), key=lambda x: -len(x[1])):
            type_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            unique_endpoints = set()
            unique_params = set()
            
            for f in type_findings:
                type_severity[f.get("severity", "info")] += 1
                if f.get("endpoint"):
                    unique_endpoints.add(f.get("endpoint"))
                if f.get("parameter"):
                    unique_params.add(f.get("parameter"))
            
            type_stats.append({
                "type": ftype,
                "total_count": len(type_findings),
                "severity_breakdown": {k: v for k, v in type_severity.items() if v > 0},
                "unique_endpoints": len(unique_endpoints),
                "unique_parameters": len(unique_params),
                "sample_endpoints": list(unique_endpoints)[:3],
            })
        
        aggregate_stats = {
            "total_findings": len(findings),
            "total_types": len(by_type),
            "severity_totals": severity_counts,
            "findings_by_type": type_stats[:30],  # Top 30 types by count
            "sampled_count": len(sampled),
        }
        
        return sampled, aggregate_stats
    
    async def _llm_analyze_zap(
        self,
        findings: List[Dict],
        target_url: str,
        include_chains: bool,
        include_remediation: bool,
        include_impact: bool,
        additional_context: str = None
    ) -> Optional[Dict[str, Any]]:
        """Use LLM for enhanced ZAP analysis with offensive security focus."""
        if not genai_client:
            return None
        
        # Smart sample findings instead of hard limit
        sampled_findings, aggregate_stats = self._smart_sample_findings(
            findings, 
            max_detailed=100,  # Up to 100 detailed findings
            max_per_type=5     # Max 5 per vulnerability type
        )
        
        # Group sampled findings by severity for context
        severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:  # Use ALL findings for severity counts
            sev = f.get("severity", "info")
            if sev in severity_groups:
                severity_groups[sev].append(f)
        
        # Build structured findings summary with more detail
        findings_summary = []
        for f in sampled_findings:
            findings_summary.append({
                "title": f.get("title", f.get("technique", "Unknown")),
                "severity": f.get("severity", "info"),
                "endpoint": f.get("endpoint", ""),
                "parameter": f.get("parameter", ""),
                "evidence": f.get("evidence", "")[:300] if f.get("evidence") else "",
                "cwe": f.get("cwe_id", ""),
                "solution_hint": f.get("solution", "")[:200] if f.get("solution") else "",
            })
        
        # Build additional context section
        context_section = ""
        if additional_context:
            context_section = f"""
## ADDITIONAL CONTEXT PROVIDED BY USER
{additional_context}

Take this context into account when analyzing the findings. It may include information about:
- The application's purpose and business criticality
- Known constraints or limitations
- Specific areas of concern
- Technology stack details
- Compliance requirements

"""
        
        # Build aggregate statistics section for full context
        aggregate_section = f"""
## FULL SCAN STATISTICS
This scan found **{aggregate_stats['total_findings']} total findings** across **{aggregate_stats['total_types']} vulnerability types**.

### Severity Breakdown (ALL Findings)
- **Critical:** {aggregate_stats['severity_totals'].get('critical', 0)}
- **High:** {aggregate_stats['severity_totals'].get('high', 0)}
- **Medium:** {aggregate_stats['severity_totals'].get('medium', 0)}
- **Low:** {aggregate_stats['severity_totals'].get('low', 0)}
- **Informational:** {aggregate_stats['severity_totals'].get('info', 0)}

### Top Vulnerability Types by Frequency
{chr(10).join([f"- **{t['type']}**: {t['total_count']} instances ({', '.join([f'{s}: {c}' for s, c in t['severity_breakdown'].items()])})" for t in aggregate_stats['findings_by_type'][:15]])}

*Note: The detailed findings below are a representative sample ({len(sampled_findings)} of {aggregate_stats['total_findings']}). Analysis should consider the full statistics above.*
"""
        
        prompt = f"""You are an expert offensive security researcher and penetration tester conducting a comprehensive security assessment.

## TARGET INFORMATION
**Target URL:** {target_url}
**Total Findings:** {len(findings)} (showing {len(sampled_findings)} representative samples)
**Critical:** {len(severity_groups['critical'])} | **High:** {len(severity_groups['high'])} | **Medium:** {len(severity_groups['medium'])} | **Low:** {len(severity_groups['low'])} | **Info:** {len(severity_groups['info'])}
{context_section}{aggregate_section}
## DETAILED FINDINGS (Representative Sample)
The following are detailed findings prioritized by severity. ALL critical and high findings are included, plus samples from other severity levels.

```json
{json.dumps(findings_summary, indent=2)}
```

## ANALYSIS REQUIREMENTS

Provide a comprehensive security analysis from an **offensive/red team perspective**. Think like an attacker - how would these vulnerabilities be exploited in a real-world attack?

**IMPORTANT:** Your analysis must account for the FULL {aggregate_stats['total_findings']} findings, not just the {len(sampled_findings)} detailed samples shown. Use the aggregate statistics to understand the complete attack surface.

Return a JSON object with the following structure:

{{
  "summary": "A comprehensive executive summary in **markdown format** with the following structure:
    
## 🎯 Executive Summary

**Overall Security Posture:** [CRITICAL/HIGH/MEDIUM/LOW RISK]

[2-3 sentence overview of the most significant findings and their potential impact]

### 📊 Key Metrics
- **Total Vulnerabilities:** X
- **Critical/High Risk:** X
- **Exploitability Rating:** [Easy/Medium/Hard]
- **Attack Surface:** [Large/Medium/Small]

### 🔥 Top Threats (list ALL critical and high severity finding types)
1. **[Most Critical Finding]** - [Brief impact] - X instances found
2. **[Second Critical Finding]** - [Brief impact] - X instances found
3. ... continue for ALL critical/high findings

### ⚡ Immediate Actions Required
- [Action 1]
- [Action 2]
- [Action 3]
- [Continue with more actions based on finding count]",

  "exploit_chains": [
    {{
      "title": "Attack Chain Name",
      "description": "Detailed multi-paragraph description of the attack chain. Explain the complete attack flow from initial reconnaissance through to achieving the attacker's objective. Reference specific vulnerability types, endpoints, and parameters from the findings.",
      "severity": "critical|high|medium",
      "steps": [
        "Step 1: Initial reconnaissance - describe specific techniques and what information attacker gathers",
        "Step 2: Vulnerability identification - how attacker finds and confirms the vulnerabilities",
        "Step 3: Initial exploitation - detailed exploitation technique with tool suggestions",
        "Step 4: Privilege escalation or lateral movement - how attacker expands access",
        "Step 5: Persistence establishment - how attacker maintains access",
        "Step 6: Data exfiltration or final objective - what attacker ultimately achieves"
      ],
      "affected_findings": ["Finding1", "Finding2", "Finding3"],
      "tools": ["Tool that could be used", "Another tool", "Additional tools"],
      "difficulty": "easy|medium|hard",
      "real_world_impact": "Detailed description of business impact if this chain is exploited",
      "detection_evasion": "How attacker might avoid detection during this attack"
    }}
  ],
  
  NOTE: Generate at LEAST 3-5 exploit chains based on the vulnerability combinations found. Consider:
  - Authentication bypass chains
  - Data exfiltration chains  
  - Account takeover chains
  - Privilege escalation chains
  - Remote code execution chains

  "remediation_plan": [
    {{
      "priority": 1,
      "vulnerability": "Vulnerability Name",
      "severity": "critical|high|medium|low",
      "recommendation": "**Detailed remediation guidance in markdown:**\\n\\n### Issue\\nExplanation of the vulnerability\\n\\n### Fix\\n```code\\nexample fix code if applicable\\n```\\n\\n### Verification\\nHow to verify the fix works",
      "affected_count": X,
      "effort": "low|medium|high",
      "quick_win": true|false
    }}
  ],
  
  NOTE: Include remediation for ALL vulnerability types found, prioritized by severity and count.

  "business_impact": "**Comprehensive markdown-formatted business impact assessment covering:**\\n\\n## 💼 Business Impact Analysis\\n\\n### Financial Risk\\n- Direct costs (breach response, legal, regulatory fines)\\n- Indirect costs (business disruption, customer churn)\\n- Estimated financial exposure range\\n\\n### Regulatory/Compliance\\n- GDPR implications and potential fines\\n- PCI-DSS compliance status\\n- HIPAA/SOC2 implications if applicable\\n- Industry-specific regulations\\n\\n### Reputational\\n- Brand damage assessment\\n- Customer trust implications\\n- Media/PR risk\\n\\n### Operational\\n- Service availability risks\\n- Business continuity concerns\\n- Recovery time objectives",

  "attack_narrative": "## 🔓 Detailed Attack Narrative\\n\\nA comprehensive story of how a sophisticated attacker would target this application based on the {aggregate_stats['total_findings']} vulnerabilities discovered:\\n\\n### Phase 1: Reconnaissance & Target Profiling\\n[Detailed description of information gathering, technology fingerprinting, and vulnerability scanning that would reveal these issues]\\n\\n### Phase 2: Initial Access Vectors\\n[Multiple entry points an attacker could use, prioritized by ease of exploitation]\\n\\n### Phase 3: Exploitation Deep-Dive\\n[Step-by-step technical exploitation of the most critical vulnerability chains]\\n\\n### Phase 4: Post-Exploitation\\n[What attacker does after gaining access - lateral movement, persistence, privilege escalation]\\n\\n### Phase 5: Objective Achievement\\n[Final impact - data theft, ransomware deployment, cryptomining, etc.]\\n\\n### Phase 6: Covering Tracks\\n[How attacker would hide their activities]",

  "offensive_insights": {{
    "easiest_entry_point": "Detailed description of the path of least resistance, with specific endpoint and parameter",
    "most_valuable_target": "What data/access an attacker would prioritize and why",
    "estimated_time_to_compromise": "Time estimate with breakdown by phase (recon: X, exploit: Y, post-exploit: Z)",
    "required_skill_level": "novice|intermediate|expert - with explanation",
    "detection_likelihood": "How likely current defenses would detect the attack, with evasion techniques",
    "attack_surface_assessment": "Overall assessment of the exposed attack surface",
    "highest_risk_endpoints": ["endpoint1", "endpoint2", "endpoint3"],
    "recommended_attacker_toolkit": ["tool1", "tool2", "tool3"]
  }}
}}

## IMPORTANT GUIDELINES:
1. **Think like a red teamer** - focus on realistic attack scenarios
2. **Be specific** - reference actual findings, endpoints, and parameters from the data
3. **Prioritize by exploitability** - not just severity
4. **Include tool suggestions** - what real attackers would use (Burp Suite, SQLMap, etc.)
5. **Markdown formatting** - use headers, bold, bullet points, code blocks
6. **Actionable recommendations** - specific, implementable fixes
7. **Real-world context** - relate to known attack patterns, CVEs, and MITRE ATT&CK
8. **Comprehensive coverage** - your analysis should reflect the FULL {len(findings)} findings, not just the samples
9. **Multiple attack chains** - identify at least 3-5 different exploitation paths
10. **Detailed narrative** - the attack narrative should be detailed enough to serve as a red team playbook"""

        try:
            from google.genai import types
            
            response = genai_client.models.generate_content(
                model=settings.gemini_model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="high"),
                    max_output_tokens=16000,
                )
            )
            
            # Parse JSON from response
            response_text = response.text if response else ""
            logger.info(f"LLM ZAP response length: {len(response_text)} chars")
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                result = json.loads(json_match.group())
                logger.info(f"LLM ZAP result keys: {list(result.keys())}")
                if 'attack_narrative' in result:
                    logger.info(f"attack_narrative length: {len(result.get('attack_narrative', ''))}")
                else:
                    logger.warning("attack_narrative NOT in LLM response!")
                # Add aggregate statistics to result for export reports
                result['aggregate_statistics'] = {
                    'total_findings': aggregate_stats['total_findings'],
                    'total_types': aggregate_stats['total_types'],
                    'severity_breakdown': aggregate_stats['severity_totals'],
                    'findings_by_type': aggregate_stats['findings_by_type'],
                    'sampled_count': len(sampled_findings),
                }
                return result
            
            logger.warning("Could not extract JSON from LLM ZAP response")
            return None
            
        except Exception as e:
            logger.warning(f"LLM ZAP analysis failed: {e}")
            return None
