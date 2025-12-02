"""
AI-Enhanced Vulnerability Analysis Service

Provides intelligent analysis of scan findings using LLM:
1. False Positive Detection - Identify likely false positives
2. Data Flow Analysis - Trace how tainted data flows
3. Severity Adjustment - Re-assess severity based on context
4. Attack Chain Discovery - Find chained vulnerabilities
5. Custom Remediation - Generate tailored fix code

Optimized for minimal LLM calls by batching findings.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Use google-genai SDK (consistent with other services)
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


# Patterns that strongly suggest false positives
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
    analysis_types: List[str] = None
) -> Dict[int, AIAnalysisResult]:
    """
    Call LLM once for a batch of findings.
    Returns analysis results keyed by finding ID.
    
    analysis_types can include: 'false_positive', 'severity', 'data_flow', 'remediation'
    """
    if not genai or not settings.gemini_api_key:
        logger.info("Gemini API not configured, skipping LLM analysis")
        return {}
    
    if analysis_types is None:
        analysis_types = ['false_positive', 'severity', 'remediation']
    
    if not findings_batch:
        return {}
    
    # Build prompt with all findings
    findings_text = []
    for i, f in enumerate(findings_batch[:15]):  # Max 15 findings per batch
        snippet = code_snippets.get(f.get("id"), "")[:500]  # Truncate snippets
        findings_text.append(f"""
Finding #{f.get('id')}:
- Type: {f.get('type')}
- Severity: {f.get('severity')}
- File: {f.get('file_path')}
- Line: {f.get('start_line')}
- Summary: {f.get('summary')}
- Code snippet:
```
{snippet}
```
""")
    
    analysis_instructions = []
    if 'false_positive' in analysis_types:
        analysis_instructions.append("""
- false_positive_score: 0.0-1.0 (1.0 = definitely false positive)
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

Only include fields that are relevant. Be conservative with false_positive_score."""

    try:
        if not genai_client:
            logger.warning("Gemini client not initialized, skipping LLM analysis")
            return {}
            
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt,
            config={
                "temperature": 0.2,
                "max_output_tokens": 4000,
            }
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
    if not genai or not settings.gemini_api_key:
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
            
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt,
            config={
                "temperature": 0.3,
                "max_output_tokens": 2000,
            }
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
) -> AIAnalysisSummary:
    """
    Main entry point for AI-enhanced analysis.
    
    Performs:
    1. Quick heuristic checks on all findings (no LLM)
    2. LLM analysis on top priority findings (batched, 1-2 calls max)
    3. Attack chain identification (1 LLM call)
    
    Args:
        findings: List of finding dicts with id, type, severity, file_path, summary, details
        code_snippets: Optional dict mapping finding_id -> code snippet
        enable_llm: Whether to use LLM (set False for fast mode)
        max_llm_findings: Max findings to send to LLM
        
    Returns:
        AIAnalysisSummary with all analysis results
    """
    if code_snippets is None:
        code_snippets = {}
    
    analysis_results: Dict[int, AIAnalysisResult] = {}
    false_positives_count = 0
    severity_adjustments_count = 0
    
    # Step 1: Quick heuristic analysis on ALL findings
    for f in findings:
        finding_id = f.get("id")
        if not finding_id:
            continue
        
        snippet = code_snippets.get(finding_id, "")
        
        # Quick false positive check
        fp_score, fp_reason = _quick_false_positive_check(f, snippet)
        
        # Quick severity adjustment
        new_severity, sev_reason = _quick_severity_adjustment(f, snippet)
        
        if fp_score > 0.3 or new_severity:
            result = AIAnalysisResult(
                finding_id=finding_id,
                false_positive_score=fp_score,
                false_positive_reason=fp_reason,
                adjusted_severity=new_severity,
                severity_reason=sev_reason,
            )
            analysis_results[finding_id] = result
            
            if fp_score >= 0.5:
                false_positives_count += 1
            if new_severity:
                severity_adjustments_count += 1
    
    # Step 2: Attack chain identification (heuristic)
    attack_chains = _identify_attack_chains_heuristic(findings)
    
    # Step 3: LLM analysis (if enabled and we have API key)
    if enable_llm and genai_client and settings.gemini_api_key:
        # Prioritize high/critical findings not yet marked as false positives
        priority_findings = [
            f for f in findings
            if f.get("severity") in ("critical", "high")
            and f.get("id") not in analysis_results
        ][:max_llm_findings]
        
        if priority_findings:
            logger.info(f"Running LLM analysis on {len(priority_findings)} priority findings")
            
            # Single batched LLM call for finding analysis
            llm_results = await _call_llm_batch_analysis(
                priority_findings,
                code_snippets,
                analysis_types=['false_positive', 'severity', 'data_flow', 'remediation']
            )
            
            for finding_id, result in llm_results.items():
                # Merge with existing heuristic results
                if finding_id in analysis_results:
                    existing = analysis_results[finding_id]
                    # LLM results take precedence but we keep higher FP scores
                    result.false_positive_score = max(result.false_positive_score, existing.false_positive_score)
                    if not result.false_positive_reason and existing.false_positive_reason:
                        result.false_positive_reason = existing.false_positive_reason
                
                analysis_results[finding_id] = result
                
                if result.false_positive_score >= 0.5:
                    false_positives_count += 1
                if result.adjusted_severity:
                    severity_adjustments_count += 1
        
        # Single LLM call for attack chain refinement
        if findings:
            logger.info("Running LLM attack chain analysis")
            attack_chains = await _call_llm_attack_chains(findings, attack_chains)
    
    return AIAnalysisSummary(
        findings_analyzed=len(findings),
        false_positives_detected=false_positives_count,
        severity_adjustments=severity_adjustments_count,
        attack_chains=attack_chains,
        analysis_results=analysis_results,
    )


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
