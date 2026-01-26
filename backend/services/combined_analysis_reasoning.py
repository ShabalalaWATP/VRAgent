"""
Combined Analysis AI Reasoning Engine

A TRUE reasoning engine for combined security analysis that uses AI to:
1. Dynamically discover vulnerability correlations (not template matching)
2. Synthesize exploit chains with detailed step-by-step guidance
3. Verify and validate PoC scripts
4. Cross-reference findings across all scan types (MITM + SAST + DAST + Network)
5. Apply security principles to novel scenarios

This replaces the template-based approach with genuine AI reasoning.
"""

import json
import re
import ast
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import os

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


class ReasoningDepth(str, Enum):
    """How deep the AI should reason about findings."""
    QUICK = "quick"           # Fast correlation, surface-level
    STANDARD = "standard"     # Normal analysis
    DEEP = "deep"             # Thorough reasoning, slower
    EXHAUSTIVE = "exhaustive" # Maximum reasoning, very slow


class AnalysisStatus(str, Enum):
    """Status of an analysis operation - distinguishes success from failure."""
    SUCCESS = "success"           # Analysis completed successfully
    AI_UNAVAILABLE = "ai_unavailable"  # AI client not available
    AI_ERROR = "ai_error"         # AI call failed
    PARSE_ERROR = "parse_error"   # Failed to parse AI response
    FALLBACK_USED = "fallback_used"  # Used rule-based fallback
    NO_DATA = "no_data"           # No input data to analyze


@dataclass
class AnalysisResult:
    """Wrapper for analysis results with explicit status tracking."""
    status: AnalysisStatus
    data: Any
    error_message: Optional[str] = None
    used_fallback: bool = False
    ai_response_raw: Optional[str] = None  # For debugging


@dataclass
class ExploitStep:
    """A single step in an exploit chain."""
    step_number: int
    action: str
    target: str
    technique: str
    prerequisites: List[str]
    expected_outcome: str
    command_example: Optional[str] = None
    tool_suggestion: Optional[str] = None
    risk_level: str = "Medium"
    notes: str = ""


@dataclass
class SynthesizedExploitChain:
    """A complete exploit chain with step-by-step exploitation guidance."""
    id: str
    name: str
    summary: str
    entry_point: str
    final_impact: str
    steps: List[ExploitStep]
    total_steps: int
    estimated_complexity: str
    prerequisites: List[str]
    affected_findings: List[str]
    risk_score: float
    reasoning: str  # AI's explanation of WHY this chain works


@dataclass
class CrossDomainCorrelation:
    """A correlation discovered by AI reasoning, not template matching."""
    id: str
    finding_a: Dict[str, Any]
    finding_b: Dict[str, Any]
    source_a: str  # e.g., "SAST", "MITM", "Network"
    source_b: str
    correlation_type: str
    reasoning: str  # AI's explanation of the correlation
    exploitation_narrative: str  # How to exploit this correlation
    confidence: float
    novel: bool  # True if not from predefined templates


@dataclass
class PoCVerificationResult:
    """Result of verifying a generated PoC script."""
    script: str
    language: str
    syntax_valid: bool
    syntax_errors: List[str]
    security_issues: List[str]
    logic_assessment: str
    improved_script: Optional[str]
    verification_notes: str
    would_work: bool = False


class CombinedAnalysisReasoningEngine:
    """
    AI-powered security reasoning engine for combined analysis that discovers
    correlations and synthesizes exploits through genuine reasoning, not templates.
    """

    def __init__(self, depth: ReasoningDepth = ReasoningDepth.STANDARD):
        self.depth = depth
        self._ai_client = None
        self._model_id = getattr(settings, 'gemini_model_id', 'gemini-3-flash-preview')

    def _get_ai_client(self):
        """Lazy initialization of AI client."""
        if self._ai_client is None:
            try:
                from google import genai
                api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
                if api_key:
                    self._ai_client = genai.Client(api_key=api_key)
                else:
                    logger.warning("No Gemini API key found in environment")
            except Exception as e:
                logger.error(f"Failed to initialize AI client: {e}")
        return self._ai_client

    def _sync_generate_content(self, client, model_id: str, prompt: str, thinking_level: str = "high"):
        """
        Synchronous AI call - will be wrapped in thread executor.

        Uses Gemini 3's thinking_level parameter for reasoning control:
        - minimal: Quick, surface-level analysis
        - low: Basic reasoning
        - medium: Standard analysis depth
        - high: Deep, thorough reasoning (default for security analysis)
        """
        from google.genai import types
        response = client.models.generate_content(
            model=model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level=thinking_level),
                max_output_tokens=16384,
            )
        )
        return response.text if response.text else ""

    async def _reason(self, system_prompt: str, user_prompt: str, thinking_level: str = "high") -> Tuple[str, AnalysisStatus, Optional[str]]:
        """
        Execute AI reasoning with the given prompts.
        Returns: (response_text, status, error_message)

        Uses asyncio.to_thread() to avoid blocking the event loop.

        Args:
            system_prompt: The system context and instructions
            user_prompt: The user's specific query/data
            thinking_level: Gemini 3 thinking depth - "minimal", "low", "medium", or "high" (default)
        """
        client = self._get_ai_client()
        if not client:
            logger.warning("AI client not available")
            return "", AnalysisStatus.AI_UNAVAILABLE, "Gemini API key not configured"

        try:
            full_prompt = f"{system_prompt}\n\n{user_prompt}"

            # Run the blocking AI call in a thread pool to avoid blocking event loop
            response_text = await asyncio.to_thread(
                self._sync_generate_content,
                client,
                self._model_id,
                full_prompt,
                thinking_level
            )

            if not response_text:
                return "", AnalysisStatus.AI_ERROR, "AI returned empty response"

            return response_text, AnalysisStatus.SUCCESS, None

        except Exception as e:
            logger.error(f"AI reasoning failed: {e}")
            return "", AnalysisStatus.AI_ERROR, str(e)

    # =========================================================================
    # FEATURE 1: Dynamic AI Correlation Discovery
    # =========================================================================

    async def discover_correlations(
        self,
        findings: List[Dict[str, Any]],
        scan_sources: Dict[str, List[Dict[str, Any]]]
    ) -> AnalysisResult:
        """
        Use AI to discover correlations between findings.
        This goes beyond template matching to find novel relationships.

        Returns AnalysisResult with status tracking to distinguish success from failure.
        """
        if not findings:
            return AnalysisResult(
                status=AnalysisStatus.NO_DATA,
                data=[],
                error_message="No findings provided for correlation analysis"
            )

        correlations = []

        # Build comprehensive findings context including scan sources
        findings_context = self._build_findings_context(findings, scan_sources)

        system_prompt = """You are an expert security researcher who discovers hidden relationships between vulnerabilities.

Your task is to analyze findings from multiple security scans and discover correlations that:
1. Are NOT obvious from simple pattern matching
2. Require understanding of exploitation mechanics
3. Consider the ACTUAL technical relationship, not just keyword similarity

For each correlation you find, explain:
- WHY these findings are related (technical explanation)
- HOW an attacker could exploit this relationship
- What makes this correlation significant

Think like an attacker planning an engagement. What connections would you make?

IMPORTANT: Return ONLY valid JSON, no other text.

Return JSON array of correlations:
[{
    "finding_a_id": "F1",
    "finding_b_id": "F2",
    "source_a": "SAST/DAST/MITM/Network/Fuzzing",
    "source_b": "SAST/DAST/MITM/Network/Fuzzing",
    "correlation_type": "chained|amplified|enabling|corroborating|dependent",
    "reasoning": "Technical explanation of why these are related...",
    "exploitation_narrative": "Step-by-step how to exploit this relationship...",
    "confidence": 0.85,
    "novel": true
}]"""

        user_prompt = f"""Analyze these findings from multiple security scans and discover correlations:

{findings_context}

Focus on finding:
1. Attack chains: Finding A enables exploitation of Finding B
2. Amplification: Combined findings have greater impact than individually
3. Cross-domain insights: e.g., MITM credential leak + SAST weak password storage
4. Dependencies: Finding B can only be exploited if Finding A exists
5. Novel relationships that wouldn't be found by simple keyword matching

Think deeply about exploitation mechanics. How would a real attacker connect these dots?

Return ONLY the JSON array, no explanation text."""

        response_text, ai_status, ai_error = await self._reason(system_prompt, user_prompt, thinking_level="high")

        # If AI failed, use rule-based fallback
        if ai_status != AnalysisStatus.SUCCESS:
            logger.warning(f"AI correlation discovery failed ({ai_status}), using rule-based fallback")
            fallback_correlations = self._fallback_rule_based_correlations(findings, scan_sources)
            return AnalysisResult(
                status=AnalysisStatus.FALLBACK_USED,
                data=fallback_correlations,
                error_message=ai_error,
                used_fallback=True
            )

        try:
            # Extract JSON from response
            json_match = re.search(r'\[[\s\S]*\]', response_text)
            if json_match:
                correlation_data = json.loads(json_match.group())
                for corr in correlation_data:
                    # Get findings with validation
                    finding_a = self._get_finding_by_id(corr.get("finding_a_id", ""), findings)
                    finding_b = self._get_finding_by_id(corr.get("finding_b_id", ""), findings)

                    # Skip if either finding couldn't be found (returns None now)
                    if finding_a is None or finding_b is None:
                        logger.warning(f"Skipping correlation with invalid finding IDs: {corr.get('finding_a_id')}, {corr.get('finding_b_id')}")
                        continue

                    correlations.append(CrossDomainCorrelation(
                        id=f"corr_{len(correlations)}",
                        finding_a=finding_a,
                        finding_b=finding_b,
                        source_a=corr.get("source_a", finding_a.get("source", "Unknown")),
                        source_b=corr.get("source_b", finding_b.get("source", "Unknown")),
                        correlation_type=corr.get("correlation_type", "related"),
                        reasoning=corr.get("reasoning", ""),
                        exploitation_narrative=corr.get("exploitation_narrative", ""),
                        confidence=float(corr.get("confidence", 0.5)),
                        novel=corr.get("novel", True),
                    ))

                logger.info(f"Discovered {len(correlations)} correlations via AI reasoning")
                return AnalysisResult(
                    status=AnalysisStatus.SUCCESS,
                    data=correlations,
                    ai_response_raw=response_text[:500]  # For debugging
                )
            else:
                # No JSON found, use fallback
                logger.warning("No JSON found in AI response, using rule-based fallback")
                fallback_correlations = self._fallback_rule_based_correlations(findings, scan_sources)
                return AnalysisResult(
                    status=AnalysisStatus.FALLBACK_USED,
                    data=fallback_correlations,
                    error_message="AI response did not contain valid JSON",
                    used_fallback=True,
                    ai_response_raw=response_text[:500]
                )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse correlation JSON: {e}")
            fallback_correlations = self._fallback_rule_based_correlations(findings, scan_sources)
            return AnalysisResult(
                status=AnalysisStatus.FALLBACK_USED,
                data=fallback_correlations,
                error_message=f"JSON parse error: {str(e)}",
                used_fallback=True,
                ai_response_raw=response_text[:500]
            )

    def _fallback_rule_based_correlations(
        self,
        findings: List[Dict[str, Any]],
        scan_sources: Dict[str, List[Dict[str, Any]]]
    ) -> List[CrossDomainCorrelation]:
        """
        Rule-based correlation discovery as fallback when AI is unavailable.
        Uses predefined patterns to find common vulnerability relationships.
        """
        correlations = []

        # Index findings by type/category for faster lookup
        findings_by_type = {}
        for i, f in enumerate(findings):
            f_type = self._classify_finding(f)
            if f_type not in findings_by_type:
                findings_by_type[f_type] = []
            findings_by_type[f_type].append((i, f))

        # Rule 1: SQL Injection + Sensitive Data Exposure = Data Breach Chain
        sqli_findings = findings_by_type.get("sql_injection", [])
        data_exp_findings = findings_by_type.get("sensitive_data", [])
        for sqli_idx, sqli in sqli_findings:
            for data_idx, data_exp in data_exp_findings:
                correlations.append(CrossDomainCorrelation(
                    id=f"rule_corr_{len(correlations)}",
                    finding_a=sqli,
                    finding_b=data_exp,
                    source_a=sqli.get("source", "SAST"),
                    source_b=data_exp.get("source", "SAST"),
                    correlation_type="chained",
                    reasoning="SQL Injection can be used to exfiltrate sensitive data that was identified as exposed",
                    exploitation_narrative="1. Exploit SQL injection to access database. 2. Query tables containing sensitive data identified in other finding. 3. Exfiltrate data.",
                    confidence=0.75,
                    novel=False,
                ))

        # Rule 2: Auth Bypass + IDOR = Full Account Takeover
        auth_bypass = findings_by_type.get("auth_bypass", [])
        idor_findings = findings_by_type.get("idor", [])
        for auth_idx, auth in auth_bypass:
            for idor_idx, idor in idor_findings:
                correlations.append(CrossDomainCorrelation(
                    id=f"rule_corr_{len(correlations)}",
                    finding_a=auth,
                    finding_b=idor,
                    source_a=auth.get("source", "DAST"),
                    source_b=idor.get("source", "DAST"),
                    correlation_type="amplified",
                    reasoning="Authentication bypass combined with IDOR allows accessing any user's resources",
                    exploitation_narrative="1. Bypass authentication to gain access. 2. Use IDOR to enumerate and access other users' data.",
                    confidence=0.8,
                    novel=False,
                ))

        # Rule 3: XSS + Session Management Issues = Session Hijacking
        xss_findings = findings_by_type.get("xss", [])
        session_findings = findings_by_type.get("session", [])
        for xss_idx, xss in xss_findings:
            for sess_idx, sess in session_findings:
                correlations.append(CrossDomainCorrelation(
                    id=f"rule_corr_{len(correlations)}",
                    finding_a=xss,
                    finding_b=sess,
                    source_a=xss.get("source", "DAST"),
                    source_b=sess.get("source", "SAST"),
                    correlation_type="enabling",
                    reasoning="XSS can be used to steal session tokens if session management is weak",
                    exploitation_narrative="1. Inject XSS payload. 2. Capture session cookie via document.cookie. 3. Hijack victim session.",
                    confidence=0.7,
                    novel=False,
                ))

        # Rule 4: SSRF + Internal Service Discovery = Internal Network Access
        ssrf_findings = findings_by_type.get("ssrf", [])
        network_findings = findings_by_type.get("network", [])
        for ssrf_idx, ssrf in ssrf_findings:
            for net_idx, net in network_findings:
                correlations.append(CrossDomainCorrelation(
                    id=f"rule_corr_{len(correlations)}",
                    finding_a=ssrf,
                    finding_b=net,
                    source_a=ssrf.get("source", "DAST"),
                    source_b=net.get("source", "Network"),
                    correlation_type="enabling",
                    reasoning="SSRF can be used to access internal services discovered via network scan",
                    exploitation_narrative="1. Use SSRF to probe internal IPs from network scan. 2. Access internal services/metadata. 3. Pivot deeper.",
                    confidence=0.75,
                    novel=False,
                ))

        # Rule 5: RCE + Privilege Escalation = Full System Compromise
        rce_findings = findings_by_type.get("rce", [])
        privesc_findings = findings_by_type.get("privilege_escalation", [])
        for rce_idx, rce in rce_findings:
            for priv_idx, priv in privesc_findings:
                correlations.append(CrossDomainCorrelation(
                    id=f"rule_corr_{len(correlations)}",
                    finding_a=rce,
                    finding_b=priv,
                    source_a=rce.get("source", "SAST"),
                    source_b=priv.get("source", "SAST"),
                    correlation_type="chained",
                    reasoning="RCE provides initial access, privilege escalation leads to full system control",
                    exploitation_narrative="1. Exploit RCE for initial shell. 2. Enumerate local privesc vectors. 3. Escalate to root/SYSTEM.",
                    confidence=0.85,
                    novel=False,
                ))

        logger.info(f"Rule-based fallback found {len(correlations)} correlations")
        return correlations

    def _classify_finding(self, finding: Dict[str, Any]) -> str:
        """Classify a finding into a category for rule-based correlation."""
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        vuln_type = finding.get("type", "").lower()
        combined = f"{title} {desc} {vuln_type}"

        if any(x in combined for x in ["sql injection", "sqli", "sql-injection"]):
            return "sql_injection"
        elif any(x in combined for x in ["xss", "cross-site scripting", "cross site scripting"]):
            return "xss"
        elif any(x in combined for x in ["ssrf", "server-side request"]):
            return "ssrf"
        elif any(x in combined for x in ["idor", "insecure direct object"]):
            return "idor"
        elif any(x in combined for x in ["auth bypass", "authentication bypass", "broken auth"]):
            return "auth_bypass"
        elif any(x in combined for x in ["rce", "remote code", "command injection"]):
            return "rce"
        elif any(x in combined for x in ["session", "cookie", "token"]):
            return "session"
        elif any(x in combined for x in ["sensitive data", "pii", "credential", "password"]):
            return "sensitive_data"
        elif any(x in combined for x in ["privilege", "escalation", "privesc"]):
            return "privilege_escalation"
        elif any(x in combined for x in ["open port", "service", "host"]):
            return "network"
        else:
            return "other"

    def _build_findings_context(
        self,
        findings: List[Dict[str, Any]],
        scan_sources: Dict[str, List[Dict[str, Any]]]
    ) -> str:
        """Build a comprehensive context string for AI reasoning."""
        context_parts = []

        # Add scan source summary for better context
        if scan_sources:
            context_parts.append("=== SCAN SOURCES OVERVIEW ===")
            for source_name, source_findings in scan_sources.items():
                count = len(source_findings)
                severities = {}
                for f in source_findings:
                    sev = f.get("severity", "unknown").lower()
                    severities[sev] = severities.get(sev, 0) + 1
                sev_str = ", ".join(f"{k}: {v}" for k, v in severities.items())
                context_parts.append(f"- {source_name}: {count} findings ({sev_str})")
            context_parts.append("")

        # Add findings with IDs for reference
        context_parts.append("=== ALL FINDINGS (with IDs for reference) ===")
        for i, finding in enumerate(findings[:30]):  # Limit to avoid token overflow
            finding_id = f"F{i+1}"
            source = finding.get("source", "Unknown")
            title = finding.get("title", finding.get("type", finding.get("name", "Unknown")))
            severity = finding.get("severity", finding.get("risk", "Medium"))
            description = finding.get("description", finding.get("summary", ""))[:400]
            location = finding.get("file_path", finding.get("url", finding.get("endpoint", "")))
            cwe = finding.get("cwe", finding.get("cwe_id", ""))

            context_parts.append(f"""
[{finding_id}] Source: {source} | Severity: {severity}
Title: {title}
Location: {location}
CWE: {cwe if cwe else 'N/A'}
Description: {description}
---""")

        return "\n".join(context_parts)

    def _get_finding_by_id(self, finding_id: str, findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Get finding by ID or return None if not found.
        Does NOT return fake/placeholder data - callers must handle None.
        """
        try:
            if finding_id and finding_id.startswith("F"):
                idx = int(finding_id[1:]) - 1
                if 0 <= idx < len(findings):
                    return findings[idx]
        except (ValueError, IndexError) as e:
            logger.warning(f"Invalid finding ID format: {finding_id} - {e}")
        return None  # Return None instead of fake data

    # =========================================================================
    # FEATURE 2: Exploit Chain Synthesis with Step-by-Step Guidance
    # =========================================================================

    async def synthesize_exploit_chains(
        self,
        findings: List[Dict[str, Any]],
        correlations: List[CrossDomainCorrelation],
        target_context: Optional[str] = None
    ) -> List[SynthesizedExploitChain]:
        """
        Generate detailed exploit chains with step-by-step exploitation guidance.
        This explains HOW to exploit, not just THAT vulnerabilities are related.
        """
        chains = []

        # Build context for chain synthesis
        findings_summary = self._summarize_findings_for_chains(findings)
        correlations_summary = self._summarize_correlations(correlations)

        system_prompt = """You are a senior penetration tester creating detailed exploitation plans.

Your task is to synthesize realistic exploit chains from discovered vulnerabilities.
For each chain, provide ACTIONABLE step-by-step guidance that a junior pentester could follow.

Each step must include:
1. WHAT to do (specific action)
2. HOW to do it (actual commands, tools, or techniques)
3. WHAT you expect to happen (outcomes)
4. Prerequisites for this step
5. Risk level of detection

IMPORTANT: Return ONLY valid JSON, no other text.

Return JSON:
{
    "chains": [{
        "name": "Descriptive chain name",
        "summary": "1-2 sentence overview of the complete attack",
        "entry_point": "Where the attack starts (e.g., public web form, API endpoint)",
        "final_impact": "What attacker ultimately achieves (e.g., RCE, data exfil)",
        "estimated_complexity": "Low|Medium|High|Expert",
        "prerequisites": ["List of things needed before starting"],
        "affected_finding_ids": ["F1", "F3", "F5"],
        "steps": [{
            "step_number": 1,
            "action": "What to do",
            "target": "What you're targeting",
            "technique": "Specific technique/attack type",
            "prerequisites": ["What must be true for this step"],
            "expected_outcome": "What should happen if successful",
            "command_example": "curl -X POST 'http://target/api' -d 'payload'",
            "tool_suggestion": "Recommended tool (e.g., Burp Suite, sqlmap)",
            "risk_level": "Low|Medium|High",
            "notes": "Additional guidance or caveats"
        }],
        "reasoning": "Why this chain works - technical explanation of exploitation mechanics"
    }]
}"""

        user_prompt = f"""Based on these findings and correlations, synthesize detailed exploit chains:

=== FINDINGS ===
{findings_summary}

=== DISCOVERED CORRELATIONS ===
{correlations_summary}

{f"=== TARGET CONTEXT ==={chr(10)}{target_context}" if target_context else ""}

Create realistic, actionable exploit chains. For each chain:
1. Start from an externally accessible entry point
2. Show clear progression through multiple vulnerabilities
3. End with significant impact (data access, RCE, privilege escalation)
4. Include actual commands/tools where possible
5. Explain WHY each step enables the next

Generate 2-4 chains of varying complexity. Return ONLY the JSON."""

        response = await self._reason(system_prompt, user_prompt, thinking_level="high")

        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
                for chain_data in data.get("chains", []):
                    steps = []
                    for step_data in chain_data.get("steps", []):
                        steps.append(ExploitStep(
                            step_number=step_data.get("step_number", len(steps) + 1),
                            action=step_data.get("action", ""),
                            target=step_data.get("target", ""),
                            technique=step_data.get("technique", ""),
                            prerequisites=step_data.get("prerequisites", []),
                            expected_outcome=step_data.get("expected_outcome", ""),
                            command_example=step_data.get("command_example"),
                            tool_suggestion=step_data.get("tool_suggestion"),
                            risk_level=step_data.get("risk_level", "Medium"),
                            notes=step_data.get("notes", ""),
                        ))

                    chains.append(SynthesizedExploitChain(
                        id=f"chain_{len(chains)}",
                        name=chain_data.get("name", "Unnamed Chain"),
                        summary=chain_data.get("summary", ""),
                        entry_point=chain_data.get("entry_point", ""),
                        final_impact=chain_data.get("final_impact", ""),
                        steps=steps,
                        total_steps=len(steps),
                        estimated_complexity=chain_data.get("estimated_complexity", "Medium"),
                        prerequisites=chain_data.get("prerequisites", []),
                        affected_findings=chain_data.get("affected_finding_ids", []),
                        risk_score=self._calculate_chain_risk(steps),
                        reasoning=chain_data.get("reasoning", ""),
                    ))
                logger.info(f"Synthesized {len(chains)} exploit chains")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse chain JSON: {e}")

        return chains

    def _summarize_findings_for_chains(self, findings: List[Dict[str, Any]]) -> str:
        """Create a concise summary of findings for chain synthesis."""
        summaries = []
        for i, f in enumerate(findings[:25]):
            title = f.get("title", f.get("type", f.get("name", "Unknown")))
            severity = f.get("severity", f.get("risk", "Medium"))
            location = f.get("file_path", f.get("url", f.get("endpoint", "N/A")))
            source = f.get("source", "Unknown")
            summaries.append(f"[F{i+1}] {source} | {severity}: {title} @ {location}")
        return "\n".join(summaries)

    def _summarize_correlations(self, correlations: List[CrossDomainCorrelation]) -> str:
        """Summarize correlations for chain synthesis context."""
        if not correlations:
            return "No specific correlations discovered yet - look for attack paths yourself."

        summaries = []
        for corr in correlations[:15]:
            a_title = corr.finding_a.get("title", corr.finding_a.get("type", "Finding A"))
            b_title = corr.finding_b.get("title", corr.finding_b.get("type", "Finding B"))
            summaries.append(f"- [{corr.source_a}] {a_title} --> [{corr.source_b}] {b_title}")
            summaries.append(f"  Relationship: {corr.correlation_type} | Confidence: {corr.confidence:.0%}")
            summaries.append(f"  Reason: {corr.reasoning[:150]}...")
        return "\n".join(summaries)

    def _calculate_chain_risk(self, steps: List[ExploitStep]) -> float:
        """Calculate overall risk score for a chain."""
        if not steps:
            return 0.0

        risk_values = {"Low": 0.3, "Medium": 0.6, "High": 0.9}
        total_risk = sum(risk_values.get(s.risk_level, 0.5) for s in steps)
        # More steps = higher risk potential
        complexity_bonus = min(len(steps) * 0.05, 0.2)
        return min((total_risk / len(steps)) + complexity_bonus, 1.0)

    # =========================================================================
    # FEATURE 3: PoC Verification
    # =========================================================================

    async def verify_poc_script(
        self,
        script: str,
        language: str,
        vulnerability_context: str
    ) -> PoCVerificationResult:
        """
        Verify a generated PoC script for syntax, logic, and security issues.
        """
        result = PoCVerificationResult(
            script=script,
            language=language.lower(),
            syntax_valid=True,
            syntax_errors=[],
            security_issues=[],
            logic_assessment="",
            improved_script=None,
            verification_notes="",
            would_work=False,
        )

        # Step 1: Syntax validation
        syntax_errors = self._check_syntax(script, language.lower())
        result.syntax_errors = syntax_errors
        result.syntax_valid = len(syntax_errors) == 0

        # Step 2: AI logic and security assessment
        system_prompt = """You are a security code reviewer analyzing PoC (Proof of Concept) exploit scripts.

Evaluate the script for:
1. LOGIC: Does it actually exploit the vulnerability it claims to? Would it work in practice?
2. SECURITY: Any issues with the script itself (hardcoded creds, dangerous operations)?
3. COMPLETENESS: Is anything missing for it to work?
4. CORRECTNESS: Are there bugs or errors in the code?

Be critical and thorough. Many AI-generated PoCs have subtle bugs that make them non-functional.

IMPORTANT: Return ONLY valid JSON, no other text.

Return JSON:
{
    "would_work": true/false,
    "logic_assessment": "Detailed assessment of whether this PoC would actually work...",
    "logic_issues": ["Specific problems that would prevent it from working"],
    "security_issues": ["Security concerns with the script itself"],
    "completeness_issues": ["What's missing for it to work"],
    "improved_script": "Corrected/improved version if there are issues, or null if it's fine",
    "verification_notes": "Summary - would you trust this PoC?"
}"""

        user_prompt = f"""Analyze this {language} PoC script for the following vulnerability:

=== VULNERABILITY CONTEXT ===
{vulnerability_context}

=== POC SCRIPT ===
```{language}
{script}
```

Would this PoC actually work? Be critical - many AI-generated PoCs have subtle bugs.
Return ONLY the JSON."""

        response = await self._reason(system_prompt, user_prompt, thinking_level="high")

        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
                result.would_work = data.get("would_work", False)
                result.logic_assessment = data.get("logic_assessment", "")
                result.security_issues = data.get("security_issues", []) + data.get("logic_issues", [])
                result.improved_script = data.get("improved_script")
                result.verification_notes = data.get("verification_notes", "")
        except json.JSONDecodeError:
            result.verification_notes = "Failed to parse AI assessment"

        return result

    def _check_syntax(self, script: str, language: str) -> List[str]:
        """Check syntax of a script without executing it."""
        errors = []

        if language in ("python", "py"):
            try:
                ast.parse(script)
            except SyntaxError as e:
                errors.append(f"Python syntax error at line {e.lineno}: {e.msg}")

        elif language in ("javascript", "js", "node"):
            # Basic JS syntax checks
            brace_count = script.count("{") - script.count("}")
            paren_count = script.count("(") - script.count(")")
            bracket_count = script.count("[") - script.count("]")

            if brace_count != 0:
                errors.append(f"Unbalanced braces: {brace_count:+d}")
            if paren_count != 0:
                errors.append(f"Unbalanced parentheses: {paren_count:+d}")
            if bracket_count != 0:
                errors.append(f"Unbalanced brackets: {bracket_count:+d}")

        elif language in ("bash", "sh", "shell"):
            if script.count("'") % 2 != 0:
                errors.append("Unbalanced single quotes")
            if script.count('"') % 2 != 0:
                errors.append("Unbalanced double quotes")

        elif language in ("sql",):
            # Basic SQL checks
            if script.lower().count("select") > script.lower().count("from"):
                errors.append("SELECT without matching FROM")

        return errors

    # =========================================================================
    # FEATURE 4: Enhanced MITM Correlation with Code Findings
    # =========================================================================

    async def correlate_mitm_with_code(
        self,
        mitm_findings: List[Dict[str, Any]],
        sast_findings: List[Dict[str, Any]],
        source_code_context: Optional[str] = None
    ) -> List[CrossDomainCorrelation]:
        """
        Cross-reference MITM traffic findings with SAST code findings.
        Discovers relationships like:
        - Plaintext credential in traffic + weak password storage code
        - Sensitive data exposure + missing encryption in code
        - Authentication bypass indicators + auth code vulnerabilities
        """
        correlations = []

        if not mitm_findings and not sast_findings:
            return correlations

        # Build context
        mitm_context = self._build_mitm_context(mitm_findings)
        sast_context = self._build_sast_context(sast_findings)

        system_prompt = """You are a security researcher correlating network traffic analysis with source code vulnerabilities.

Your task is to find meaningful connections between:
1. What was observed in network traffic (MITM/proxy findings)
2. What vulnerabilities exist in the source code (SAST findings)

Look for patterns like:
- Credentials seen in plaintext traffic → weak credential storage/handling in code
- Sensitive data in HTTP responses → missing output encoding in code
- Authentication tokens with issues → flawed token generation/validation code
- Unencrypted sensitive fields → missing encryption implementation
- Session handling issues → session management code vulnerabilities
- API keys/secrets in traffic → hardcoded credentials in code

For each correlation, explain:
- The TRAFFIC observation (what was seen)
- The CODE vulnerability (what's wrong in code)
- WHY these are related (technical connection)
- How to EXPLOIT this combined weakness (practical attack)

IMPORTANT: Return ONLY valid JSON, no other text.

Return JSON array:
[{
    "mitm_finding_summary": "What was observed in traffic",
    "sast_finding_summary": "What code vulnerability exists",
    "correlation_type": "credential_exposure|data_leak|auth_flaw|crypto_weakness|session_issue|api_key_leak",
    "reasoning": "Technical explanation of the relationship",
    "exploitation_narrative": "How an attacker exploits this combined weakness",
    "combined_severity": "Critical|High|Medium|Low",
    "confidence": 0.85
}]"""

        user_prompt = f"""Correlate these MITM and SAST findings:

=== MITM (TRAFFIC) FINDINGS ===
{mitm_context if mitm_context else "No MITM findings available"}

=== SAST (CODE) FINDINGS ===
{sast_context if sast_context else "No SAST findings available"}

{f"=== SOURCE CODE SNIPPETS ==={chr(10)}{source_code_context[:3000]}" if source_code_context else ""}

Find meaningful correlations between what's seen in traffic and what's vulnerable in code.
Even if findings are from different areas, think about how they might connect.
Return ONLY the JSON array."""

        response = await self._reason(system_prompt, user_prompt, thinking_level="high")

        try:
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                data = json.loads(json_match.group())
                for corr_data in data:
                    correlations.append(CrossDomainCorrelation(
                        id=f"mitm_code_{len(correlations)}",
                        finding_a={"description": corr_data.get("mitm_finding_summary", ""), "source": "MITM"},
                        finding_b={"description": corr_data.get("sast_finding_summary", ""), "source": "SAST"},
                        source_a="MITM",
                        source_b="SAST",
                        correlation_type=corr_data.get("correlation_type", "related"),
                        reasoning=corr_data.get("reasoning", ""),
                        exploitation_narrative=corr_data.get("exploitation_narrative", ""),
                        confidence=float(corr_data.get("confidence", 0.5)),
                        novel=True,
                    ))
                logger.info(f"Found {len(correlations)} MITM-Code correlations")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse MITM-code correlation JSON: {e}")

        return correlations

    def _build_mitm_context(self, findings: List[Dict[str, Any]]) -> str:
        """Build context from MITM findings."""
        if not findings:
            return ""
        parts = []
        for i, f in enumerate(findings[:20]):
            parts.append(f"""[M{i+1}] {f.get('title', f.get('type', 'MITM Finding'))}
  Risk: {f.get('risk_level', f.get('severity', 'Medium'))}
  Details: {f.get('description', f.get('details', ''))[:250]}
  Endpoint: {f.get('url', f.get('endpoint', 'N/A'))}""")
        return "\n".join(parts)

    def _build_sast_context(self, findings: List[Dict[str, Any]]) -> str:
        """Build context from SAST findings."""
        if not findings:
            return ""
        parts = []
        for i, f in enumerate(findings[:20]):
            parts.append(f"""[S{i+1}] {f.get('type', f.get('title', 'Code Finding'))}
  Severity: {f.get('severity', 'Medium')}
  File: {f.get('file_path', 'Unknown')}:{f.get('line_number', '?')}
  CWE: {f.get('cwe', 'N/A')}
  Description: {f.get('summary', f.get('description', ''))[:250]}""")
        return "\n".join(parts)

    # =========================================================================
    # FEATURE 5: Security Reasoning Engine
    # =========================================================================

    async def reason_about_security(
        self,
        findings: List[Dict[str, Any]],
        target_description: str,
        specific_questions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Apply security principles to reason about findings.
        This handles novel scenarios by applying foundational security knowledge.
        """

        system_prompt = """You are a principal security architect applying security principles to analyze vulnerabilities.

Unlike pattern-matching systems, you should:
1. Apply FIRST PRINCIPLES of security (CIA triad, least privilege, defense in depth)
2. Consider the SPECIFIC CONTEXT of the target application
3. Reason about NOVEL attack scenarios not in standard vulnerability databases
4. Think about BUSINESS IMPACT, not just technical severity
5. Consider ATTACKER MOTIVATION and realistic threat models

Your analysis should answer:
- What's the WORST CASE scenario from these findings?
- What COMPENSATING CONTROLS might reduce risk?
- What ASSUMPTIONS are we making about exploitability?
- What ADDITIONAL TESTING would validate these findings?
- What's the REALISTIC RISK considering full context?

IMPORTANT: Return ONLY valid JSON, no other text.

Return JSON:
{
    "executive_summary": "2-3 sentences for leadership - what they need to know",
    "worst_case_scenario": "What happens if everything is exploited successfully",
    "realistic_risk_assessment": "Balanced view considering context and compensating controls",
    "novel_attack_scenarios": [
        {"scenario": "Description", "likelihood": "Low/Medium/High", "impact": "Low/Medium/High/Critical"}
    ],
    "compensating_controls_to_verify": ["Controls that might reduce risk - verify these exist"],
    "validation_recommendations": ["Additional tests to confirm findings are exploitable"],
    "business_impact_analysis": "Impact on business operations, reputation, compliance",
    "attacker_perspective": "How a motivated attacker would approach this target",
    "prioritized_actions": [
        {"action": "What to do", "urgency": "immediate|this_week|this_month", "rationale": "Why"}
    ],
    "confidence_assessment": "How confident are we in this analysis",
    "reasoning_chain": ["Step 1 of analysis", "Step 2", "Step 3", "Conclusion"]
}"""

        questions_section = ""
        if specific_questions:
            questions_section = "\n\n=== SPECIFIC QUESTIONS TO ADDRESS ===\n" + "\n".join(f"- {q}" for q in specific_questions)

        findings_context = self._build_findings_context(findings, {})

        user_prompt = f"""Apply security first principles to analyze these findings:

=== TARGET DESCRIPTION ===
{target_description}

=== FINDINGS ===
{findings_context}
{questions_section}

Reason through this like a principal security architect advising a CISO.
Don't just list findings - THINK about what they mean together.
Consider attackers, business context, and realistic risk.
Return ONLY the JSON."""

        response = await self._reason(system_prompt, user_prompt, thinking_level="high")

        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                result = json.loads(json_match.group())
                logger.info("Security reasoning analysis completed")
                return result
        except json.JSONDecodeError:
            pass

        return {
            "executive_summary": "Analysis could not be completed - AI reasoning failed",
            "reasoning_chain": ["AI reasoning failed to produce structured output"],
            "raw_response": response[:1000] if response else "No response",
        }

    # =========================================================================
    # Combined Analysis Pipeline
    # =========================================================================

    async def run_full_analysis(
        self,
        aggregated_data: Dict[str, Any],
        target_description: str = "Web application security assessment"
    ) -> Dict[str, Any]:
        """
        Run the complete agentic reasoning pipeline.
        Returns comprehensive analysis with AI-discovered insights.

        Includes explicit status tracking so callers know if AI failed vs found nothing.
        """
        logger.info("Starting agentic reasoning analysis pipeline...")

        # Track status of each step
        analysis_status = {
            "correlations": {"status": "pending", "used_fallback": False, "error": None},
            "chains": {"status": "pending", "used_fallback": False, "error": None},
            "mitm_correlation": {"status": "pending", "used_fallback": False, "error": None},
            "security_reasoning": {"status": "pending", "used_fallback": False, "error": None},
        }

        # Extract findings from all sources
        all_findings = self._extract_all_findings(aggregated_data)
        scan_sources = self._organize_by_source(aggregated_data)

        logger.info(f"Analyzing {len(all_findings)} findings from {len(scan_sources)} sources")

        # Step 1: Discover correlations with AI reasoning
        logger.info("Step 1/4: Discovering correlations via AI...")
        correlation_result = await self.discover_correlations(all_findings, scan_sources)

        # Handle AnalysisResult from discover_correlations
        correlations = correlation_result.data if isinstance(correlation_result, AnalysisResult) else correlation_result
        if isinstance(correlation_result, AnalysisResult):
            analysis_status["correlations"] = {
                "status": correlation_result.status.value,
                "used_fallback": correlation_result.used_fallback,
                "error": correlation_result.error_message,
            }
        else:
            analysis_status["correlations"]["status"] = "success"

        # Step 2: Synthesize exploit chains
        logger.info("Step 2/4: Synthesizing exploit chains...")
        try:
            chains = await self.synthesize_exploit_chains(
                all_findings, correlations, target_description
            )
            analysis_status["chains"]["status"] = "success"
        except Exception as e:
            logger.error(f"Chain synthesis failed: {e}")
            chains = []
            analysis_status["chains"] = {"status": "error", "error": str(e)}

        # Step 3: MITM + Code correlation
        logger.info("Step 3/4: Correlating MITM with code findings...")
        mitm_findings = []
        for report in aggregated_data.get("mitm_reports", []):
            mitm_findings.extend(report.get("findings", []))

        sast_findings = []
        for scan in aggregated_data.get("security_scans", []):
            sast_findings.extend(scan.get("findings", []))

        try:
            mitm_correlations = await self.correlate_mitm_with_code(mitm_findings, sast_findings)
            all_correlations = correlations + mitm_correlations
            analysis_status["mitm_correlation"]["status"] = "success"
        except Exception as e:
            logger.error(f"MITM correlation failed: {e}")
            all_correlations = correlations
            mitm_correlations = []
            analysis_status["mitm_correlation"] = {"status": "error", "error": str(e)}

        # Step 4: Security reasoning
        logger.info("Step 4/4: Applying security reasoning...")
        try:
            reasoning = await self.reason_about_security(all_findings, target_description)
            analysis_status["security_reasoning"]["status"] = "success"
        except Exception as e:
            logger.error(f"Security reasoning failed: {e}")
            reasoning = {}
            analysis_status["security_reasoning"] = {"status": "error", "error": str(e)}

        # Compile results
        novel_insights = [c for c in all_correlations if c.novel]

        # Determine overall status
        all_success = all(s.get("status") == "success" for s in analysis_status.values())
        any_fallback = any(s.get("used_fallback", False) for s in analysis_status.values())
        any_error = any(s.get("status") == "error" for s in analysis_status.values())

        overall_status = "success"
        if any_error:
            overall_status = "partial_failure"
        elif any_fallback:
            overall_status = "success_with_fallback"

        result = {
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "analysis_depth": self.depth.value,
            "overall_status": overall_status,
            "step_status": analysis_status,
            "statistics": {
                "total_findings_analyzed": len(all_findings),
                "sources_analyzed": list(scan_sources.keys()),
                "correlations_discovered": len(all_correlations),
                "novel_correlations": len(novel_insights),
                "exploit_chains_synthesized": len(chains),
                "used_fallback_analysis": any_fallback,
            },
            "correlations": [self._correlation_to_dict(c) for c in all_correlations],
            "exploit_chains": [self._chain_to_dict(c) for c in chains],
            "security_reasoning": reasoning,
            "novel_insights": [self._correlation_to_dict(c) for c in novel_insights],
        }

        logger.info(f"Analysis complete ({overall_status}): {len(all_correlations)} correlations, {len(chains)} chains")
        return result

    def _extract_all_findings(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from all sources into a unified list."""
        findings = []

        # Security scans (SAST)
        for scan in data.get("security_scans", []):
            for f in scan.get("findings", []):
                finding = dict(f)
                finding["source"] = "SAST"
                findings.append(finding)

        # Dynamic scans (DAST)
        for scan in data.get("dynamic_scans", []):
            for alert in scan.get("alerts", []):
                finding = dict(alert)
                finding["source"] = "DAST"
                finding["title"] = alert.get("name", alert.get("title", "DAST Finding"))
                findings.append(finding)

        # MITM reports
        for report in data.get("mitm_reports", []):
            for f in report.get("findings", []):
                finding = dict(f)
                finding["source"] = "MITM"
                findings.append(finding)

        # Network analysis
        for analysis in data.get("network_analyses", []):
            for f in analysis.get("findings", []):
                if isinstance(f, dict):
                    finding = dict(f)
                    finding["source"] = "Network"
                    findings.append(finding)

        # Fuzzing sessions
        for session in data.get("fuzzing_sessions", []):
            for f in session.get("findings", []):
                if isinstance(f, dict):
                    finding = dict(f)
                    finding["source"] = "Fuzzing"
                    findings.append(finding)

        # Agentic fuzzer
        for report in data.get("agentic_fuzzer_reports", []):
            for f in report.get("findings", []):
                if isinstance(f, dict):
                    finding = dict(f)
                    finding["source"] = "Agentic Fuzzer"
                    findings.append(finding)

        # Binary fuzzer
        for session in data.get("binary_fuzzer_sessions", []):
            for crash in session.get("crashes", []):
                if isinstance(crash, dict):
                    findings.append({
                        "source": "Binary Fuzzer",
                        "title": f"Crash: {crash.get('crash_type', 'Unknown')}",
                        "severity": "High",
                        "description": crash.get("description", "Binary crash detected"),
                    })

        # RE reports
        for report in data.get("re_reports", []):
            for f in report.get("findings", []):
                if isinstance(f, dict):
                    finding = dict(f)
                    finding["source"] = "Reverse Engineering"
                    findings.append(finding)

        return findings

    def _organize_by_source(self, data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Organize findings by their source for context building."""
        sources = {}

        source_keys = [
            ("security_scans", "SAST", "findings"),
            ("dynamic_scans", "DAST", "alerts"),
            ("mitm_reports", "MITM", "findings"),
            ("fuzzing_sessions", "Fuzzing", "findings"),
            ("network_analyses", "Network", "findings"),
        ]

        for data_key, source_name, findings_key in source_keys:
            items = data.get(data_key, [])
            if items:
                sources[source_name] = []
                for item in items:
                    findings = item.get(findings_key, [])
                    sources[source_name].extend(findings if isinstance(findings, list) else [])

        return sources

    def _correlation_to_dict(self, corr: CrossDomainCorrelation) -> Dict[str, Any]:
        """Convert correlation to dict for JSON serialization."""
        return {
            "id": corr.id,
            "source_a": corr.source_a,
            "source_b": corr.source_b,
            "finding_a_summary": corr.finding_a.get("title", corr.finding_a.get("description", "")[:100]),
            "finding_b_summary": corr.finding_b.get("title", corr.finding_b.get("description", "")[:100]),
            "correlation_type": corr.correlation_type,
            "reasoning": corr.reasoning,
            "exploitation_narrative": corr.exploitation_narrative,
            "confidence": corr.confidence,
            "novel": corr.novel,
        }

    def _chain_to_dict(self, chain: SynthesizedExploitChain) -> Dict[str, Any]:
        """Convert chain to dict for JSON serialization."""
        return {
            "id": chain.id,
            "name": chain.name,
            "summary": chain.summary,
            "entry_point": chain.entry_point,
            "final_impact": chain.final_impact,
            "total_steps": chain.total_steps,
            "estimated_complexity": chain.estimated_complexity,
            "prerequisites": chain.prerequisites,
            "affected_findings": chain.affected_findings,
            "risk_score": chain.risk_score,
            "reasoning": chain.reasoning,
            "steps": [
                {
                    "step_number": s.step_number,
                    "action": s.action,
                    "target": s.target,
                    "technique": s.technique,
                    "prerequisites": s.prerequisites,
                    "expected_outcome": s.expected_outcome,
                    "command_example": s.command_example,
                    "tool_suggestion": s.tool_suggestion,
                    "risk_level": s.risk_level,
                    "notes": s.notes,
                }
                for s in chain.steps
            ],
        }
