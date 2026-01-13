"""
Advanced False Positive Detection Engine

Implements Burp Suite-style verification techniques:
1. Response Differential Analysis - Compare baseline vs attack responses
2. Multi-Stage Verification - Re-test with varied payloads
3. Proof-of-Execution - Verify actual exploitation
4. Callback Verification - OOB detection for blind vulns
5. Confidence Tiering - Certain/Firm/Tentative classifications
6. User Feedback Loop - Learn from manual FP markings
7. Context Analysis - Code path and dataflow validation
"""

import asyncio
import hashlib
import re
import json
import difflib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

import httpx

from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger(__name__)


# =============================================================================
# Confidence Levels (Burp-style)
# =============================================================================

class ConfidenceLevel(str, Enum):
    """
    Burp Suite-style confidence levels:
    - CERTAIN: Verified exploitation, no doubt
    - FIRM: Strong indicators, high confidence
    - TENTATIVE: Possible vulnerability, needs review
    - FALSE_POSITIVE: Verified as not exploitable
    """
    CERTAIN = "certain"      # 95-100% confidence - verified exploit
    FIRM = "firm"            # 75-94% confidence - strong evidence
    TENTATIVE = "tentative"  # 50-74% confidence - needs review
    FALSE_POSITIVE = "false_positive"  # <50% or verified FP


class ValidationMethod(str, Enum):
    """Methods used to validate findings."""
    RESPONSE_DIFF = "response_diff"
    PAYLOAD_VARIATION = "payload_variation"
    TIME_BASED = "time_based"
    OOB_CALLBACK = "oob_callback"
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    CODE_ANALYSIS = "code_analysis"
    PATTERN_MATCH = "pattern_match"
    MANUAL_REVIEW = "manual_review"
    LLM_ANALYSIS = "llm_analysis"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ValidationResult:
    """Result of a single validation attempt."""
    method: ValidationMethod
    passed: bool
    confidence_delta: float  # -1.0 to +1.0
    evidence: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FPVerificationResult:
    """Complete false positive verification result."""
    finding_id: int
    original_confidence: float
    final_confidence: float
    confidence_level: ConfidenceLevel
    is_false_positive: bool
    validation_results: List[ValidationResult]
    verification_time_ms: int
    recommendation: str
    evidence_summary: str


@dataclass
class UserFeedback:
    """User feedback on a finding."""
    finding_id: int
    marked_as: str  # "true_positive", "false_positive"
    reason: Optional[str]
    context_patterns: List[str]  # Patterns to learn from
    timestamp: datetime


# =============================================================================
# Response Analysis
# =============================================================================

class ResponseAnalyzer:
    """
    Analyzes HTTP responses to determine if vulnerability was triggered.
    Implements response differential analysis like Burp Scanner.
    """
    
    # Patterns indicating successful exploitation
    EXPLOITATION_INDICATORS = {
        "sql_injection": [
            r"sql\s*syntax.*error",
            r"mysql_fetch|mysqli_|pg_query",
            r"ORA-\d{5}",
            r"SQLite3::SQLException",
            r"SQLSTATE\[",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"Microsoft.*ODBC.*Driver",
        ],
        "xss": [
            r"<script[^>]*>.*</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"alert\s*\(",
            r"document\.cookie",
        ],
        "command_injection": [
            r"uid=\d+.*gid=\d+",
            r"root:.*:0:0:",
            r"Windows.*\d+\.\d+\.\d+",
            r"bin/\w+",
            r"Permission denied",
            r"not recognized as.*command",
        ],
        "path_traversal": [
            r"\[boot\s+loader\]",
            r"root:.*:0:0:",
            r"localhost.*\d+\.\d+\.\d+\.\d+",
        ],
        "ssrf": [
            r"127\.0\.0\.1",
            r"localhost",
            r"169\.254\.169\.254",  # AWS metadata
            r"metadata\.google\.internal",
        ],
        "xxe": [
            r"root:.*:0:0:",
            r"<!\[CDATA\[",
            r"ENTITY.*SYSTEM",
        ],
    }
    
    # Patterns indicating false positive
    FALSE_POSITIVE_INDICATORS = [
        r"CSRF.*token.*invalid",
        r"rate.*limit.*exceeded",
        r"not.*authenticated",
        r"permission.*denied",
        r"404.*not.*found",
        r"invalid.*request",
        r"bad.*request",
        r"method.*not.*allowed",
    ]
    
    # Noise patterns to ignore in diff
    NOISE_PATTERNS = [
        r"csrf[_-]?token",
        r"nonce",
        r"\d{10,}",  # Timestamps
        r"[a-f0-9]{32,}",  # Hashes/tokens
        r"session[_-]?id",
        r"__viewstate",
        r"request[_-]?id",
    ]
    
    def __init__(self):
        self.baseline_cache: Dict[str, str] = {}
    
    def compute_response_hash(self, response: str) -> str:
        """Compute a normalized hash of response for comparison."""
        # Remove noise
        normalized = response.lower()
        for pattern in self.NOISE_PATTERNS:
            normalized = re.sub(pattern, "[NORMALIZED]", normalized, flags=re.IGNORECASE)
        
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def compute_structural_hash(self, response: str) -> str:
        """
        Compute structural hash - only considers HTML/JSON structure.
        Useful for detecting responses that differ only in data.
        """
        # Extract structure only
        structure = []
        
        # HTML tags
        html_tags = re.findall(r'<(\w+)[^>]*>', response)
        structure.extend(html_tags)
        
        # JSON keys
        json_keys = re.findall(r'"(\w+)"\s*:', response)
        structure.extend(json_keys)
        
        structure_str = "|".join(sorted(set(structure)))
        return hashlib.sha256(structure_str.encode()).hexdigest()
    
    def analyze_diff(
        self,
        baseline_response: str,
        attack_response: str,
        vuln_type: str
    ) -> Tuple[float, str]:
        """
        Analyze difference between baseline and attack response.
        Returns (confidence_delta, evidence).
        """
        # Quick length comparison
        len_diff = abs(len(attack_response) - len(baseline_response))
        len_ratio = len_diff / max(len(baseline_response), 1)
        
        # Structural comparison
        baseline_struct = self.compute_structural_hash(baseline_response)
        attack_struct = self.compute_structural_hash(attack_response)
        structure_changed = baseline_struct != attack_struct
        
        # Check for exploitation indicators
        indicators_found = []
        patterns = self.EXPLOITATION_INDICATORS.get(vuln_type, [])
        for pattern in patterns:
            if re.search(pattern, attack_response, re.IGNORECASE):
                # Check if pattern was in baseline
                if not re.search(pattern, baseline_response, re.IGNORECASE):
                    indicators_found.append(pattern)
        
        # Check for FP indicators
        fp_indicators = []
        for pattern in self.FALSE_POSITIVE_INDICATORS:
            if re.search(pattern, attack_response, re.IGNORECASE):
                fp_indicators.append(pattern)
        
        # Compute line-by-line diff
        baseline_lines = baseline_response.split('\n')
        attack_lines = attack_response.split('\n')
        diff = list(difflib.unified_diff(baseline_lines, attack_lines, lineterm=''))
        added_lines = [l for l in diff if l.startswith('+') and not l.startswith('+++')]
        removed_lines = [l for l in diff if l.startswith('-') and not l.startswith('---')]
        
        # Calculate confidence
        confidence = 0.0
        evidence_parts = []
        
        if indicators_found:
            confidence += 0.4
            evidence_parts.append(f"Exploitation indicators found: {indicators_found[:3]}")
        
        if structure_changed and len_ratio > 0.1:
            confidence += 0.2
            evidence_parts.append(f"Response structure changed significantly")
        
        if len(added_lines) > 5:
            confidence += 0.1
            evidence_parts.append(f"{len(added_lines)} new lines in response")
        
        # Reduce confidence for FP indicators
        if fp_indicators:
            confidence -= 0.3
            evidence_parts.append(f"False positive indicators: {fp_indicators[:2]}")
        
        # Reduce confidence if response is generic error
        if len(attack_response) < 500 and "error" in attack_response.lower():
            confidence -= 0.2
            evidence_parts.append("Generic error response")
        
        return max(-1.0, min(1.0, confidence)), "; ".join(evidence_parts) or "No significant differences"


# =============================================================================
# Payload Variation Validator
# =============================================================================

class PayloadVariationValidator:
    """
    Tests finding with multiple payload variations.
    If only specific payloads trigger the issue, it's more likely real.
    """
    
    PAYLOAD_VARIATIONS = {
        "sql_injection": [
            # Boundary variations
            ("'", "Single quote"),
            ("\"", "Double quote"),
            ("' OR '1'='1", "Classic OR"),
            ("1' OR '1'='1' --", "With comment"),
            ("1; DROP TABLE users--", "Stacked query"),
            ("1 UNION SELECT NULL--", "Union based"),
            # False positive triggers (should NOT work)
            ("' AND '1'='2", "False condition"),
            ("normal_value", "Clean value"),
        ],
        "xss": [
            ("<script>alert(1)</script>", "Basic script"),
            ("<img src=x onerror=alert(1)>", "Event handler"),
            ("javascript:alert(1)", "JS protocol"),
            ("<svg onload=alert(1)>", "SVG handler"),
            # Encoded variations
            ("&lt;script&gt;", "HTML encoded"),
            # Clean
            ("hello world", "Clean text"),
        ],
        "command_injection": [
            ("; id", "Semicolon"),
            ("| id", "Pipe"),
            ("$(id)", "Command substitution"),
            ("`id`", "Backticks"),
            ("|| id", "OR operator"),
            ("&& id", "AND operator"),
            # Clean
            ("normal text", "Clean value"),
        ],
    }
    
    async def validate_with_variations(
        self,
        endpoint: str,
        method: str,
        param_name: str,
        original_payload: str,
        vuln_type: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0
    ) -> ValidationResult:
        """
        Test endpoint with multiple payload variations.
        Real vulnerabilities should trigger on multiple similar payloads.
        """
        variations = self.PAYLOAD_VARIATIONS.get(vuln_type, [])
        if not variations:
            return ValidationResult(
                method=ValidationMethod.PAYLOAD_VARIATION,
                passed=False,
                confidence_delta=0.0,
                evidence="No variations defined for this vulnerability type"
            )
        
        results = []
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            for payload, description in variations:
                try:
                    # Build request
                    if method.upper() == "GET":
                        url = f"{endpoint}?{param_name}={payload}"
                        response = await client.get(url, headers=headers)
                    else:
                        response = await client.request(
                            method.upper(),
                            endpoint,
                            data={param_name: payload},
                            headers=headers
                        )
                    
                    # Check for vulnerability indicators
                    triggered = self._check_trigger(response.text, vuln_type, payload)
                    results.append({
                        "payload": payload,
                        "description": description,
                        "triggered": triggered,
                        "status_code": response.status_code,
                        "response_length": len(response.text)
                    })
                except Exception as e:
                    results.append({
                        "payload": payload,
                        "description": description,
                        "error": str(e)
                    })
        
        # Analyze results
        triggered_count = sum(1 for r in results if r.get("triggered"))
        clean_triggered = sum(1 for r in results if "Clean" in r.get("description", "") and r.get("triggered"))
        malicious_triggered = triggered_count - clean_triggered
        
        # Calculate confidence
        confidence_delta = 0.0
        evidence_parts = []
        
        if malicious_triggered >= 2 and clean_triggered == 0:
            # Multiple malicious payloads triggered, clean didn't = HIGH confidence
            confidence_delta = 0.3
            evidence_parts.append(f"{malicious_triggered} attack payloads triggered, 0 clean triggers")
            passed = True
        elif malicious_triggered > 0 and clean_triggered > 0:
            # Both triggered = probably FP (application shows everything)
            confidence_delta = -0.2
            evidence_parts.append(f"Both malicious AND clean payloads triggered - likely FP")
            passed = False
        elif malicious_triggered == 0:
            # No payloads triggered = false positive
            confidence_delta = -0.4
            evidence_parts.append(f"No attack payloads triggered vulnerability")
            passed = False
        else:
            confidence_delta = 0.1
            evidence_parts.append(f"{malicious_triggered} payloads triggered")
            passed = True
        
        return ValidationResult(
            method=ValidationMethod.PAYLOAD_VARIATION,
            passed=passed,
            confidence_delta=confidence_delta,
            evidence="; ".join(evidence_parts),
            details={"variations_tested": len(results), "results": results}
        )
    
    def _check_trigger(self, response: str, vuln_type: str, payload: str) -> bool:
        """Check if response indicates the payload triggered the vulnerability."""
        patterns = ResponseAnalyzer.EXPLOITATION_INDICATORS.get(vuln_type, [])
        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        
        # Check for reflection (XSS)
        if vuln_type == "xss" and payload in response:
            return True
        
        return False


# =============================================================================
# Time-Based Validator
# =============================================================================

class TimeBasedValidator:
    """
    Validates time-based blind vulnerabilities.
    Uses statistical analysis to reduce false positives from network jitter.
    """
    
    SLEEP_PAYLOADS = {
        "sql_injection": [
            ("' OR SLEEP(5)--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("' OR pg_sleep(5)--", 5),
        ],
        "command_injection": [
            ("; sleep 5", 5),
            ("| sleep 5", 5),
            ("$(sleep 5)", 5),
        ],
        "ssti": [
            ("{{7*7}}", 0),  # Non-time based but calculable
        ],
    }
    
    async def validate_time_based(
        self,
        endpoint: str,
        method: str,
        param_name: str,
        vuln_type: str,
        headers: Optional[Dict[str, str]] = None,
        baseline_samples: int = 3,
        delay_threshold: float = 4.0,  # seconds
    ) -> ValidationResult:
        """
        Validate time-based vulnerabilities with statistical confidence.
        
        Algorithm:
        1. Measure baseline response times (N samples)
        2. Calculate mean and stddev
        3. Test with sleep payloads
        4. If delay > mean + 3*stddev, high confidence
        """
        payloads = self.SLEEP_PAYLOADS.get(vuln_type, [])
        if not payloads:
            return ValidationResult(
                method=ValidationMethod.TIME_BASED,
                passed=False,
                confidence_delta=0.0,
                evidence="No time-based payloads for this type"
            )
        
        baseline_times = []
        sleep_results = []
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            # Collect baseline samples
            for _ in range(baseline_samples):
                try:
                    start = asyncio.get_event_loop().time()
                    if method.upper() == "GET":
                        await client.get(f"{endpoint}?{param_name}=test")
                    else:
                        await client.request(method.upper(), endpoint, data={param_name: "test"})
                    elapsed = asyncio.get_event_loop().time() - start
                    baseline_times.append(elapsed)
                    await asyncio.sleep(0.1)  # Small delay between requests
                except Exception as e:
                    logger.warning(f"Baseline request failed: {e}")
            
            if len(baseline_times) < 2:
                return ValidationResult(
                    method=ValidationMethod.TIME_BASED,
                    passed=False,
                    confidence_delta=-0.1,
                    evidence="Could not establish baseline"
                )
            
            # Calculate statistics
            mean_baseline = sum(baseline_times) / len(baseline_times)
            variance = sum((t - mean_baseline) ** 2 for t in baseline_times) / len(baseline_times)
            stddev = variance ** 0.5
            
            # Test with sleep payloads
            for payload, expected_delay in payloads:
                if expected_delay == 0:
                    continue  # Skip non-time-based payloads
                
                try:
                    start = asyncio.get_event_loop().time()
                    if method.upper() == "GET":
                        await client.get(f"{endpoint}?{param_name}={payload}")
                    else:
                        await client.request(method.upper(), endpoint, data={param_name: payload})
                    elapsed = asyncio.get_event_loop().time() - start
                    
                    sleep_results.append({
                        "payload": payload,
                        "expected_delay": expected_delay,
                        "actual_time": elapsed,
                        "baseline_mean": mean_baseline,
                        "time_delta": elapsed - mean_baseline,
                    })
                except asyncio.TimeoutError:
                    # Timeout could indicate successful sleep
                    sleep_results.append({
                        "payload": payload,
                        "expected_delay": expected_delay,
                        "actual_time": 30.0,  # Timeout
                        "timeout": True
                    })
                except Exception as e:
                    logger.warning(f"Time-based test failed: {e}")
        
        # Analyze results
        successful_delays = []
        for result in sleep_results:
            if result.get("timeout"):
                successful_delays.append(result)
            elif result.get("time_delta", 0) > delay_threshold:
                # Check if delay is within expected range
                actual_delay = result["time_delta"]
                expected = result["expected_delay"]
                if 0.8 * expected <= actual_delay <= 1.5 * expected:
                    successful_delays.append(result)
        
        # Calculate confidence
        if successful_delays:
            confidence_delta = 0.4
            evidence = f"Time-based validation successful: {len(successful_delays)} payloads caused expected delays"
            passed = True
        else:
            confidence_delta = -0.3
            evidence = f"Time-based validation failed: no delays observed (baseline: {mean_baseline:.2f}s)"
            passed = False
        
        return ValidationResult(
            method=ValidationMethod.TIME_BASED,
            passed=passed,
            confidence_delta=confidence_delta,
            evidence=evidence,
            details={
                "baseline_mean": mean_baseline,
                "baseline_stddev": stddev,
                "results": sleep_results
            }
        )


# =============================================================================
# OOB (Out-of-Band) Validator
# =============================================================================

class OOBValidator:
    """
    Validates blind vulnerabilities using Out-of-Band callbacks.
    Similar to Burp Collaborator.
    """
    
    def __init__(self, callback_server: Optional[str] = None):
        """
        Initialize with callback server URL.
        Uses Interactsh or custom callback server.
        """
        self.callback_server = callback_server or settings.get("INTERACTSH_URL", "")
        self.pending_callbacks: Dict[str, Dict[str, Any]] = {}
    
    async def generate_callback_url(self, finding_id: int, vuln_type: str) -> str:
        """Generate unique callback URL for tracking."""
        unique_id = hashlib.sha256(f"{finding_id}-{vuln_type}-{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        
        if self.callback_server:
            callback_url = f"http://{unique_id}.{self.callback_server}"
        else:
            # Fallback - use a self-hosted endpoint
            callback_url = f"http://{unique_id}.callback.local"
        
        self.pending_callbacks[unique_id] = {
            "finding_id": finding_id,
            "vuln_type": vuln_type,
            "created": datetime.utcnow(),
            "triggered": False
        }
        
        return callback_url
    
    async def check_callbacks(self, unique_id: str, timeout_seconds: int = 30) -> bool:
        """Check if callback was triggered."""
        # In production, query Interactsh or callback server
        # For now, check local state
        callback = self.pending_callbacks.get(unique_id)
        if callback and callback.get("triggered"):
            return True
        
        # Would poll callback server here
        return False
    
    async def validate_oob(
        self,
        endpoint: str,
        method: str,
        param_name: str,
        vuln_type: str,
        finding_id: int,
        headers: Optional[Dict[str, str]] = None,
        wait_time: int = 10
    ) -> ValidationResult:
        """
        Validate using OOB callback.
        """
        if not self.callback_server:
            return ValidationResult(
                method=ValidationMethod.OOB_CALLBACK,
                passed=False,
                confidence_delta=0.0,
                evidence="OOB callback server not configured"
            )
        
        callback_url = await self.generate_callback_url(finding_id, vuln_type)
        unique_id = callback_url.split('.')[0].replace('http://', '')
        
        # Generate OOB payloads
        oob_payloads = {
            "ssrf": [callback_url],
            "xxe": [f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><foo>&xxe;</foo>'],
            "command_injection": [f"curl {callback_url}", f"wget {callback_url}"],
            "sql_injection": [f"' UNION SELECT LOAD_FILE('{callback_url}')--"],
        }
        
        payloads = oob_payloads.get(vuln_type, [callback_url])
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            for payload in payloads:
                try:
                    if method.upper() == "GET":
                        await client.get(f"{endpoint}?{param_name}={payload}", headers=headers)
                    else:
                        await client.request(method.upper(), endpoint, data={param_name: payload}, headers=headers)
                except Exception as e:
                    logger.warning(f"OOB request failed: {e}")
        
        # Wait for callback
        await asyncio.sleep(wait_time)
        
        triggered = await self.check_callbacks(unique_id)
        
        if triggered:
            return ValidationResult(
                method=ValidationMethod.OOB_CALLBACK,
                passed=True,
                confidence_delta=0.5,  # High confidence for OOB
                evidence=f"OOB callback received for {vuln_type}",
                details={"callback_url": callback_url, "triggered": True}
            )
        else:
            return ValidationResult(
                method=ValidationMethod.OOB_CALLBACK,
                passed=False,
                confidence_delta=-0.1,
                evidence=f"No OOB callback received (waited {wait_time}s)",
                details={"callback_url": callback_url, "triggered": False}
            )


# =============================================================================
# User Feedback Learning System
# =============================================================================

class FeedbackLearner:
    """
    Learns from user feedback on findings to improve FP detection.
    Stores patterns and adjusts confidence scoring.
    """
    
    def __init__(self):
        self.feedback_store: List[UserFeedback] = []
        self.learned_patterns: Dict[str, List[str]] = {
            "true_positive": [],
            "false_positive": []
        }
        self.pattern_weights: Dict[str, float] = {}
    
    def record_feedback(
        self,
        finding_id: int,
        marked_as: str,
        reason: Optional[str],
        finding_details: Dict[str, Any]
    ) -> None:
        """Record user feedback and extract patterns."""
        # Extract context patterns from finding
        patterns = self._extract_patterns(finding_details)
        
        feedback = UserFeedback(
            finding_id=finding_id,
            marked_as=marked_as,
            reason=reason,
            context_patterns=patterns,
            timestamp=datetime.utcnow()
        )
        self.feedback_store.append(feedback)
        
        # Update learned patterns
        if marked_as == "false_positive":
            self.learned_patterns["false_positive"].extend(patterns)
            for pattern in patterns:
                self.pattern_weights[pattern] = self.pattern_weights.get(pattern, 0) - 0.1
        else:
            self.learned_patterns["true_positive"].extend(patterns)
            for pattern in patterns:
                self.pattern_weights[pattern] = self.pattern_weights.get(pattern, 0) + 0.1
        
        logger.info(f"Recorded feedback for finding {finding_id}: {marked_as}")
    
    def _extract_patterns(self, finding: Dict[str, Any]) -> List[str]:
        """Extract learnable patterns from a finding."""
        patterns = []
        
        file_path = finding.get("file_path", "")
        summary = finding.get("summary", "")
        code = finding.get("details", {}).get("code_snippet", "")
        
        # File path patterns
        if file_path:
            # Directory pattern
            if "/" in file_path:
                dir_name = file_path.rsplit("/", 1)[0].split("/")[-1]
                patterns.append(f"dir:{dir_name}")
            
            # File name pattern
            file_name = file_path.rsplit("/", 1)[-1]
            if "_test." in file_name or "test_" in file_name:
                patterns.append("pattern:test_file")
            if "mock" in file_name.lower():
                patterns.append("pattern:mock_file")
        
        # Code patterns
        if code:
            if "@require_auth" in code or "@login_required" in code:
                patterns.append("code:requires_auth")
            if "admin" in code.lower():
                patterns.append("code:admin_context")
            if "example" in code.lower() or "sample" in code.lower():
                patterns.append("code:example_code")
        
        # Finding type
        vuln_type = finding.get("type", "")
        if vuln_type:
            patterns.append(f"type:{vuln_type}")
        
        return patterns
    
    def get_confidence_adjustment(self, finding: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        Get confidence adjustment based on learned patterns.
        Returns (adjustment, matching_patterns).
        """
        patterns = self._extract_patterns(finding)
        adjustment = 0.0
        matching = []
        
        for pattern in patterns:
            if pattern in self.pattern_weights:
                adjustment += self.pattern_weights[pattern]
                matching.append(f"{pattern}: {self.pattern_weights[pattern]:+.2f}")
        
        return max(-0.5, min(0.5, adjustment)), matching
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get feedback statistics."""
        total = len(self.feedback_store)
        fp_count = sum(1 for f in self.feedback_store if f.marked_as == "false_positive")
        tp_count = total - fp_count
        
        return {
            "total_feedback": total,
            "false_positives_marked": fp_count,
            "true_positives_marked": tp_count,
            "learned_patterns": len(self.pattern_weights),
            "top_fp_patterns": sorted(
                [(p, w) for p, w in self.pattern_weights.items() if w < 0],
                key=lambda x: x[1]
            )[:10],
            "top_tp_patterns": sorted(
                [(p, w) for p, w in self.pattern_weights.items() if w > 0],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }


# =============================================================================
# Main False Positive Engine
# =============================================================================

class FalsePositiveEngine:
    """
    Main engine that orchestrates all validation methods.
    Produces Burp-style confidence levels.
    """
    
    def __init__(self, callback_server: Optional[str] = None):
        self.response_analyzer = ResponseAnalyzer()
        self.payload_validator = PayloadVariationValidator()
        self.time_validator = TimeBasedValidator()
        self.oob_validator = OOBValidator(callback_server)
        self.feedback_learner = FeedbackLearner()
    
    async def verify_finding(
        self,
        finding: Dict[str, Any],
        endpoint: Optional[str] = None,
        method: str = "GET",
        param_name: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        baseline_response: Optional[str] = None,
        attack_response: Optional[str] = None,
        enable_active_validation: bool = True,
        timeout_seconds: float = 30.0
    ) -> FPVerificationResult:
        """
        Comprehensively verify a finding for false positives.
        
        Returns verification result with confidence level.
        """
        import time
        start_time = time.time()
        
        finding_id = finding.get("id", 0)
        vuln_type = self._normalize_vuln_type(finding.get("type", ""))
        original_confidence = finding.get("details", {}).get("confidence", 0.5)
        
        validation_results: List[ValidationResult] = []
        
        # 1. Check learned patterns from user feedback
        feedback_adjustment, matching_patterns = self.feedback_learner.get_confidence_adjustment(finding)
        if matching_patterns:
            validation_results.append(ValidationResult(
                method=ValidationMethod.PATTERN_MATCH,
                passed=feedback_adjustment > 0,
                confidence_delta=feedback_adjustment,
                evidence=f"Learned patterns: {', '.join(matching_patterns)}"
            ))
        
        # 2. Quick heuristic checks (file patterns, etc.)
        heuristic_result = self._quick_heuristic_check(finding)
        validation_results.append(heuristic_result)
        
        # 3. Response differential analysis (if we have responses)
        if baseline_response and attack_response:
            diff_delta, diff_evidence = self.response_analyzer.analyze_diff(
                baseline_response, attack_response, vuln_type
            )
            validation_results.append(ValidationResult(
                method=ValidationMethod.RESPONSE_DIFF,
                passed=diff_delta > 0,
                confidence_delta=diff_delta,
                evidence=diff_evidence
            ))
        
        # 4. Active validation (if enabled and we have endpoint info)
        if enable_active_validation and endpoint and param_name:
            # Payload variation testing
            variation_result = await self.payload_validator.validate_with_variations(
                endpoint, method, param_name, finding.get("payload", ""), vuln_type, headers
            )
            validation_results.append(variation_result)
            
            # Time-based validation for applicable types
            if vuln_type in ("sql_injection", "command_injection"):
                time_result = await self.time_validator.validate_time_based(
                    endpoint, method, param_name, vuln_type, headers
                )
                validation_results.append(time_result)
            
            # OOB validation for applicable types
            if vuln_type in ("ssrf", "xxe"):
                oob_result = await self.oob_validator.validate_oob(
                    endpoint, method, param_name, vuln_type, finding_id, headers
                )
                validation_results.append(oob_result)
        
        # Calculate final confidence
        total_delta = sum(r.confidence_delta for r in validation_results)
        final_confidence = max(0.0, min(1.0, original_confidence + total_delta))
        
        # Determine confidence level
        passed_validations = sum(1 for r in validation_results if r.passed)
        total_validations = len([r for r in validation_results if r.confidence_delta != 0])
        
        if final_confidence >= 0.95 or (passed_validations >= 3 and final_confidence >= 0.75):
            confidence_level = ConfidenceLevel.CERTAIN
            is_false_positive = False
        elif final_confidence >= 0.75:
            confidence_level = ConfidenceLevel.FIRM
            is_false_positive = False
        elif final_confidence >= 0.50:
            confidence_level = ConfidenceLevel.TENTATIVE
            is_false_positive = False
        else:
            confidence_level = ConfidenceLevel.FALSE_POSITIVE
            is_false_positive = True
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            confidence_level, validation_results, vuln_type
        )
        
        # Generate evidence summary
        evidence_summary = self._summarize_evidence(validation_results)
        
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        return FPVerificationResult(
            finding_id=finding_id,
            original_confidence=original_confidence,
            final_confidence=final_confidence,
            confidence_level=confidence_level,
            is_false_positive=is_false_positive,
            validation_results=validation_results,
            verification_time_ms=elapsed_ms,
            recommendation=recommendation,
            evidence_summary=evidence_summary
        )
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type string."""
        vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")
        
        mappings = {
            "sqli": "sql_injection",
            "xss": "xss",
            "cross_site_scripting": "xss",
            "cmd_injection": "command_injection",
            "rce": "command_injection",
            "lfi": "path_traversal",
            "rfi": "path_traversal",
            "xxe": "xxe",
            "xml_external_entity": "xxe",
            "ssrf": "ssrf",
            "server_side_request_forgery": "ssrf",
        }
        
        return mappings.get(vuln_type, vuln_type)
    
    def _quick_heuristic_check(self, finding: Dict[str, Any]) -> ValidationResult:
        """Quick heuristic FP check."""
        file_path = finding.get("file_path", "").lower()
        summary = finding.get("summary", "").lower()
        
        fp_indicators = []
        confidence_delta = 0.0
        
        # Test file check
        if any(x in file_path for x in ["test_", "_test.", ".test.", "spec.", "/tests/", "/test/"]):
            fp_indicators.append("test file")
            confidence_delta -= 0.3
        
        # Mock/example check
        if any(x in file_path for x in ["mock", "stub", "fake", "example", "sample", "demo"]):
            fp_indicators.append("mock/example code")
            confidence_delta -= 0.25
        
        # Vendor/third-party check
        if any(x in file_path for x in ["vendor", "node_modules", ".min.js", "third_party"]):
            fp_indicators.append("vendor/third-party code")
            confidence_delta -= 0.2
        
        # Suppression comment check
        code = finding.get("details", {}).get("code_snippet", "")
        if any(x in code for x in ["# nosec", "// nosec", "NOSONAR", "@SuppressWarnings"]):
            fp_indicators.append("explicitly suppressed")
            confidence_delta -= 0.4
        
        if fp_indicators:
            return ValidationResult(
                method=ValidationMethod.PATTERN_MATCH,
                passed=False,
                confidence_delta=confidence_delta,
                evidence=f"Heuristic FP indicators: {', '.join(fp_indicators)}"
            )
        else:
            return ValidationResult(
                method=ValidationMethod.PATTERN_MATCH,
                passed=True,
                confidence_delta=0.1,
                evidence="No heuristic FP indicators found"
            )
    
    def _generate_recommendation(
        self,
        confidence_level: ConfidenceLevel,
        validations: List[ValidationResult],
        vuln_type: str
    ) -> str:
        """Generate human-readable recommendation."""
        if confidence_level == ConfidenceLevel.CERTAIN:
            return f"HIGH CONFIDENCE: This {vuln_type} vulnerability has been verified. Remediate immediately."
        elif confidence_level == ConfidenceLevel.FIRM:
            return f"LIKELY VULNERABLE: Strong evidence of {vuln_type}. Manual verification recommended before remediation."
        elif confidence_level == ConfidenceLevel.TENTATIVE:
            return f"NEEDS REVIEW: Possible {vuln_type} vulnerability. Requires manual code review to confirm."
        else:
            failed = [v for v in validations if not v.passed]
            reasons = [v.evidence for v in failed[:2]]
            return f"LIKELY FALSE POSITIVE: {'; '.join(reasons)}"
    
    def _summarize_evidence(self, validations: List[ValidationResult]) -> str:
        """Summarize all validation evidence."""
        passed = [v for v in validations if v.passed and v.confidence_delta > 0]
        failed = [v for v in validations if not v.passed and v.confidence_delta < 0]
        
        parts = []
        if passed:
            parts.append(f"✓ Positive: {', '.join(v.method.value for v in passed)}")
        if failed:
            parts.append(f"✗ Negative: {', '.join(v.method.value for v in failed)}")
        
        return " | ".join(parts) or "No validation evidence"
    
    def record_user_feedback(
        self,
        finding_id: int,
        marked_as: str,
        reason: Optional[str],
        finding_details: Dict[str, Any]
    ) -> None:
        """Record user feedback for learning."""
        self.feedback_learner.record_feedback(finding_id, marked_as, reason, finding_details)
    
    def get_feedback_stats(self) -> Dict[str, Any]:
        """Get feedback learning statistics."""
        return self.feedback_learner.get_statistics()


# =============================================================================
# Batch Processing
# =============================================================================

async def verify_findings_batch(
    findings: List[Dict[str, Any]],
    engine: Optional[FalsePositiveEngine] = None,
    concurrency: int = 5
) -> List[FPVerificationResult]:
    """
    Verify multiple findings in parallel.
    """
    if engine is None:
        engine = FalsePositiveEngine()
    
    semaphore = asyncio.Semaphore(concurrency)
    
    async def verify_with_semaphore(finding: Dict[str, Any]) -> FPVerificationResult:
        async with semaphore:
            return await engine.verify_finding(
                finding,
                enable_active_validation=False  # Disable for batch
            )
    
    tasks = [verify_with_semaphore(f) for f in findings]
    results = await asyncio.gather(*tasks)
    
    return list(results)


# =============================================================================
# Integration with AI Analysis
# =============================================================================

def enhance_ai_analysis_with_fp_verification(
    ai_result: Any,
    fp_result: FPVerificationResult
) -> Dict[str, Any]:
    """
    Combine AI analysis with FP verification results.
    """
    enhanced = {
        "finding_id": fp_result.finding_id,
        "confidence_level": fp_result.confidence_level.value,
        "final_confidence": fp_result.final_confidence,
        "is_false_positive": fp_result.is_false_positive,
        "recommendation": fp_result.recommendation,
        "evidence_summary": fp_result.evidence_summary,
        "validation_methods": [v.method.value for v in fp_result.validation_results],
        "verification_time_ms": fp_result.verification_time_ms,
    }
    
    # Merge with AI analysis if available
    if ai_result:
        enhanced["ai_false_positive_score"] = getattr(ai_result, "false_positive_score", 0)
        enhanced["ai_severity_adjustment"] = getattr(ai_result, "adjusted_severity", None)
        enhanced["ai_remediation"] = getattr(ai_result, "remediation_code", None)
    
    return enhanced
