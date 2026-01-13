"""
Response Diffing Engine

Advanced response comparison and anomaly detection for identifying
blind vulnerabilities and subtle behavioral differences.
"""

import hashlib
import re
import difflib
import time
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import statistics
import logging

logger = logging.getLogger(__name__)


class DiffType(Enum):
    """Types of response differences."""
    STATUS_CODE = "status_code"
    CONTENT_LENGTH = "content_length"
    RESPONSE_TIME = "response_time"
    HEADERS_ADDED = "headers_added"
    HEADERS_REMOVED = "headers_removed"
    HEADERS_CHANGED = "headers_changed"
    BODY_HASH = "body_hash"
    BODY_STRUCTURE = "body_structure"
    BODY_CONTENT = "body_content"
    ERROR_MESSAGE = "error_message"
    REDIRECT = "redirect"
    COOKIES = "cookies"


class AnomalyType(Enum):
    """Types of detected anomalies."""
    TIMING_ANOMALY = "timing_anomaly"
    SIZE_ANOMALY = "size_anomaly"
    CONTENT_ANOMALY = "content_anomaly"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    ERROR_ANOMALY = "error_anomaly"
    BLIND_INJECTION = "blind_injection"
    INFORMATION_LEAK = "information_leak"


@dataclass
class ResponseFingerprint:
    """Complete fingerprint of an HTTP response."""
    status_code: int
    content_length: int
    response_time: float
    headers: Dict[str, str]
    body_hash: str
    body_word_count: int
    body_line_count: int
    body_tag_count: int  # For HTML responses
    body_structure_hash: str  # Hash of structural elements
    error_keywords: List[str]
    redirect_url: Optional[str]
    cookies: Dict[str, str]
    content_type: str
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status_code": self.status_code,
            "content_length": self.content_length,
            "response_time": self.response_time,
            "headers": self.headers,
            "body_hash": self.body_hash,
            "body_word_count": self.body_word_count,
            "body_line_count": self.body_line_count,
            "body_tag_count": self.body_tag_count,
            "body_structure_hash": self.body_structure_hash,
            "error_keywords": self.error_keywords,
            "redirect_url": self.redirect_url,
            "cookies": self.cookies,
            "content_type": self.content_type,
            "timestamp": self.timestamp,
        }


@dataclass
class DiffResult:
    """Result of comparing two responses."""
    diff_type: DiffType
    baseline_value: Any
    test_value: Any
    delta: Optional[float] = None  # For numeric comparisons
    significance: float = 0.0  # 0-1, how significant is this diff
    details: str = ""


@dataclass
class AnomalyResult:
    """A detected anomaly from response comparison."""
    anomaly_type: AnomalyType
    confidence: float  # 0-1
    description: str
    evidence: Dict[str, Any]
    diffs: List[DiffResult]
    potential_vulnerability: Optional[str] = None
    severity: str = "medium"


@dataclass
class BaselineProfile:
    """Statistical profile of baseline responses."""
    url: str
    method: str
    fingerprints: List[ResponseFingerprint] = field(default_factory=list)
    
    # Statistical aggregates
    avg_response_time: float = 0.0
    std_response_time: float = 0.0
    avg_content_length: float = 0.0
    std_content_length: float = 0.0
    common_status_codes: Set[int] = field(default_factory=set)
    common_headers: Set[str] = field(default_factory=set)
    common_body_hashes: Set[str] = field(default_factory=set)
    
    def update_statistics(self):
        """Update statistical aggregates from fingerprints."""
        if not self.fingerprints:
            return
        
        times = [f.response_time for f in self.fingerprints]
        lengths = [f.content_length for f in self.fingerprints]
        
        self.avg_response_time = statistics.mean(times)
        self.std_response_time = statistics.stdev(times) if len(times) > 1 else 0.0
        self.avg_content_length = statistics.mean(lengths)
        self.std_content_length = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
        
        self.common_status_codes = {f.status_code for f in self.fingerprints}
        self.common_headers = set.intersection(
            *[set(f.headers.keys()) for f in self.fingerprints]
        ) if self.fingerprints else set()
        self.common_body_hashes = {f.body_hash for f in self.fingerprints}


class ResponseDiffingEngine:
    """
    Advanced response comparison engine for detecting subtle differences
    and anomalies that may indicate vulnerabilities.
    """
    
    # Keywords indicating errors
    ERROR_KEYWORDS = [
        "error", "exception", "fatal", "failed", "invalid", "denied",
        "unauthorized", "forbidden", "not found", "timeout", "crash",
        "stack trace", "traceback", "syntax error", "parse error",
        "sql", "query", "database", "connection", "refused"
    ]
    
    # Timing thresholds (in seconds)
    BLIND_SQLI_TIMING_THRESHOLD = 2.0  # Base delay for time-based detection
    TIMING_SIGNIFICANCE_THRESHOLD = 1.5  # Multiplier of std dev
    
    # Size thresholds
    SIZE_SIGNIFICANCE_PERCENT = 0.15  # 15% change is significant
    
    def __init__(self):
        """Initialize the diffing engine."""
        self._baselines: Dict[str, BaselineProfile] = {}
        self._response_history: List[Tuple[str, ResponseFingerprint]] = []
        self._stats = {
            "comparisons_made": 0,
            "anomalies_detected": 0,
            "baselines_created": 0,
        }

    def create_fingerprint(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        response_time: float,
    ) -> ResponseFingerprint:
        """
        Create a comprehensive fingerprint of an HTTP response.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            response_time: Time taken for request (seconds)
            
        Returns:
            ResponseFingerprint capturing all aspects of the response
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Extract content type
        content_type = headers_lower.get("content-type", "text/plain")
        
        # Parse cookies from Set-Cookie header
        cookies = {}
        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie:
            for cookie in set_cookie.split(","):
                parts = cookie.strip().split(";")[0]
                if "=" in parts:
                    name, value = parts.split("=", 1)
                    cookies[name.strip()] = value.strip()
        
        # Calculate body metrics
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        body_word_count = len(body.split())
        body_line_count = body.count("\n") + 1
        
        # Count HTML tags if HTML response
        body_tag_count = 0
        if "html" in content_type.lower():
            body_tag_count = len(re.findall(r'<[^>]+>', body))
        
        # Create structure hash (captures structural elements without actual content)
        structure_hash = self._compute_structure_hash(body, content_type)
        
        # Extract error keywords found
        error_keywords = [kw for kw in self.ERROR_KEYWORDS if kw.lower() in body.lower()]
        
        # Check for redirect
        redirect_url = None
        if status_code in (301, 302, 303, 307, 308):
            redirect_url = headers_lower.get("location")
        
        return ResponseFingerprint(
            status_code=status_code,
            content_length=len(body),
            response_time=response_time,
            headers=headers_lower,
            body_hash=body_hash,
            body_word_count=body_word_count,
            body_line_count=body_line_count,
            body_tag_count=body_tag_count,
            body_structure_hash=structure_hash,
            error_keywords=error_keywords,
            redirect_url=redirect_url,
            cookies=cookies,
            content_type=content_type,
        )

    def _compute_structure_hash(self, body: str, content_type: str) -> str:
        """Compute a hash of the structural elements of a response."""
        structure_elements = []
        
        if "json" in content_type.lower():
            # For JSON, capture key structure
            try:
                data = json.loads(body)
                structure_elements = self._extract_json_structure(data)
            except json.JSONDecodeError:
                structure_elements = ["invalid_json"]
        elif "html" in content_type.lower() or "xml" in content_type.lower():
            # For HTML/XML, capture tag structure
            tags = re.findall(r'<([a-zA-Z0-9]+)[^>]*>', body)
            structure_elements = tags[:100]  # First 100 tags
        else:
            # For text, capture line patterns
            lines = body.split("\n")[:50]
            structure_elements = [f"line_{i}:{len(line)}" for i, line in enumerate(lines)]
        
        structure_str = "|".join(str(e) for e in structure_elements)
        return hashlib.md5(structure_str.encode()).hexdigest()

    def _extract_json_structure(self, data: Any, prefix: str = "") -> List[str]:
        """Extract structural keys from JSON data."""
        structure = []
        
        if isinstance(data, dict):
            for key in sorted(data.keys()):
                full_key = f"{prefix}.{key}" if prefix else key
                structure.append(full_key)
                structure.extend(self._extract_json_structure(data[key], full_key))
        elif isinstance(data, list) and data:
            structure.append(f"{prefix}[]")
            structure.extend(self._extract_json_structure(data[0], f"{prefix}[]"))
        
        return structure[:100]  # Limit to prevent huge structures

    def establish_baseline(
        self,
        url: str,
        method: str,
        responses: List[Tuple[int, Dict[str, str], str, float]]
    ) -> BaselineProfile:
        """
        Establish a baseline from multiple normal responses.
        
        Args:
            url: The target URL
            method: HTTP method
            responses: List of (status_code, headers, body, response_time) tuples
            
        Returns:
            BaselineProfile with statistical metrics
        """
        baseline_key = f"{method}:{url}"
        
        profile = BaselineProfile(url=url, method=method)
        
        for status_code, headers, body, response_time in responses:
            fingerprint = self.create_fingerprint(status_code, headers, body, response_time)
            profile.fingerprints.append(fingerprint)
        
        profile.update_statistics()
        
        self._baselines[baseline_key] = profile
        self._stats["baselines_created"] += 1
        
        logger.info(f"Established baseline for {baseline_key} with {len(responses)} samples")
        return profile

    def compare_responses(
        self,
        baseline: ResponseFingerprint,
        test: ResponseFingerprint,
    ) -> List[DiffResult]:
        """
        Compare two response fingerprints and identify all differences.
        
        Args:
            baseline: The baseline/expected response
            test: The test/actual response
            
        Returns:
            List of differences found
        """
        diffs = []
        self._stats["comparisons_made"] += 1
        
        # Status code comparison
        if baseline.status_code != test.status_code:
            diffs.append(DiffResult(
                diff_type=DiffType.STATUS_CODE,
                baseline_value=baseline.status_code,
                test_value=test.status_code,
                significance=1.0 if abs(baseline.status_code - test.status_code) >= 100 else 0.5,
                details=f"Status changed from {baseline.status_code} to {test.status_code}",
            ))
        
        # Content length comparison
        if baseline.content_length != test.content_length:
            length_diff = test.content_length - baseline.content_length
            percent_diff = abs(length_diff) / max(baseline.content_length, 1)
            
            diffs.append(DiffResult(
                diff_type=DiffType.CONTENT_LENGTH,
                baseline_value=baseline.content_length,
                test_value=test.content_length,
                delta=length_diff,
                significance=min(percent_diff / self.SIZE_SIGNIFICANCE_PERCENT, 1.0),
                details=f"Content length changed by {length_diff} bytes ({percent_diff:.1%})",
            ))
        
        # Response time comparison
        time_diff = test.response_time - baseline.response_time
        if abs(time_diff) > 0.5:  # More than 500ms difference
            diffs.append(DiffResult(
                diff_type=DiffType.RESPONSE_TIME,
                baseline_value=baseline.response_time,
                test_value=test.response_time,
                delta=time_diff,
                significance=min(abs(time_diff) / self.BLIND_SQLI_TIMING_THRESHOLD, 1.0),
                details=f"Response time changed by {time_diff:.2f}s",
            ))
        
        # Header comparison
        baseline_headers = set(baseline.headers.keys())
        test_headers = set(test.headers.keys())
        
        added_headers = test_headers - baseline_headers
        removed_headers = baseline_headers - test_headers
        
        if added_headers:
            diffs.append(DiffResult(
                diff_type=DiffType.HEADERS_ADDED,
                baseline_value=list(baseline_headers),
                test_value=list(added_headers),
                significance=0.3,
                details=f"New headers: {added_headers}",
            ))
        
        if removed_headers:
            diffs.append(DiffResult(
                diff_type=DiffType.HEADERS_REMOVED,
                baseline_value=list(removed_headers),
                test_value=[],
                significance=0.3,
                details=f"Missing headers: {removed_headers}",
            ))
        
        # Check for changed header values
        common_headers = baseline_headers & test_headers
        changed_headers = {}
        for header in common_headers:
            if baseline.headers[header] != test.headers[header]:
                changed_headers[header] = {
                    "baseline": baseline.headers[header],
                    "test": test.headers[header],
                }
        
        if changed_headers:
            diffs.append(DiffResult(
                diff_type=DiffType.HEADERS_CHANGED,
                baseline_value={h: changed_headers[h]["baseline"] for h in changed_headers},
                test_value={h: changed_headers[h]["test"] for h in changed_headers},
                significance=0.4,
                details=f"Changed headers: {list(changed_headers.keys())}",
            ))
        
        # Body hash comparison
        if baseline.body_hash != test.body_hash:
            diffs.append(DiffResult(
                diff_type=DiffType.BODY_HASH,
                baseline_value=baseline.body_hash[:16],
                test_value=test.body_hash[:16],
                significance=0.5,
                details="Body content changed",
            ))
        
        # Body structure comparison
        if baseline.body_structure_hash != test.body_structure_hash:
            diffs.append(DiffResult(
                diff_type=DiffType.BODY_STRUCTURE,
                baseline_value=baseline.body_structure_hash[:16],
                test_value=test.body_structure_hash[:16],
                significance=0.7,
                details="Response structure changed",
            ))
        
        # Error keywords comparison
        new_errors = set(test.error_keywords) - set(baseline.error_keywords)
        if new_errors:
            diffs.append(DiffResult(
                diff_type=DiffType.ERROR_MESSAGE,
                baseline_value=baseline.error_keywords,
                test_value=list(new_errors),
                significance=0.8,
                details=f"New error indicators: {new_errors}",
            ))
        
        # Redirect comparison
        if baseline.redirect_url != test.redirect_url:
            diffs.append(DiffResult(
                diff_type=DiffType.REDIRECT,
                baseline_value=baseline.redirect_url,
                test_value=test.redirect_url,
                significance=0.6,
                details=f"Redirect changed from {baseline.redirect_url} to {test.redirect_url}",
            ))
        
        # Cookie comparison
        baseline_cookies = set(baseline.cookies.keys())
        test_cookies = set(test.cookies.keys())
        
        if baseline_cookies != test_cookies or \
           any(baseline.cookies.get(c) != test.cookies.get(c) for c in baseline_cookies & test_cookies):
            diffs.append(DiffResult(
                diff_type=DiffType.COOKIES,
                baseline_value=baseline.cookies,
                test_value=test.cookies,
                significance=0.5,
                details="Cookie changes detected",
            ))
        
        return diffs

    def compare_with_baseline(
        self,
        url: str,
        method: str,
        test_fingerprint: ResponseFingerprint,
    ) -> Tuple[List[DiffResult], Optional[BaselineProfile]]:
        """
        Compare a test response against the established baseline.
        
        Args:
            url: The target URL
            method: HTTP method
            test_fingerprint: Fingerprint of the test response
            
        Returns:
            Tuple of (differences, baseline_profile)
        """
        baseline_key = f"{method}:{url}"
        
        if baseline_key not in self._baselines:
            return [], None
        
        profile = self._baselines[baseline_key]
        
        # Compare against the most representative baseline fingerprint
        if not profile.fingerprints:
            return [], profile
        
        # Use the most recent baseline fingerprint
        baseline_fingerprint = profile.fingerprints[-1]
        
        diffs = self.compare_responses(baseline_fingerprint, test_fingerprint)
        
        return diffs, profile

    def detect_anomalies(
        self,
        url: str,
        method: str,
        test_fingerprint: ResponseFingerprint,
        payload_info: Optional[Dict[str, Any]] = None,
    ) -> List[AnomalyResult]:
        """
        Detect anomalies by comparing against baseline with context.
        
        Args:
            url: The target URL
            method: HTTP method
            test_fingerprint: Fingerprint of the test response
            payload_info: Optional info about the payload that triggered this response
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        diffs, profile = self.compare_with_baseline(url, method, test_fingerprint)
        
        if not profile:
            return anomalies
        
        # Analyze timing anomalies (potential blind injection)
        timing_diffs = [d for d in diffs if d.diff_type == DiffType.RESPONSE_TIME]
        for diff in timing_diffs:
            if diff.delta and diff.delta >= self.BLIND_SQLI_TIMING_THRESHOLD:
                vulnerability = None
                if payload_info:
                    payload = payload_info.get("payload", "")
                    if any(kw in payload.lower() for kw in ["sleep", "waitfor", "benchmark", "pg_sleep"]):
                        vulnerability = "Time-Based Blind SQL Injection"
                    elif "sleep" in payload.lower() and ("{{" in payload or "{%" in payload):
                        vulnerability = "Server-Side Template Injection"
                
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.TIMING_ANOMALY,
                    confidence=min(diff.delta / self.BLIND_SQLI_TIMING_THRESHOLD, 1.0),
                    description=f"Response delayed by {diff.delta:.2f}s compared to baseline",
                    evidence={
                        "baseline_time": diff.baseline_value,
                        "test_time": diff.test_value,
                        "delay": diff.delta,
                        "payload": payload_info.get("payload", "") if payload_info else "",
                    },
                    diffs=[diff],
                    potential_vulnerability=vulnerability,
                    severity="high" if vulnerability else "medium",
                ))
        
        # Analyze size anomalies
        size_diffs = [d for d in diffs if d.diff_type == DiffType.CONTENT_LENGTH]
        for diff in size_diffs:
            if diff.delta and abs(diff.delta) > profile.std_content_length * 2:
                vulnerability = None
                if payload_info:
                    payload = payload_info.get("payload", "")
                    if diff.delta > 0:  # Content increased
                        if any(kw in payload.lower() for kw in ["union", "select", "or 1=1"]):
                            vulnerability = "SQL Injection (content expansion)"
                        elif "../" in payload or "..%2f" in payload.lower():
                            vulnerability = "Path Traversal (file read)"
                
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.SIZE_ANOMALY,
                    confidence=min(diff.significance, 1.0),
                    description=f"Content size changed by {diff.delta} bytes",
                    evidence={
                        "baseline_size": diff.baseline_value,
                        "test_size": diff.test_value,
                        "delta": diff.delta,
                        "std_dev": profile.std_content_length,
                    },
                    diffs=[diff],
                    potential_vulnerability=vulnerability,
                    severity="high" if vulnerability else "medium",
                ))
        
        # Analyze error anomalies
        error_diffs = [d for d in diffs if d.diff_type == DiffType.ERROR_MESSAGE]
        for diff in error_diffs:
            vulnerability = None
            new_errors = diff.test_value
            
            if any("sql" in str(e).lower() for e in new_errors):
                vulnerability = "SQL Injection (error-based)"
            elif any("ldap" in str(e).lower() for e in new_errors):
                vulnerability = "LDAP Injection"
            elif any("xpath" in str(e).lower() for e in new_errors):
                vulnerability = "XPath Injection"
            
            anomalies.append(AnomalyResult(
                anomaly_type=AnomalyType.ERROR_ANOMALY,
                confidence=0.9 if vulnerability else 0.6,
                description=f"New error indicators detected: {new_errors}",
                evidence={
                    "new_errors": new_errors,
                    "baseline_errors": diff.baseline_value,
                },
                diffs=[diff],
                potential_vulnerability=vulnerability,
                severity="high" if vulnerability else "medium",
            ))
        
        # Analyze status code changes
        status_diffs = [d for d in diffs if d.diff_type == DiffType.STATUS_CODE]
        for diff in status_diffs:
            vulnerability = None
            baseline_status = diff.baseline_value
            test_status = diff.test_value
            
            if payload_info:
                payload = payload_info.get("payload", "")
                
                # 500 errors might indicate injection
                if test_status >= 500:
                    if any(kw in payload.lower() for kw in ["'", '"', ";", "--"]):
                        vulnerability = "Potential Injection (server error triggered)"
                
                # 403 to 200 might indicate authorization bypass
                if baseline_status == 403 and test_status == 200:
                    vulnerability = "Authorization Bypass"
                
                # 404 to 200 might indicate path traversal success
                if baseline_status == 404 and test_status == 200 and "../" in payload:
                    vulnerability = "Path Traversal Success"
            
            anomalies.append(AnomalyResult(
                anomaly_type=AnomalyType.BEHAVIOR_ANOMALY,
                confidence=diff.significance,
                description=f"Status code changed from {baseline_status} to {test_status}",
                evidence={
                    "baseline_status": baseline_status,
                    "test_status": test_status,
                },
                diffs=[diff],
                potential_vulnerability=vulnerability,
                severity="high" if vulnerability else "medium",
            ))
        
        # Analyze structure changes
        structure_diffs = [d for d in diffs if d.diff_type == DiffType.BODY_STRUCTURE]
        if structure_diffs:
            anomalies.append(AnomalyResult(
                anomaly_type=AnomalyType.CONTENT_ANOMALY,
                confidence=0.7,
                description="Response structure changed significantly",
                evidence={
                    "baseline_structure": structure_diffs[0].baseline_value,
                    "test_structure": structure_diffs[0].test_value,
                },
                diffs=structure_diffs,
                severity="medium",
            ))
        
        if anomalies:
            self._stats["anomalies_detected"] += len(anomalies)
        
        return anomalies

    def compute_diff_text(
        self,
        baseline_body: str,
        test_body: str,
        context_lines: int = 3,
    ) -> str:
        """
        Compute a unified diff between two response bodies.
        
        Args:
            baseline_body: The baseline response body
            test_body: The test response body
            context_lines: Number of context lines to include
            
        Returns:
            Unified diff string
        """
        baseline_lines = baseline_body.splitlines(keepends=True)
        test_lines = test_body.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            baseline_lines,
            test_lines,
            fromfile="baseline",
            tofile="test",
            n=context_lines,
        )
        
        return "".join(diff)

    def compute_similarity(self, baseline_body: str, test_body: str) -> float:
        """
        Compute similarity ratio between two response bodies.
        
        Args:
            baseline_body: The baseline response body
            test_body: The test response body
            
        Returns:
            Similarity ratio between 0 and 1
        """
        return difflib.SequenceMatcher(None, baseline_body, test_body).ratio()

    def find_differential_content(
        self,
        baseline_body: str,
        test_body: str,
    ) -> Dict[str, List[str]]:
        """
        Find content that was added or removed between responses.
        
        Args:
            baseline_body: The baseline response body
            test_body: The test response body
            
        Returns:
            Dict with 'added' and 'removed' lists
        """
        baseline_lines = set(baseline_body.splitlines())
        test_lines = set(test_body.splitlines())
        
        return {
            "added": list(test_lines - baseline_lines),
            "removed": list(baseline_lines - test_lines),
        }

    def detect_reflection(
        self,
        payload: str,
        response_body: str,
    ) -> Dict[str, Any]:
        """
        Detect if a payload is reflected in the response.
        
        Args:
            payload: The sent payload
            response_body: The response body to check
            
        Returns:
            Dict with reflection details
        """
        result = {
            "reflected": False,
            "exact_match": False,
            "encoded_match": False,
            "partial_match": False,
            "contexts": [],
        }
        
        # Check exact match
        if payload in response_body:
            result["reflected"] = True
            result["exact_match"] = True
            
            # Find context
            idx = response_body.find(payload)
            start = max(0, idx - 50)
            end = min(len(response_body), idx + len(payload) + 50)
            result["contexts"].append({
                "type": "exact",
                "context": response_body[start:end],
                "position": idx,
            })
        
        # Check HTML-encoded match
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload != payload and encoded_payload in response_body:
            result["reflected"] = True
            result["encoded_match"] = True
            
            idx = response_body.find(encoded_payload)
            start = max(0, idx - 50)
            end = min(len(response_body), idx + len(encoded_payload) + 50)
            result["contexts"].append({
                "type": "html_encoded",
                "context": response_body[start:end],
                "position": idx,
            })
        
        # Check URL-encoded match
        from urllib.parse import quote
        url_encoded = quote(payload)
        if url_encoded != payload and url_encoded in response_body:
            result["reflected"] = True
            result["encoded_match"] = True
            
            idx = response_body.find(url_encoded)
            start = max(0, idx - 50)
            end = min(len(response_body), idx + len(url_encoded) + 50)
            result["contexts"].append({
                "type": "url_encoded",
                "context": response_body[start:end],
                "position": idx,
            })
        
        # Check partial match (significant portion of payload)
        if len(payload) > 5 and not result["exact_match"]:
            # Check if significant portion is reflected
            for i in range(len(payload) - 5):
                chunk = payload[i:i+5]
                if chunk in response_body:
                    result["partial_match"] = True
                    result["reflected"] = True
                    break
        
        return result

    def get_baseline(self, url: str, method: str) -> Optional[BaselineProfile]:
        """Get the baseline profile for a URL/method combination."""
        baseline_key = f"{method}:{url}"
        return self._baselines.get(baseline_key)

    def clear_baseline(self, url: str, method: str):
        """Clear the baseline for a URL/method combination."""
        baseline_key = f"{method}:{url}"
        if baseline_key in self._baselines:
            del self._baselines[baseline_key]

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return self._stats.copy()

    def reset_stats(self):
        """Reset engine statistics."""
        self._stats = {
            "comparisons_made": 0,
            "anomalies_detected": 0,
            "baselines_created": 0,
        }


# Singleton instance
_diffing_engine: Optional[ResponseDiffingEngine] = None


def get_diffing_engine() -> ResponseDiffingEngine:
    """Get or create the diffing engine instance."""
    global _diffing_engine
    if _diffing_engine is None:
        _diffing_engine = ResponseDiffingEngine()
    return _diffing_engine
