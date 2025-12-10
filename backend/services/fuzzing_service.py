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


def detect_anomalies(response: FuzzResponse, baseline_length: Optional[int], all_responses: List[FuzzResponse]) -> List[str]:
    """Detect anomalies in the response that might indicate vulnerabilities."""
    flags = []
    
    # Check response body against detection patterns
    body_lower = response.body.lower()
    for pattern_name, pattern_config in DETECTION_PATTERNS.items():
        for pattern in pattern_config["patterns"]:
            if re.search(pattern, response.body, re.IGNORECASE):
                flags.append(pattern_config["type"])
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
    
    return list(set(flags))


def analyze_findings(responses: List[FuzzResponse], config: FuzzConfig) -> List[FuzzFinding]:
    """Analyze responses and generate security findings."""
    findings = []
    
    for response in responses:
        if not response.flags:
            continue
            
        for flag in response.flags:
            # Find the pattern config for this flag
            for pattern_name, pattern_config in DETECTION_PATTERNS.items():
                if pattern_config["type"] == flag:
                    finding = FuzzFinding(
                        type=flag,
                        severity=pattern_config["severity"].value,
                        description=f"Potential {flag} detected with payload: {response.payload[:100]}",
                        payload=response.payload,
                        evidence=[
                            f"Status Code: {response.status_code}",
                            f"Response Length: {response.response_length}",
                            f"Response Time: {response.response_time}ms",
                        ],
                        recommendation=pattern_config["recommendation"],
                        response_id=response.id,
                    )
                    findings.append(finding)
                    break
            else:
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
