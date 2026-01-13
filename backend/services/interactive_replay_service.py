"""
Interactive & Replay Service for Agentic Fuzzer

Provides interactive fuzzing capabilities:
- Part 1: Interactive Step Mode - manual approval for each payload
- Part 2: Request Replay System - replay any request from history
- Part 3: Finding Verification Replay - re-verify findings
- Part 4: Breakpoints & Conditions - pause on specific events
- Part 5: Integration functions

Enables fine-grained control over fuzzing operations.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, Set
from enum import Enum
from datetime import datetime
import asyncio
import json
import logging
import aiohttp
import hashlib

logger = logging.getLogger(__name__)


# =============================================================================
# PART 1: INTERACTIVE STEP MODE
# =============================================================================

class InteractiveState(Enum):
    """States for interactive mode."""
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_APPROVAL = "waiting_approval"
    STEPPING = "stepping"
    STOPPED = "stopped"


class StepAction(Enum):
    """Actions user can take in step mode."""
    APPROVE = "approve"  # Execute this payload
    SKIP = "skip"  # Skip this payload
    MODIFY = "modify"  # Modify and execute
    APPROVE_ALL = "approve_all"  # Approve all remaining
    SKIP_SIMILAR = "skip_similar"  # Skip all similar payloads
    STOP = "stop"  # Stop the scan


@dataclass
class PendingPayload:
    """A payload waiting for user approval."""
    payload_id: str
    technique: str
    url: str
    method: str
    parameter: str
    payload: str
    headers: Dict[str, str]
    body: Optional[str]
    context: str  # Why this payload was selected
    risk_level: str  # low, medium, high
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "payload_id": self.payload_id,
            "technique": self.technique,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "headers": self.headers,
            "body": self.body,
            "context": self.context,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class InteractiveSession:
    """Manages interactive fuzzing session state."""
    session_id: str
    state: InteractiveState = InteractiveState.RUNNING
    step_mode: bool = False
    pending_payload: Optional[PendingPayload] = None
    approved_count: int = 0
    skipped_count: int = 0
    modified_count: int = 0
    skip_patterns: Set[str] = field(default_factory=set)  # Patterns to auto-skip
    approve_patterns: Set[str] = field(default_factory=set)  # Patterns to auto-approve
    breakpoints: List['Breakpoint'] = field(default_factory=list)
    action_history: List[Dict] = field(default_factory=list)
    
    # Async event for waiting on user action
    _approval_event: Optional[asyncio.Event] = field(default=None, repr=False)
    _user_action: Optional[StepAction] = None
    _modified_payload: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "step_mode": self.step_mode,
            "pending_payload": self.pending_payload.to_dict() if self.pending_payload else None,
            "stats": {
                "approved": self.approved_count,
                "skipped": self.skipped_count,
                "modified": self.modified_count,
            },
            "skip_patterns_count": len(self.skip_patterns),
            "approve_patterns_count": len(self.approve_patterns),
            "breakpoints_count": len(self.breakpoints),
        }


class InteractiveController:
    """
    Controls interactive fuzzing mode.
    
    In step mode, each payload must be approved before execution.
    Provides fine-grained control over the fuzzing process.
    """
    
    def __init__(self):
        self._sessions: Dict[str, InteractiveSession] = {}
    
    def create_session(self, session_id: str, step_mode: bool = False) -> InteractiveSession:
        """Create a new interactive session."""
        session = InteractiveSession(
            session_id=session_id,
            step_mode=step_mode,
            _approval_event=asyncio.Event() if step_mode else None,
        )
        self._sessions[session_id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[InteractiveSession]:
        """Get an interactive session."""
        return self._sessions.get(session_id)
    
    def enable_step_mode(self, session_id: str) -> bool:
        """Enable step mode for a session."""
        session = self._sessions.get(session_id)
        if session:
            session.step_mode = True
            session._approval_event = asyncio.Event()
            session.state = InteractiveState.STEPPING
            return True
        return False
    
    def disable_step_mode(self, session_id: str) -> bool:
        """Disable step mode for a session."""
        session = self._sessions.get(session_id)
        if session:
            session.step_mode = False
            session.state = InteractiveState.RUNNING
            # Release any waiting coroutine
            if session._approval_event:
                session._user_action = StepAction.APPROVE_ALL
                session._approval_event.set()
            return True
        return False
    
    async def request_approval(
        self,
        session_id: str,
        technique: str,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        context: str = "",
        risk_level: str = "medium",
        timeout: float = 300.0,  # 5 minute timeout
    ) -> tuple[bool, Optional[str]]:
        """
        Request user approval for a payload in step mode.
        
        Returns:
            Tuple of (approved: bool, modified_payload: Optional[str])
        """
        session = self._sessions.get(session_id)
        if not session or not session.step_mode:
            return True, None  # Auto-approve if not in step mode
        
        # Check auto-skip patterns
        payload_sig = f"{technique}:{parameter}:{payload[:50]}"
        if any(pattern in payload_sig for pattern in session.skip_patterns):
            session.skipped_count += 1
            return False, None
        
        # Check auto-approve patterns
        if any(pattern in payload_sig for pattern in session.approve_patterns):
            session.approved_count += 1
            return True, None
        
        # Create pending payload
        payload_id = hashlib.md5(f"{url}{parameter}{payload}{datetime.now()}".encode()).hexdigest()[:12]
        
        session.pending_payload = PendingPayload(
            payload_id=payload_id,
            technique=technique,
            url=url,
            method=method,
            parameter=parameter,
            payload=payload,
            headers=headers,
            body=body,
            context=context,
            risk_level=risk_level,
        )
        
        session.state = InteractiveState.WAITING_APPROVAL
        session._approval_event = asyncio.Event()
        session._user_action = None
        session._modified_payload = None
        
        # Wait for user action
        try:
            await asyncio.wait_for(session._approval_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            session.skipped_count += 1
            session.pending_payload = None
            session.state = InteractiveState.STEPPING
            return False, None
        
        action = session._user_action
        modified = session._modified_payload
        
        # Record action
        session.action_history.append({
            "payload_id": payload_id,
            "action": action.value if action else "timeout",
            "timestamp": datetime.now().isoformat(),
        })
        
        session.pending_payload = None
        session.state = InteractiveState.STEPPING
        
        if action == StepAction.APPROVE:
            session.approved_count += 1
            return True, None
        elif action == StepAction.MODIFY:
            session.modified_count += 1
            return True, modified
        elif action == StepAction.SKIP:
            session.skipped_count += 1
            return False, None
        elif action == StepAction.APPROVE_ALL:
            session.step_mode = False
            session.state = InteractiveState.RUNNING
            return True, None
        elif action == StepAction.SKIP_SIMILAR:
            session.skip_patterns.add(f"{technique}:{parameter}")
            session.skipped_count += 1
            return False, None
        elif action == StepAction.STOP:
            session.state = InteractiveState.STOPPED
            return False, None
        
        return False, None
    
    def submit_action(
        self,
        session_id: str,
        action: StepAction,
        modified_payload: Optional[str] = None
    ) -> bool:
        """Submit user action for pending payload."""
        session = self._sessions.get(session_id)
        if not session or session.state != InteractiveState.WAITING_APPROVAL:
            return False
        
        session._user_action = action
        session._modified_payload = modified_payload
        session._approval_event.set()
        return True
    
    def add_skip_pattern(self, session_id: str, pattern: str) -> bool:
        """Add a pattern to auto-skip."""
        session = self._sessions.get(session_id)
        if session:
            session.skip_patterns.add(pattern)
            return True
        return False
    
    def add_approve_pattern(self, session_id: str, pattern: str) -> bool:
        """Add a pattern to auto-approve."""
        session = self._sessions.get(session_id)
        if session:
            session.approve_patterns.add(pattern)
            return True
        return False
    
    def cleanup_session(self, session_id: str):
        """Clean up a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]


# =============================================================================
# PART 2: REQUEST REPLAY SYSTEM
# =============================================================================

@dataclass
class RecordedRequest:
    """A recorded HTTP request for replay."""
    request_id: str
    timestamp: datetime
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str]
    parameter: Optional[str]
    payload: Optional[str]
    technique: str
    
    # Response data
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    response_time_ms: Optional[float] = None
    
    # Analysis
    finding_detected: bool = False
    finding_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "body": self.body,
            "parameter": self.parameter,
            "payload": self.payload,
            "technique": self.technique,
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body_preview": self.response_body[:500] if self.response_body else None,
                "body_length": len(self.response_body) if self.response_body else 0,
                "time_ms": self.response_time_ms,
            },
            "finding_detected": self.finding_detected,
            "finding_id": self.finding_id,
        }


class RequestRecorder:
    """Records requests for later replay."""
    
    def __init__(self, max_requests: int = 1000):
        self._requests: Dict[str, List[RecordedRequest]] = {}  # session_id -> requests
        self._max_requests = max_requests
        self._request_counter = 0
    
    def _generate_id(self) -> str:
        """Generate unique request ID."""
        self._request_counter += 1
        return f"req_{self._request_counter}_{datetime.now().strftime('%H%M%S')}"
    
    def record(
        self,
        session_id: str,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
        parameter: Optional[str],
        payload: Optional[str],
        technique: str,
    ) -> str:
        """Record a request and return its ID."""
        if session_id not in self._requests:
            self._requests[session_id] = []
        
        request_id = self._generate_id()
        
        request = RecordedRequest(
            request_id=request_id,
            timestamp=datetime.now(),
            url=url,
            method=method,
            headers=headers.copy(),
            body=body,
            parameter=parameter,
            payload=payload,
            technique=technique,
        )
        
        self._requests[session_id].append(request)
        
        # Trim if over limit
        if len(self._requests[session_id]) > self._max_requests:
            self._requests[session_id] = self._requests[session_id][-self._max_requests:]
        
        return request_id
    
    def update_response(
        self,
        session_id: str,
        request_id: str,
        status: int,
        headers: Dict[str, str],
        body: str,
        time_ms: float,
        finding_detected: bool = False,
        finding_id: Optional[str] = None,
    ):
        """Update a recorded request with response data."""
        requests = self._requests.get(session_id, [])
        for req in requests:
            if req.request_id == request_id:
                req.response_status = status
                req.response_headers = headers
                req.response_body = body
                req.response_time_ms = time_ms
                req.finding_detected = finding_detected
                req.finding_id = finding_id
                break
    
    def get_request(self, session_id: str, request_id: str) -> Optional[RecordedRequest]:
        """Get a specific request."""
        requests = self._requests.get(session_id, [])
        for req in requests:
            if req.request_id == request_id:
                return req
        return None
    
    def get_requests(
        self,
        session_id: str,
        technique: Optional[str] = None,
        finding_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[RecordedRequest]:
        """Get recorded requests with filtering."""
        requests = self._requests.get(session_id, [])
        
        # Filter
        if technique:
            requests = [r for r in requests if r.technique == technique]
        if finding_only:
            requests = [r for r in requests if r.finding_detected]
        
        # Paginate
        return requests[offset:offset + limit]
    
    def get_session_stats(self, session_id: str) -> Dict:
        """Get statistics for a session."""
        requests = self._requests.get(session_id, [])
        
        techniques = {}
        findings = 0
        total_time = 0
        
        for req in requests:
            techniques[req.technique] = techniques.get(req.technique, 0) + 1
            if req.finding_detected:
                findings += 1
            if req.response_time_ms:
                total_time += req.response_time_ms
        
        return {
            "total_requests": len(requests),
            "findings_detected": findings,
            "by_technique": techniques,
            "avg_response_time_ms": total_time / len(requests) if requests else 0,
        }
    
    def clear_session(self, session_id: str):
        """Clear recorded requests for a session."""
        if session_id in self._requests:
            del self._requests[session_id]


class RequestReplayer:
    """Replays recorded requests."""
    
    def __init__(self, recorder: RequestRecorder):
        self._recorder = recorder
    
    async def replay_request(
        self,
        session_id: str,
        request_id: str,
        modify_headers: Optional[Dict[str, str]] = None,
        modify_body: Optional[str] = None,
        modify_payload: Optional[str] = None,
        timeout: float = 30.0,
    ) -> Dict:
        """
        Replay a recorded request.
        
        Args:
            session_id: Session ID
            request_id: Request ID to replay
            modify_headers: Headers to override
            modify_body: New body (replaces original)
            modify_payload: New payload (injected into original position)
            timeout: Request timeout
            
        Returns:
            Replay result with response
        """
        request = self._recorder.get_request(session_id, request_id)
        if not request:
            return {"error": "Request not found"}
        
        # Prepare request
        url = request.url
        method = request.method
        headers = {**request.headers, **(modify_headers or {})}
        body = modify_body if modify_body is not None else request.body
        
        # Handle payload modification
        if modify_payload and request.parameter and request.payload:
            # Replace original payload with modified one
            if body and request.payload in body:
                body = body.replace(request.payload, modify_payload)
            if request.payload in url:
                url = url.replace(request.payload, modify_payload)
        
        # Execute request
        start_time = datetime.now()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as response:
                    response_body = await response.text()
                    elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000
                    
                    return {
                        "status": "success",
                        "original_request_id": request_id,
                        "replay": {
                            "url": url,
                            "method": method,
                            "modified": bool(modify_headers or modify_body or modify_payload),
                        },
                        "response": {
                            "status": response.status,
                            "headers": dict(response.headers),
                            "body": response_body,
                            "time_ms": elapsed_ms,
                        },
                        "comparison": {
                            "status_changed": response.status != request.response_status,
                            "original_status": request.response_status,
                            "time_diff_ms": elapsed_ms - (request.response_time_ms or 0),
                        },
                    }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "original_request_id": request_id,
            }
    
    async def replay_sequence(
        self,
        session_id: str,
        request_ids: List[str],
        delay_ms: int = 100,
    ) -> List[Dict]:
        """Replay a sequence of requests."""
        results = []
        
        for request_id in request_ids:
            result = await self.replay_request(session_id, request_id)
            results.append(result)
            
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000)
        
        return results


# =============================================================================
# PART 3: FINDING VERIFICATION REPLAY
# =============================================================================

@dataclass
class VerificationResult:
    """Result of finding verification."""
    finding_id: str
    verified: bool
    confidence: float  # 0-1
    original_response: Dict
    replay_response: Dict
    analysis: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "verified": self.verified,
            "confidence": self.confidence,
            "original_response": self.original_response,
            "replay_response": self.replay_response,
            "analysis": self.analysis,
            "timestamp": self.timestamp.isoformat(),
        }


class FindingVerifier:
    """Verifies findings by replaying the original request."""
    
    def __init__(self, recorder: RequestRecorder, replayer: RequestReplayer):
        self._recorder = recorder
        self._replayer = replayer
    
    async def verify_finding(
        self,
        session_id: str,
        finding: Dict,
        attempts: int = 3,
    ) -> VerificationResult:
        """
        Verify a finding by replaying its request.
        
        Args:
            session_id: Session ID
            finding: Finding dict with request_id or url/payload info
            attempts: Number of replay attempts
            
        Returns:
            Verification result
        """
        request_id = finding.get("request_id")
        
        if not request_id:
            # Try to find by URL and payload
            requests = self._recorder.get_requests(session_id, finding_only=True)
            for req in requests:
                if req.finding_id == finding.get("id"):
                    request_id = req.request_id
                    break
        
        if not request_id:
            return VerificationResult(
                finding_id=finding.get("id", "unknown"),
                verified=False,
                confidence=0.0,
                original_response={},
                replay_response={},
                analysis="Could not find original request to replay",
            )
        
        original_request = self._recorder.get_request(session_id, request_id)
        if not original_request:
            return VerificationResult(
                finding_id=finding.get("id", "unknown"),
                verified=False,
                confidence=0.0,
                original_response={},
                replay_response={},
                analysis="Original request not found in history",
            )
        
        # Replay multiple times
        successful_replays = 0
        last_replay = None
        
        for _ in range(attempts):
            result = await self._replayer.replay_request(session_id, request_id)
            if result.get("status") == "success":
                last_replay = result
                
                # Check if vulnerability indicators still present
                if self._check_vulnerability_indicators(
                    finding.get("technique", ""),
                    original_request.response_body or "",
                    result.get("response", {}).get("body", ""),
                ):
                    successful_replays += 1
            
            await asyncio.sleep(0.5)  # Brief delay between attempts
        
        verified = successful_replays >= (attempts // 2 + 1)  # Majority must succeed
        confidence = successful_replays / attempts
        
        analysis = self._generate_analysis(
            finding.get("technique", ""),
            verified,
            confidence,
            original_request,
            last_replay,
        )
        
        return VerificationResult(
            finding_id=finding.get("id", "unknown"),
            verified=verified,
            confidence=confidence,
            original_response={
                "status": original_request.response_status,
                "body_preview": (original_request.response_body or "")[:200],
            },
            replay_response=last_replay.get("response", {}) if last_replay else {},
            analysis=analysis,
        )
    
    def _check_vulnerability_indicators(
        self,
        technique: str,
        original_body: str,
        replay_body: str,
    ) -> bool:
        """Check if vulnerability indicators are present in replay."""
        indicators = {
            "sql_injection": ["sql", "syntax", "mysql", "postgresql", "sqlite", "error"],
            "xss": ["<script", "onerror", "onload", "javascript:"],
            "command_injection": ["root:", "/bin/", "uid=", "gid="],
            "path_traversal": ["root:", "[extensions]", "passwd", "shadow"],
            "ssrf": ["internal", "127.0.0.1", "localhost", "metadata"],
        }
        
        technique_indicators = indicators.get(technique.lower().replace(" ", "_"), [])
        
        # Check if any indicator present in both original and replay
        for indicator in technique_indicators:
            if indicator.lower() in original_body.lower() and indicator.lower() in replay_body.lower():
                return True
        
        # Fallback: check similar response length (within 20%)
        if original_body and replay_body:
            ratio = len(replay_body) / len(original_body)
            if 0.8 <= ratio <= 1.2:
                return True
        
        return False
    
    def _generate_analysis(
        self,
        technique: str,
        verified: bool,
        confidence: float,
        original: RecordedRequest,
        replay: Optional[Dict],
    ) -> str:
        """Generate analysis text for verification result."""
        if not replay:
            return "Replay failed - could not connect to target"
        
        if verified:
            if confidence >= 0.9:
                return f"CONFIRMED: {technique} vulnerability consistently reproduced with {confidence*100:.0f}% confidence"
            else:
                return f"LIKELY: {technique} vulnerability reproduced in {confidence*100:.0f}% of attempts"
        else:
            if confidence > 0:
                return f"INTERMITTENT: {technique} only reproduced in {confidence*100:.0f}% of attempts - may be timing-dependent"
            else:
                return f"NOT VERIFIED: {technique} could not be reproduced - may be false positive or patched"


# =============================================================================
# PART 4: BREAKPOINTS & CONDITIONS
# =============================================================================

class BreakpointType(Enum):
    """Types of breakpoints."""
    TECHNIQUE = "technique"  # Break on specific technique
    SEVERITY = "severity"  # Break on severity level
    STATUS_CODE = "status_code"  # Break on response status
    RESPONSE_CONTAINS = "response_contains"  # Break on response content
    FINDING = "finding"  # Break on any finding
    ERROR = "error"  # Break on request error
    ITERATION = "iteration"  # Break at specific iteration


@dataclass
class Breakpoint:
    """A breakpoint condition."""
    breakpoint_id: str
    breakpoint_type: BreakpointType
    condition: str  # Type-specific condition value
    enabled: bool = True
    hit_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "breakpoint_id": self.breakpoint_id,
            "type": self.breakpoint_type.value,
            "condition": self.condition,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "created_at": self.created_at.isoformat(),
        }


class BreakpointManager:
    """Manages breakpoints for fuzzing sessions."""
    
    def __init__(self):
        self._breakpoints: Dict[str, List[Breakpoint]] = {}  # session_id -> breakpoints
        self._bp_counter = 0
    
    def _generate_id(self) -> str:
        """Generate breakpoint ID."""
        self._bp_counter += 1
        return f"bp_{self._bp_counter}"
    
    def add_breakpoint(
        self,
        session_id: str,
        bp_type: BreakpointType,
        condition: str,
    ) -> Breakpoint:
        """Add a breakpoint."""
        if session_id not in self._breakpoints:
            self._breakpoints[session_id] = []
        
        bp = Breakpoint(
            breakpoint_id=self._generate_id(),
            breakpoint_type=bp_type,
            condition=condition,
        )
        
        self._breakpoints[session_id].append(bp)
        return bp
    
    def remove_breakpoint(self, session_id: str, breakpoint_id: str) -> bool:
        """Remove a breakpoint."""
        breakpoints = self._breakpoints.get(session_id, [])
        for i, bp in enumerate(breakpoints):
            if bp.breakpoint_id == breakpoint_id:
                breakpoints.pop(i)
                return True
        return False
    
    def toggle_breakpoint(self, session_id: str, breakpoint_id: str) -> bool:
        """Toggle breakpoint enabled state."""
        breakpoints = self._breakpoints.get(session_id, [])
        for bp in breakpoints:
            if bp.breakpoint_id == breakpoint_id:
                bp.enabled = not bp.enabled
                return True
        return False
    
    def get_breakpoints(self, session_id: str) -> List[Breakpoint]:
        """Get all breakpoints for a session."""
        return self._breakpoints.get(session_id, [])
    
    def check_breakpoints(
        self,
        session_id: str,
        context: Dict,
    ) -> Optional[Breakpoint]:
        """
        Check if any breakpoint is hit.
        
        Context should contain:
        - technique: str
        - severity: str
        - status_code: int
        - response_body: str
        - finding: bool
        - error: bool
        - iteration: int
        """
        breakpoints = self._breakpoints.get(session_id, [])
        
        for bp in breakpoints:
            if not bp.enabled:
                continue
            
            hit = False
            
            if bp.breakpoint_type == BreakpointType.TECHNIQUE:
                hit = context.get("technique", "").lower() == bp.condition.lower()
            
            elif bp.breakpoint_type == BreakpointType.SEVERITY:
                hit = context.get("severity", "").lower() == bp.condition.lower()
            
            elif bp.breakpoint_type == BreakpointType.STATUS_CODE:
                hit = str(context.get("status_code", "")) == bp.condition
            
            elif bp.breakpoint_type == BreakpointType.RESPONSE_CONTAINS:
                hit = bp.condition.lower() in context.get("response_body", "").lower()
            
            elif bp.breakpoint_type == BreakpointType.FINDING:
                hit = context.get("finding", False)
            
            elif bp.breakpoint_type == BreakpointType.ERROR:
                hit = context.get("error", False)
            
            elif bp.breakpoint_type == BreakpointType.ITERATION:
                hit = context.get("iteration", 0) == int(bp.condition)
            
            if hit:
                bp.hit_count += 1
                return bp
        
        return None
    
    def clear_session(self, session_id: str):
        """Clear all breakpoints for a session."""
        if session_id in self._breakpoints:
            del self._breakpoints[session_id]


# =============================================================================
# PART 5: INTEGRATION - SINGLETONS & EXPORTS
# =============================================================================

# Singleton instances
_interactive_controller: Optional[InteractiveController] = None
_request_recorder: Optional[RequestRecorder] = None
_request_replayer: Optional[RequestReplayer] = None
_finding_verifier: Optional[FindingVerifier] = None
_breakpoint_manager: Optional[BreakpointManager] = None


def get_interactive_controller() -> InteractiveController:
    """Get singleton interactive controller."""
    global _interactive_controller
    if _interactive_controller is None:
        _interactive_controller = InteractiveController()
    return _interactive_controller


def get_request_recorder() -> RequestRecorder:
    """Get singleton request recorder."""
    global _request_recorder
    if _request_recorder is None:
        _request_recorder = RequestRecorder()
    return _request_recorder


def get_request_replayer() -> RequestReplayer:
    """Get singleton request replayer."""
    global _request_replayer
    if _request_replayer is None:
        _request_replayer = RequestReplayer(get_request_recorder())
    return _request_replayer


def get_finding_verifier() -> FindingVerifier:
    """Get singleton finding verifier."""
    global _finding_verifier
    if _finding_verifier is None:
        _finding_verifier = FindingVerifier(get_request_recorder(), get_request_replayer())
    return _finding_verifier


def get_breakpoint_manager() -> BreakpointManager:
    """Get singleton breakpoint manager."""
    global _breakpoint_manager
    if _breakpoint_manager is None:
        _breakpoint_manager = BreakpointManager()
    return _breakpoint_manager


# Module exports
__all__ = [
    # Enums
    "InteractiveState",
    "StepAction",
    "BreakpointType",
    
    # Data classes
    "PendingPayload",
    "InteractiveSession",
    "RecordedRequest",
    "VerificationResult",
    "Breakpoint",
    
    # Controllers
    "InteractiveController",
    "RequestRecorder",
    "RequestReplayer",
    "FindingVerifier",
    "BreakpointManager",
    
    # Factory functions
    "get_interactive_controller",
    "get_request_recorder",
    "get_request_replayer",
    "get_finding_verifier",
    "get_breakpoint_manager",
]
