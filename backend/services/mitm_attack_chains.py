"""
MITM Attack Chains

Defines automated attack chains that execute sequences of tools
when trigger conditions are met:
- Credential to Session: Captured creds -> session takeover
- Injection Escalation: Script injection -> full credential pipeline
- SSL Strip Capture: SSL strip -> credential capture
- Network Pivot: ARP spoof -> DNS spoof -> full network MITM
- API Exploitation: Token capture -> API abuse
- Cache Poisoning: Detect cache -> poison for persistence
"""

import asyncio
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ============================================================================
# Chain Definitions
# ============================================================================

class ChainTrigger(str, Enum):
    """Events that can trigger attack chains."""
    CREDENTIALS_CAPTURED = "credentials_captured"
    SCRIPT_INJECTION_SUCCESSFUL = "script_injection_successful"
    SSL_STRIP_SUCCESSFUL = "ssl_strip_successful"
    NETWORK_ACCESS_CONFIRMED = "network_access_confirmed"
    API_TOKEN_CAPTURED = "api_token_captured"
    CACHE_DETECTED = "cache_detected"
    SESSION_HIJACKED = "session_hijacked"
    JWT_TOKEN_CAPTURED = "jwt_token_captured"
    FORM_DETECTED = "form_detected"
    WEBSOCKET_DETECTED = "websocket_detected"
    TWO_FA_PAGE_DETECTED = "2fa_page_detected"


class ChainStatus(str, Enum):
    """Status of a chain execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # Some steps succeeded, some failed


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    step_number: int
    tool_id: str
    description: str

    # Configuration for this step
    options: Dict[str, Any] = field(default_factory=dict)

    # Conditions
    depends_on_previous: bool = True  # Only run if previous step succeeded
    required_for_chain: bool = True  # Chain fails if this step fails
    skip_on_existing: bool = False  # Skip if tool already executed

    # Verification
    verify_condition: Optional[str] = None  # Condition to verify after execution
    timeout_seconds: int = 30


@dataclass
class AttackChain:
    """Definition of an attack chain."""
    chain_id: str
    name: str
    description: str

    # What triggers this chain
    triggers: List[ChainTrigger]

    # Steps to execute
    steps: List[ChainStep]

    # Expected outcome
    expected_outcome: str

    # Metadata
    risk_level: str = "high"
    mitre_techniques: List[str] = field(default_factory=list)
    estimated_time_seconds: int = 60

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['triggers'] = [t.value for t in self.triggers]
        return d


# ============================================================================
# Chain Definitions Registry
# ============================================================================

ATTACK_CHAINS: Dict[str, AttackChain] = {
    "credential_to_session": AttackChain(
        chain_id="credential_to_session",
        name="Credential to Session Takeover",
        description="After capturing credentials, escalate to full session takeover "
                    "through cookie hijacking and persistent credential harvesting.",
        triggers=[ChainTrigger.CREDENTIALS_CAPTURED],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="cookie_hijacker",
                description="Capture session cookies from the authenticated user",
                verify_condition="cookies_captured"
            ),
            ChainStep(
                step_number=2,
                tool_id="phishing_injector",
                description="Inject fake session timeout to capture fresh credentials",
                depends_on_previous=False  # Can run in parallel
            ),
            ChainStep(
                step_number=3,
                tool_id="keylogger_advanced",
                description="Deploy keylogger for continuous credential capture",
                depends_on_previous=False
            )
        ],
        expected_outcome="Full session takeover with persistent credential capture",
        risk_level="critical",
        mitre_techniques=["T1539", "T1056.001", "T1557"]
    ),

    "injection_escalation": AttackChain(
        chain_id="injection_escalation",
        name="Injection to Credential Pipeline",
        description="After successful script injection, escalate to full credential "
                    "capture pipeline including keylogging and 2FA interception.",
        triggers=[ChainTrigger.SCRIPT_INJECTION_SUCCESSFUL],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="keylogger_advanced",
                description="Inject advanced keylogger to capture all input",
                verify_condition="keylogger_active"
            ),
            ChainStep(
                step_number=2,
                tool_id="form_hijacker",
                description="Hijack form submissions to capture credentials",
                depends_on_previous=True
            ),
            ChainStep(
                step_number=3,
                tool_id="2fa_interceptor",
                description="Deploy 2FA interceptor for MFA bypass",
                depends_on_previous=False,
                required_for_chain=False  # Optional enhancement
            )
        ],
        expected_outcome="Complete credential harvesting pipeline including 2FA bypass",
        risk_level="critical",
        mitre_techniques=["T1056.001", "T1539", "T1111"]
    ),

    "ssl_strip_capture": AttackChain(
        chain_id="ssl_strip_capture",
        name="SSL Strip to Credential Capture",
        description="After successfully stripping SSL, capture all credentials "
                    "transmitted over the downgraded HTTP connection.",
        triggers=[ChainTrigger.SSL_STRIP_SUCCESSFUL],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="credential_sniffer",
                description="Sniff credentials from HTTP traffic",
                verify_condition="sniffer_active"
            ),
            ChainStep(
                step_number=2,
                tool_id="form_hijacker",
                description="Hijack login forms to capture credentials",
                depends_on_previous=False
            ),
            ChainStep(
                step_number=3,
                tool_id="cookie_hijacker",
                description="Capture session cookies over HTTP",
                depends_on_previous=False
            )
        ],
        expected_outcome="Capture all credentials and sessions over downgraded HTTP",
        risk_level="critical",
        mitre_techniques=["T1557.002", "T1040", "T1539"]
    ),

    "network_pivot": AttackChain(
        chain_id="network_pivot",
        name="Network Pivot Attack",
        description="Establish full network MITM position through ARP spoofing, "
                    "DNS spoofing, and LLMNR poisoning.",
        triggers=[ChainTrigger.NETWORK_ACCESS_CONFIRMED],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="arp_spoofing",
                description="Establish ARP spoofing for network MITM",
                verify_condition="arp_spoof_active"
            ),
            ChainStep(
                step_number=2,
                tool_id="dns_spoofing",
                description="Set up DNS spoofing for traffic redirection",
                depends_on_previous=True
            ),
            ChainStep(
                step_number=3,
                tool_id="llmnr_poison",
                description="Deploy LLMNR/NBT-NS poisoning for Windows targets",
                depends_on_previous=False,
                required_for_chain=False  # Only on Windows networks
            )
        ],
        expected_outcome="Full network MITM position with traffic interception",
        risk_level="critical",
        mitre_techniques=["T1557.002", "T1557.001"]
    ),

    "api_exploitation": AttackChain(
        chain_id="api_exploitation",
        name="API Token Exploitation",
        description="After capturing API token, escalate access through JWT manipulation, "
                    "parameter tampering, and OAuth abuse.",
        triggers=[ChainTrigger.API_TOKEN_CAPTURED, ChainTrigger.JWT_TOKEN_CAPTURED],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="jwt_manipulator",
                description="Attempt JWT algorithm confusion and claim modification",
                verify_condition="jwt_modified"
            ),
            ChainStep(
                step_number=2,
                tool_id="api_param_tamper",
                description="Tamper with API parameters for privilege escalation",
                depends_on_previous=False
            ),
            ChainStep(
                step_number=3,
                tool_id="oauth_interceptor",
                description="Intercept OAuth flows for additional access",
                depends_on_previous=False,
                required_for_chain=False
            )
        ],
        expected_outcome="Escalated API access with privilege escalation",
        risk_level="high",
        mitre_techniques=["T1528", "T1550.001"]
    ),

    "cache_poisoning": AttackChain(
        chain_id="cache_poisoning",
        name="Cache Poisoning Persistence",
        description="After detecting cache presence, poison it to serve malicious "
                    "content to all users persistently.",
        triggers=[ChainTrigger.CACHE_DETECTED],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="request_smuggling_clte",
                description="Attempt HTTP request smuggling to bypass cache controls",
                required_for_chain=False  # Try but not required
            ),
            ChainStep(
                step_number=2,
                tool_id="cache_poisoning",
                description="Poison cache via unkeyed headers",
                verify_condition="cache_poisoned"
            ),
            ChainStep(
                step_number=3,
                tool_id="script_injector",
                description="Inject persistent XSS payload in cached response",
                depends_on_previous=True
            )
        ],
        expected_outcome="Persistent XSS affecting all users via cache poisoning",
        risk_level="critical",
        mitre_techniques=["T1190", "T1059.007"]
    ),

    "websocket_takeover": AttackChain(
        chain_id="websocket_takeover",
        name="WebSocket Session Takeover",
        description="After detecting WebSocket traffic, hijack the connection "
                    "and inject messages to take over real-time sessions.",
        triggers=[ChainTrigger.WEBSOCKET_DETECTED],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="websocket_hijacker",
                description="Intercept and hijack WebSocket connection",
                verify_condition="websocket_intercepted"
            ),
            ChainStep(
                step_number=2,
                tool_id="graphql_injector",
                description="Inject malicious GraphQL queries if applicable",
                depends_on_previous=True,
                required_for_chain=False
            )
        ],
        expected_outcome="WebSocket session hijacked with message injection capability",
        risk_level="high",
        mitre_techniques=["T1557"]
    ),

    "mfa_bypass": AttackChain(
        chain_id="mfa_bypass",
        name="MFA Bypass Chain",
        description="When 2FA page is detected and credentials are captured, "
                    "intercept the 2FA code for complete authentication bypass.",
        triggers=[ChainTrigger.TWO_FA_PAGE_DETECTED],
        steps=[
            ChainStep(
                step_number=1,
                tool_id="2fa_interceptor",
                description="Deploy 2FA code interceptor",
                verify_condition="2fa_interceptor_active"
            ),
            ChainStep(
                step_number=2,
                tool_id="phishing_injector",
                description="Inject fake 2FA prompt for real-time capture",
                depends_on_previous=False,
                required_for_chain=False
            )
        ],
        expected_outcome="2FA codes captured for complete authentication bypass",
        risk_level="critical",
        mitre_techniques=["T1111", "T1539"]
    ),
}


# ============================================================================
# Chain Execution State
# ============================================================================

@dataclass
class ChainExecutionState:
    """State of a chain execution."""
    chain_id: str
    execution_id: str
    status: ChainStatus = ChainStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Step tracking
    current_step: int = 0
    steps_completed: List[int] = field(default_factory=list)
    steps_failed: List[int] = field(default_factory=list)
    steps_skipped: List[int] = field(default_factory=list)

    # Results
    step_results: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    total_findings: int = 0
    total_credentials: int = 0

    # Trigger info
    triggered_by: str = ""
    trigger_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "execution_id": self.execution_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "current_step": self.current_step,
            "steps_completed": self.steps_completed,
            "steps_failed": self.steps_failed,
            "steps_skipped": self.steps_skipped,
            "step_results": self.step_results,
            "total_findings": self.total_findings,
            "total_credentials": self.total_credentials,
            "triggered_by": self.triggered_by,
            "trigger_data": self.trigger_data
        }


# ============================================================================
# Chain Executor
# ============================================================================

class MITMChainExecutor:
    """
    Executes attack chains when trigger conditions are met.

    Monitors events, checks chain triggers, and executes
    chains with verification between steps.
    """

    def __init__(self, tool_executor=None, memory=None):
        """
        Args:
            tool_executor: The tool executor service for running individual tools
            memory: The agent memory for recording outcomes
        """
        self.tool_executor = tool_executor
        self.memory = memory

        # Event subscriptions
        self.event_handlers: Dict[str, List[Callable]] = {}

        # Active chains
        self.active_executions: Dict[str, ChainExecutionState] = {}
        self.execution_history: List[ChainExecutionState] = []

        # Tools already executed (to avoid duplicates)
        self.executed_tools: Set[str] = set()

        # Register triggers
        self._register_chain_triggers()

    def _register_chain_triggers(self):
        """Register event handlers for chain triggers."""
        for chain_id, chain in ATTACK_CHAINS.items():
            for trigger in chain.triggers:
                if trigger.value not in self.event_handlers:
                    self.event_handlers[trigger.value] = []
                self.event_handlers[trigger.value].append(
                    lambda event_data, cid=chain_id: self._on_trigger(cid, event_data)
                )

    def emit_event(self, event_type: str, event_data: Dict[str, Any]):
        """
        Emit an event that may trigger attack chains.

        Call this when significant events occur (credential capture, etc.)
        """
        logger.info(f"Event emitted: {event_type}")

        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                handler(event_data)
            except Exception as e:
                logger.error(f"Chain trigger handler error: {e}")

    def _on_trigger(self, chain_id: str, event_data: Dict[str, Any]):
        """Handle a chain trigger event."""
        # Check if chain is already running
        if chain_id in self.active_executions:
            logger.debug(f"Chain {chain_id} already executing, skipping")
            return

        # Queue chain for execution
        asyncio.create_task(self.execute_chain(chain_id, event_data))

    def check_chain_triggers(self, metrics: Dict[str, Any]) -> List[str]:
        """
        Check which chains should be triggered based on current metrics.

        Returns list of chain_ids that should be executed.
        """
        chains_to_trigger = []

        for chain_id, chain in ATTACK_CHAINS.items():
            # Skip if already running
            if chain_id in self.active_executions:
                continue

            # Check each trigger
            for trigger in chain.triggers:
                trigger_value = trigger.value

                # Map trigger to metric
                should_trigger = False

                if trigger_value == "credentials_captured":
                    should_trigger = metrics.get("credentials_captured", 0) > 0

                elif trigger_value == "script_injection_successful":
                    should_trigger = metrics.get("injection_successful", False)

                elif trigger_value == "ssl_strip_successful":
                    should_trigger = metrics.get("ssl_stripped", False)

                elif trigger_value == "network_access_confirmed":
                    should_trigger = metrics.get("network_access", False)

                elif trigger_value == "api_token_captured":
                    should_trigger = metrics.get("api_tokens_captured", 0) > 0

                elif trigger_value == "jwt_token_captured":
                    should_trigger = metrics.get("jwt_tokens_captured", 0) > 0

                elif trigger_value == "cache_detected":
                    should_trigger = metrics.get("cache_headers_present", False)

                elif trigger_value == "session_hijacked":
                    should_trigger = metrics.get("sessions_hijacked", 0) > 0

                elif trigger_value == "websocket_detected":
                    should_trigger = metrics.get("websocket_traffic", False)

                elif trigger_value == "2fa_page_detected":
                    should_trigger = metrics.get("2fa_page_detected", False)

                elif trigger_value == "form_detected":
                    should_trigger = metrics.get("forms_detected", 0) > 0

                if should_trigger:
                    chains_to_trigger.append(chain_id)
                    break  # Only trigger once per chain

        return chains_to_trigger

    async def execute_chain(
        self,
        chain_id: str,
        trigger_data: Optional[Dict[str, Any]] = None
    ) -> ChainExecutionState:
        """
        Execute an attack chain.

        Args:
            chain_id: ID of the chain to execute
            trigger_data: Data from the triggering event
        """
        chain = ATTACK_CHAINS.get(chain_id)
        if not chain:
            raise ValueError(f"Unknown chain: {chain_id}")

        # Create execution state
        import uuid
        execution = ChainExecutionState(
            chain_id=chain_id,
            execution_id=str(uuid.uuid4()),
            status=ChainStatus.RUNNING,
            started_at=datetime.utcnow(),
            triggered_by=trigger_data.get("trigger_type", "manual") if trigger_data else "manual",
            trigger_data=trigger_data or {}
        )

        self.active_executions[chain_id] = execution

        logger.info(f"Starting chain execution: {chain.name} ({chain_id})")

        try:
            # Execute steps
            for step in chain.steps:
                execution.current_step = step.step_number

                # Check if should skip
                if step.skip_on_existing and step.tool_id in self.executed_tools:
                    execution.steps_skipped.append(step.step_number)
                    logger.info(f"Skipping step {step.step_number}: {step.tool_id} (already executed)")
                    continue

                # Check dependencies
                if step.depends_on_previous and step.step_number > 1:
                    prev_step = step.step_number - 1
                    if prev_step in execution.steps_failed:
                        execution.steps_skipped.append(step.step_number)
                        logger.info(f"Skipping step {step.step_number}: dependency failed")
                        continue

                # Execute step
                logger.info(f"Executing chain step {step.step_number}: {step.tool_id}")
                result = await self._execute_step(step, trigger_data)

                execution.step_results[step.step_number] = result

                if result.get("success"):
                    execution.steps_completed.append(step.step_number)
                    self.executed_tools.add(step.tool_id)

                    # Accumulate findings
                    execution.total_findings += len(result.get("findings", []))
                    execution.total_credentials += len(result.get("credentials_captured", []))

                    # Verify condition if specified
                    if step.verify_condition:
                        if not await self._verify_condition(step.verify_condition, result):
                            logger.warning(f"Step verification failed: {step.verify_condition}")
                else:
                    execution.steps_failed.append(step.step_number)

                    if step.required_for_chain:
                        logger.warning(f"Required step failed, aborting chain: {step.tool_id}")
                        execution.status = ChainStatus.FAILED
                        break

            # Determine final status
            if execution.status != ChainStatus.FAILED:
                if execution.steps_failed:
                    execution.status = ChainStatus.PARTIAL
                else:
                    execution.status = ChainStatus.COMPLETED

            execution.completed_at = datetime.utcnow()

        except Exception as e:
            logger.error(f"Chain execution error: {e}")
            execution.status = ChainStatus.FAILED
            execution.completed_at = datetime.utcnow()

        finally:
            # Clean up
            del self.active_executions[chain_id]
            self.execution_history.append(execution)

        logger.info(f"Chain {chain_id} completed with status: {execution.status.value}")
        return execution

    async def _execute_step(
        self,
        step: ChainStep,
        trigger_data: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Execute a single chain step."""
        if not self.tool_executor:
            # Simulate execution if no executor
            logger.warning(f"No tool executor configured, simulating step: {step.tool_id}")
            await asyncio.sleep(0.5)  # Simulate execution time
            return {
                "success": True,
                "tool_id": step.tool_id,
                "simulated": True,
                "findings": [],
                "credentials_captured": []
            }

        try:
            # Execute tool
            result = await asyncio.wait_for(
                self.tool_executor.execute_tool(
                    step.tool_id,
                    step.options,
                    trigger_data
                ),
                timeout=step.timeout_seconds
            )
            return result

        except asyncio.TimeoutError:
            return {
                "success": False,
                "tool_id": step.tool_id,
                "error": "Step execution timed out"
            }
        except Exception as e:
            return {
                "success": False,
                "tool_id": step.tool_id,
                "error": str(e)
            }

    async def _verify_condition(
        self,
        condition: str,
        result: Dict[str, Any]
    ) -> bool:
        """Verify a condition after step execution."""
        # Simple condition checking based on result
        if condition in result:
            return bool(result[condition])

        # Check for standard success indicators
        if condition == "cookies_captured":
            return len(result.get("cookies_captured", [])) > 0

        if condition == "sniffer_active":
            return result.get("monitoring_started", False)

        if condition == "keylogger_active":
            return result.get("injection_successful", False)

        if condition == "arp_spoof_active":
            return result.get("spoofing_active", False)

        if condition == "websocket_intercepted":
            return result.get("websocket_hooked", False)

        if condition == "2fa_interceptor_active":
            return result.get("interceptor_deployed", False)

        if condition == "jwt_modified":
            return result.get("token_modified", False)

        if condition == "cache_poisoned":
            return result.get("cache_poisoned", False)

        # Default: check if successful
        return result.get("success", False)

    def get_available_chains(self) -> List[Dict[str, Any]]:
        """Get all available attack chains."""
        return [chain.to_dict() for chain in ATTACK_CHAINS.values()]

    def get_chain_info(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific chain."""
        chain = ATTACK_CHAINS.get(chain_id)
        if chain:
            return chain.to_dict()
        return None

    def get_active_executions(self) -> List[Dict[str, Any]]:
        """Get currently executing chains."""
        return [exec.to_dict() for exec in self.active_executions.values()]

    def get_execution_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get history of chain executions."""
        return [exec.to_dict() for exec in self.execution_history[-limit:]]

    def get_chain_stats(self) -> Dict[str, Any]:
        """Get statistics about chain executions."""
        completed = [e for e in self.execution_history if e.status == ChainStatus.COMPLETED]
        failed = [e for e in self.execution_history if e.status == ChainStatus.FAILED]
        partial = [e for e in self.execution_history if e.status == ChainStatus.PARTIAL]

        return {
            "total_executions": len(self.execution_history),
            "completed": len(completed),
            "failed": len(failed),
            "partial": len(partial),
            "currently_active": len(self.active_executions),
            "total_findings": sum(e.total_findings for e in self.execution_history),
            "total_credentials": sum(e.total_credentials for e in self.execution_history),
            "most_triggered_chains": self._get_most_triggered_chains()
        }

    def _get_most_triggered_chains(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """Get most frequently triggered chains."""
        chain_counts: Dict[str, int] = {}

        for exec in self.execution_history:
            chain_counts[exec.chain_id] = chain_counts.get(exec.chain_id, 0) + 1

        sorted_chains = sorted(
            chain_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]

        return [
            {"chain_id": cid, "count": count}
            for cid, count in sorted_chains
        ]
