"""
MITM Attack Phases

Defines goal-oriented attack phases for the MITM agent:
- Reconnaissance: Fingerprint, enumerate, identify weaknesses
- Initial Access: Credential capture, SSL strip, session hijack
- Exploitation: Inject payloads, manipulate sessions
- Persistence: Maintain interception, continuous capture
- Escalation: Chain attacks, pivot to new targets
- Exfiltration: Extract data, document attack path
"""

import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ============================================================================
# Phase Definitions
# ============================================================================

class AttackPhase(str, Enum):
    """Attack phases for the MITM agent."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXPLOITATION = "exploitation"
    PERSISTENCE = "persistence"
    ESCALATION = "escalation"
    EXFILTRATION = "exfiltration"


@dataclass
class PhaseDefinition:
    """Definition of an attack phase with goals and success criteria."""
    phase: AttackPhase
    name: str
    description: str

    # Goals for this phase
    goals: List[str] = field(default_factory=list)

    # Success criteria (conditions that indicate phase completion)
    success_criteria: Dict[str, Any] = field(default_factory=dict)

    # Tools relevant to this phase
    relevant_tools: List[str] = field(default_factory=list)

    # Possible next phases
    next_phases: List[AttackPhase] = field(default_factory=list)

    # Minimum requirements before entering this phase
    prerequisites: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['phase'] = self.phase.value
        d['next_phases'] = [p.value for p in self.next_phases]
        return d


# Phase definitions following penetration testing methodology
PHASE_DEFINITIONS: Dict[AttackPhase, PhaseDefinition] = {
    AttackPhase.RECONNAISSANCE: PhaseDefinition(
        phase=AttackPhase.RECONNAISSANCE,
        name="Reconnaissance",
        description="Passive and active information gathering. Fingerprint target technologies, "
                    "enumerate endpoints, identify security weaknesses.",
        goals=[
            "Identify target technologies",
            "Map API endpoints",
            "Analyze security headers",
            "Discover authentication mechanisms",
            "Fingerprint web frameworks"
        ],
        success_criteria={
            "technologies_identified": 3,  # Minimum technologies to identify
            "headers_analyzed": True,
            "endpoints_discovered": 5,
            "auth_mechanism_identified": True
        },
        relevant_tools=[
            "fingerprinter",
            "header_analyzer",
            "technology_detector",
            "endpoint_enumerator",
            "auth_identifier"
        ],
        next_phases=[AttackPhase.INITIAL_ACCESS, AttackPhase.EXPLOITATION],
        prerequisites={}
    ),

    AttackPhase.INITIAL_ACCESS: PhaseDefinition(
        phase=AttackPhase.INITIAL_ACCESS,
        name="Initial Access",
        description="Gain initial foothold through credential capture, SSL stripping, "
                    "or session hijacking.",
        goals=[
            "Capture user credentials",
            "Strip SSL/TLS protection",
            "Hijack active sessions",
            "Intercept authentication tokens",
            "Bypass authentication controls"
        ],
        success_criteria={
            "credentials_captured": 1,  # At least one credential
            "session_hijacked": 1,
            "ssl_stripped": True
        },
        relevant_tools=[
            "sslstrip",
            "hsts_bypass",
            "credential_sniffer",
            "cookie_hijacker",
            "form_hijacker",
            "keylogger_advanced",
            "phishing_injector"
        ],
        next_phases=[AttackPhase.EXPLOITATION, AttackPhase.PERSISTENCE],
        prerequisites={
            "traffic_captured": True,
            "reconnaissance_complete": True
        }
    ),

    AttackPhase.EXPLOITATION: PhaseDefinition(
        phase=AttackPhase.EXPLOITATION,
        name="Exploitation",
        description="Actively exploit identified vulnerabilities through injection, "
                    "manipulation, and control bypass.",
        goals=[
            "Inject malicious scripts",
            "Manipulate session state",
            "Bypass security controls",
            "Exploit protocol weaknesses",
            "Achieve privilege escalation"
        ],
        success_criteria={
            "injection_successful": True,
            "control_bypassed": True,
            "privilege_escalated": True
        },
        relevant_tools=[
            "script_injector",
            "csp_bypass",
            "cors_manipulator",
            "x_frame_bypass",
            "jwt_manipulator",
            "api_param_tamper",
            "request_smuggling_clte",
            "request_smuggling_tecl",
            "cache_poisoning"
        ],
        next_phases=[AttackPhase.PERSISTENCE, AttackPhase.ESCALATION],
        prerequisites={
            "initial_access_gained": True
        }
    ),

    AttackPhase.PERSISTENCE: PhaseDefinition(
        phase=AttackPhase.PERSISTENCE,
        name="Persistence",
        description="Maintain access and continue intercepting traffic. Ensure stable "
                    "credential capture pipeline.",
        goals=[
            "Maintain MITM position",
            "Continuous credential capture",
            "Monitor for new sessions",
            "Persist injected payloads",
            "Evade detection"
        ],
        success_criteria={
            "traffic_flowing": True,
            "capture_active": True,
            "position_stable": True
        },
        relevant_tools=[
            "arp_spoofing",
            "dns_spoofing",
            "credential_sniffer",
            "keylogger_advanced",
            "cookie_hijacker"
        ],
        next_phases=[AttackPhase.ESCALATION, AttackPhase.EXFILTRATION],
        prerequisites={
            "exploitation_successful": True
        }
    ),

    AttackPhase.ESCALATION: PhaseDefinition(
        phase=AttackPhase.ESCALATION,
        name="Escalation",
        description="Chain attacks together and pivot to additional targets. Escalate "
                    "access and capabilities.",
        goals=[
            "Execute attack chains",
            "Pivot to new targets",
            "Escalate privileges",
            "Expand attack surface",
            "Compromise additional accounts"
        ],
        success_criteria={
            "chain_executed": True,
            "pivot_successful": True,
            "additional_access": True
        },
        relevant_tools=[
            "llmnr_poison",
            "dhcp_rogue",
            "oauth_interceptor",
            "2fa_interceptor",
            "graphql_injector",
            "websocket_hijacker"
        ],
        next_phases=[AttackPhase.EXFILTRATION],
        prerequisites={
            "persistence_achieved": True
        }
    ),

    AttackPhase.EXFILTRATION: PhaseDefinition(
        phase=AttackPhase.EXFILTRATION,
        name="Exfiltration",
        description="Extract captured data and document the complete attack path for "
                    "reporting.",
        goals=[
            "Export captured credentials",
            "Document attack timeline",
            "Generate attack narrative",
            "Map MITRE techniques used",
            "Prepare remediation recommendations"
        ],
        success_criteria={
            "data_exported": True,
            "attack_documented": True
        },
        relevant_tools=[
            "report_generator",
            "data_exporter",
            "mitre_mapper"
        ],
        next_phases=[],  # Terminal phase
        prerequisites={
            "data_captured": True
        }
    ),
}


# ============================================================================
# Phase State Tracking
# ============================================================================

@dataclass
class PhaseState:
    """Current state of a phase."""
    phase: AttackPhase
    entered_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    # Progress tracking
    goals_achieved: List[str] = field(default_factory=list)
    tools_executed: List[str] = field(default_factory=list)

    # Metrics
    credentials_captured: int = 0
    sessions_hijacked: int = 0
    injections_successful: int = 0
    findings_generated: int = 0

    # Flags
    is_complete: bool = False
    completion_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "entered_at": self.entered_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "goals_achieved": self.goals_achieved,
            "tools_executed": self.tools_executed,
            "credentials_captured": self.credentials_captured,
            "sessions_hijacked": self.sessions_hijacked,
            "injections_successful": self.injections_successful,
            "findings_generated": self.findings_generated,
            "is_complete": self.is_complete,
            "completion_reason": self.completion_reason
        }


# ============================================================================
# Phase Controller
# ============================================================================

class MITMPhaseController:
    """
    Controls attack phase progression.

    Manages phase transitions, evaluates completion criteria,
    and provides phase-appropriate tool recommendations.
    """

    def __init__(self, memory=None):
        self.memory = memory
        self.current_phase: AttackPhase = AttackPhase.RECONNAISSANCE
        self.phase_history: List[PhaseState] = []
        self.current_state: Optional[PhaseState] = None

        # Start in reconnaissance
        self._enter_phase(AttackPhase.RECONNAISSANCE)

    def _enter_phase(self, phase: AttackPhase):
        """Enter a new attack phase."""
        # Complete current phase if any
        if self.current_state and not self.current_state.is_complete:
            self.current_state.is_complete = True
            self.current_state.completed_at = datetime.utcnow()
            self.current_state.completion_reason = "phase_transition"
            self.phase_history.append(self.current_state)

        # Start new phase
        self.current_phase = phase
        self.current_state = PhaseState(phase=phase)

        logger.info(f"Entered phase: {phase.value}")

    def evaluate_phase_completion(self, metrics: Dict[str, Any]) -> bool:
        """
        Evaluate if current phase success criteria are met.

        Args:
            metrics: Current attack metrics including captured data counts
        """
        if not self.current_state:
            return False

        definition = PHASE_DEFINITIONS[self.current_phase]
        criteria = definition.success_criteria

        # Check each criterion
        criteria_met = 0
        total_criteria = len(criteria)

        for criterion, required in criteria.items():
            actual = metrics.get(criterion, 0 if isinstance(required, int) else False)

            if isinstance(required, bool):
                if actual == required:
                    criteria_met += 1
            elif isinstance(required, int):
                if actual >= required:
                    criteria_met += 1

        # Phase complete if majority of criteria met
        completion_threshold = total_criteria // 2 + 1
        is_complete = criteria_met >= completion_threshold

        if is_complete:
            self.current_state.is_complete = True
            self.current_state.completed_at = datetime.utcnow()
            self.current_state.completion_reason = f"criteria_met_{criteria_met}/{total_criteria}"

        return is_complete

    def select_next_phase(self, metrics: Dict[str, Any]) -> Optional[AttackPhase]:
        """
        AI-driven phase selection based on current state and metrics.

        Returns the recommended next phase or None if should stay.
        """
        definition = PHASE_DEFINITIONS[self.current_phase]
        possible_next = definition.next_phases

        if not possible_next:
            return None  # Terminal phase

        # Score each possible next phase
        phase_scores: Dict[AttackPhase, float] = {}

        for next_phase in possible_next:
            next_def = PHASE_DEFINITIONS[next_phase]
            score = self._score_phase_transition(next_phase, next_def, metrics)
            phase_scores[next_phase] = score

        # Select highest scoring phase above threshold
        best_phase = max(phase_scores, key=lambda p: phase_scores[p])
        if phase_scores[best_phase] >= 0.5:
            return best_phase

        return None

    def _score_phase_transition(
        self,
        phase: AttackPhase,
        definition: PhaseDefinition,
        metrics: Dict[str, Any]
    ) -> float:
        """Score a potential phase transition."""
        score = 0.0

        # Check prerequisites
        prereqs_met = 0
        for prereq, required in definition.prerequisites.items():
            if metrics.get(prereq, False) == required:
                prereqs_met += 1

        if definition.prerequisites:
            score += (prereqs_met / len(definition.prerequisites)) * 0.4

        # Bonus for logical progression
        phase_order = [
            AttackPhase.RECONNAISSANCE,
            AttackPhase.INITIAL_ACCESS,
            AttackPhase.EXPLOITATION,
            AttackPhase.PERSISTENCE,
            AttackPhase.ESCALATION,
            AttackPhase.EXFILTRATION
        ]

        current_idx = phase_order.index(self.current_phase)
        next_idx = phase_order.index(phase)

        # Prefer forward progression
        if next_idx == current_idx + 1:
            score += 0.3
        elif next_idx > current_idx:
            score += 0.2

        # Bonus if we have data suggesting this phase would be fruitful
        if phase == AttackPhase.INITIAL_ACCESS:
            if metrics.get("credentials_visible") or metrics.get("http_only_traffic"):
                score += 0.3

        elif phase == AttackPhase.EXPLOITATION:
            if metrics.get("credentials_captured", 0) > 0:
                score += 0.3

        elif phase == AttackPhase.PERSISTENCE:
            if metrics.get("injection_successful"):
                score += 0.3

        elif phase == AttackPhase.ESCALATION:
            if metrics.get("multiple_targets") or metrics.get("admin_access"):
                score += 0.3

        return min(1.0, score)

    def transition_phase(self, next_phase: AttackPhase) -> Dict[str, Any]:
        """
        Execute phase transition with logging.

        Returns transition details.
        """
        previous_phase = self.current_phase
        previous_state = self.current_state

        # Enter new phase
        self._enter_phase(next_phase)

        return {
            "previous_phase": previous_phase.value,
            "new_phase": next_phase.value,
            "transition_time": datetime.utcnow().isoformat(),
            "previous_state": previous_state.to_dict() if previous_state else None
        }

    def get_phase_relevant_tools(self) -> List[str]:
        """Get tools relevant to the current phase."""
        definition = PHASE_DEFINITIONS[self.current_phase]
        return definition.relevant_tools

    def get_current_phase_info(self) -> Dict[str, Any]:
        """Get information about the current phase."""
        definition = PHASE_DEFINITIONS[self.current_phase]

        return {
            "phase": self.current_phase.value,
            "name": definition.name,
            "description": definition.description,
            "goals": definition.goals,
            "relevant_tools": definition.relevant_tools,
            "next_phases": [p.value for p in definition.next_phases],
            "state": self.current_state.to_dict() if self.current_state else None
        }

    def record_tool_execution(self, tool_id: str, success: bool, result: Dict[str, Any]):
        """Record tool execution in current phase state."""
        if not self.current_state:
            return

        self.current_state.tools_executed.append(tool_id)

        # Update metrics from result
        if result.get("credentials_captured"):
            self.current_state.credentials_captured += len(result["credentials_captured"])

        if result.get("session_hijacked"):
            self.current_state.sessions_hijacked += 1

        if result.get("injection_successful"):
            self.current_state.injections_successful += 1

        if result.get("findings"):
            self.current_state.findings_generated += len(result["findings"])

        # Check for goal achievement
        self._check_goal_achievement(tool_id, result)

    def _check_goal_achievement(self, tool_id: str, result: Dict[str, Any]):
        """Check if any phase goals were achieved."""
        if not self.current_state:
            return

        definition = PHASE_DEFINITIONS[self.current_phase]

        # Map results to goals
        goal_triggers = {
            "Capture user credentials": result.get("credentials_captured"),
            "Hijack active sessions": result.get("session_hijacked"),
            "Inject malicious scripts": result.get("injection_successful"),
            "Bypass security controls": result.get("control_bypassed"),
            "Execute attack chains": result.get("chain_triggered"),
        }

        for goal in definition.goals:
            if goal not in self.current_state.goals_achieved:
                if goal_triggers.get(goal):
                    self.current_state.goals_achieved.append(goal)
                    logger.info(f"Goal achieved: {goal}")

    def get_phase_progress(self) -> Dict[str, Any]:
        """Get progress through current phase."""
        if not self.current_state:
            return {}

        definition = PHASE_DEFINITIONS[self.current_phase]

        return {
            "phase": self.current_phase.value,
            "goals_total": len(definition.goals),
            "goals_achieved": len(self.current_state.goals_achieved),
            "goals_achieved_list": self.current_state.goals_achieved,
            "tools_executed": len(self.current_state.tools_executed),
            "credentials_captured": self.current_state.credentials_captured,
            "sessions_hijacked": self.current_state.sessions_hijacked,
            "injections_successful": self.current_state.injections_successful,
            "findings_generated": self.current_state.findings_generated,
            "is_complete": self.current_state.is_complete
        }

    def get_phase_history(self) -> List[Dict[str, Any]]:
        """Get history of completed phases."""
        return [state.to_dict() for state in self.phase_history]

    def force_phase(self, phase: AttackPhase):
        """Force transition to a specific phase (for manual control)."""
        self._enter_phase(phase)

    def get_all_phases_status(self) -> List[Dict[str, Any]]:
        """Get status of all phases for UI display."""
        status = []

        for phase in AttackPhase:
            definition = PHASE_DEFINITIONS[phase]

            # Check if phase was completed
            completed_state = None
            for state in self.phase_history:
                if state.phase == phase:
                    completed_state = state
                    break

            # Check if current
            is_current = phase == self.current_phase

            status.append({
                "phase": phase.value,
                "name": definition.name,
                "description": definition.description,
                "is_current": is_current,
                "is_complete": completed_state is not None or (is_current and self.current_state and self.current_state.is_complete),
                "goals": definition.goals,
                "goals_achieved": self.current_state.goals_achieved if is_current else (completed_state.goals_achieved if completed_state else []),
                "entered_at": self.current_state.entered_at.isoformat() if is_current else (completed_state.entered_at.isoformat() if completed_state else None),
                "completed_at": completed_state.completed_at.isoformat() if completed_state and completed_state.completed_at else None
            })

        return status
