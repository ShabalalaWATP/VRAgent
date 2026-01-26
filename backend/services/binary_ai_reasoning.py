"""
Binary AI Reasoning Engine

AI-powered decision making for autonomous binary fuzzing campaigns.
Uses LLM for campaign planning, strategy selection, and crash analysis.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
import hashlib

from backend.core.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================

class FuzzingStrategy(str, Enum):
    """Available fuzzing strategies."""
    COVERAGE_GUIDED = "coverage_guided"
    DIRECTED = "directed_fuzzing"
    CONCOLIC = "concolic_execution"
    GRAMMAR_BASED = "grammar_based"
    PROTOCOL = "protocol_fuzzing"
    DIFFERENTIAL = "differential"
    EXPLOIT_ORIENTED = "exploit_oriented"
    HYBRID = "hybrid"


class DecisionType(str, Enum):
    """Types of AI decisions."""
    # Strategy decisions
    SWITCH_STRATEGY = "switch_strategy"
    ENABLE_CONCOLIC = "enable_concolic"
    ENABLE_TAINT = "enable_taint"

    # Mutation decisions
    ADJUST_MUTATION_WEIGHTS = "adjust_mutations"
    ADD_DICTIONARY = "add_dictionary"
    FOCUS_BYTE_RANGE = "focus_bytes"

    # Seed decisions
    GENERATE_SEEDS = "generate_seeds"
    IMPORT_SEEDS = "import_seeds"
    MINIMIZE_CORPUS = "minimize_corpus"
    SPLICE_INTERESTING = "splice_interesting"

    # Targeting decisions
    FOCUS_FUNCTION = "focus_function"
    AVOID_FUNCTION = "avoid_function"
    DIRECTED_FUZZING = "directed_fuzzing"

    # Resource decisions
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    REBALANCE = "rebalance"

    # Crash handling
    TRIAGE_CRASH = "triage_crash"
    PRIORITIZE_CRASH = "prioritize_crash"
    REPRODUCE_CRASH = "reproduce_crash"
    GENERATE_EXPLOIT = "generate_exploit"

    # Campaign control
    CHECKPOINT = "checkpoint"
    PAUSE = "pause"
    RESUME = "resume"
    TERMINATE = "terminate"
    CONTINUE = "continue"


class ExploitabilityScore(str, Enum):
    """Crash exploitability assessment."""
    EXPLOITABLE = "exploitable"
    PROBABLY_EXPLOITABLE = "probably_exploitable"
    PROBABLY_NOT = "probably_not_exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    UNKNOWN = "unknown"


class TrendDirection(str, Enum):
    """Trend direction for metrics."""
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"
    PLATEAU = "plateau"


class CrashType(str, Enum):
    """Types of crashes."""
    SEGFAULT = "segmentation_fault"
    STACK_OVERFLOW = "stack_buffer_overflow"
    HEAP_OVERFLOW = "heap_buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_DEREF = "null_pointer_dereference"
    DIV_ZERO = "divide_by_zero"
    INT_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    ASSERTION = "assertion_failure"
    ABORT = "abort"
    TIMEOUT = "timeout"
    OOM = "out_of_memory"
    UNKNOWN = "unknown"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class SecurityFeatures:
    """Binary security features."""
    aslr: bool = False
    dep_nx: bool = False
    stack_canary: bool = False
    relro: str = "none"  # none, partial, full
    pie: bool = False
    fortify: bool = False
    cfi: bool = False
    safe_seh: bool = False  # Windows
    authenticode: bool = False  # Windows


@dataclass
class FunctionInfo:
    """Information about a function in the binary."""
    name: str
    address: int
    size: int
    is_imported: bool = False
    is_exported: bool = False
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    complexity: int = 0
    has_loops: bool = False
    dangerous_calls: List[str] = field(default_factory=list)


@dataclass
class InputHandler:
    """Identified input handling function."""
    function_name: str
    input_type: str  # file, stdin, network, argv, env
    address: int
    confidence: float
    related_functions: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityHint:
    """Potential vulnerability pattern detected."""
    type: str
    location: str
    confidence: float
    description: str
    dangerous_function: Optional[str] = None


@dataclass
class AttackSurface:
    """Identified attack surface."""
    name: str
    entry_point: str
    input_type: str
    priority: int  # 1-10
    description: str
    functions_involved: List[str] = field(default_factory=list)


@dataclass
class InputFormatGuess:
    """AI-inferred input format."""
    format_type: str  # binary, text, json, xml, custom
    confidence: float
    structure_hints: List[str] = field(default_factory=list)
    magic_bytes: Optional[bytes] = None
    suggested_grammar: Optional[Dict[str, Any]] = None


@dataclass
class BinaryProfile:
    """Complete binary analysis profile."""
    # Basic info
    file_path: str
    file_hash: str
    file_type: str
    architecture: str
    bits: int
    endianness: str
    file_size: int

    # Security
    protections: SecurityFeatures

    # Static analysis
    entry_point: int
    imports: List[str]
    exports: List[str]
    strings_of_interest: List[str]
    sections: List[Dict[str, Any]]

    # Functions
    function_count: int
    functions: List[FunctionInfo] = field(default_factory=list)

    # AI-enhanced
    input_handlers: List[InputHandler] = field(default_factory=list)
    vulnerability_hints: List[VulnerabilityHint] = field(default_factory=list)
    attack_surfaces: List[AttackSurface] = field(default_factory=list)
    input_format_guess: Optional[InputFormatGuess] = None
    attack_surface_score: float = 0.0

    # Analysis metadata
    analysis_time_sec: float = 0.0
    ai_analysis_complete: bool = False


@dataclass
class SeedSuggestion:
    """AI-suggested seed input."""
    content: bytes
    rationale: str
    target_path: Optional[str] = None
    expected_coverage: Optional[str] = None
    format_type: str = "binary"


@dataclass
class SeedPlan:
    """Plan for seed generation."""
    initial_seeds: List[SeedSuggestion]
    dictionary_tokens: List[bytes]
    format_template: Optional[Dict[str, Any]] = None
    generation_strategy: str = "format_aware"


@dataclass
class ResourcePlan:
    """Resource allocation plan."""
    cpu_cores: int
    memory_mb: int
    timeout_per_exec_ms: int
    max_input_size: int
    parallel_instances: int


@dataclass
class SuccessCriteria:
    """Campaign success criteria."""
    min_coverage_pct: float = 70.0
    max_duration_hours: float = 24.0
    target_crashes: int = 0  # 0 = any
    target_exploitable: int = 0
    coverage_plateau_hours: float = 2.0


@dataclass
class Checkpoint:
    """Campaign checkpoint for strategy changes."""
    time_hours: float
    coverage_threshold: float
    check_type: str  # time, coverage, crashes


@dataclass
class RiskAssessment:
    """Risk assessment for campaign."""
    crash_likelihood: float  # 0-1
    hang_likelihood: float
    resource_exhaustion_risk: float
    estimated_difficulty: str  # easy, medium, hard


@dataclass
class CampaignPlan:
    """AI-generated campaign plan."""
    plan_id: str
    binary_profile: BinaryProfile

    # Strategy
    initial_strategy: FuzzingStrategy
    attack_surfaces: List[AttackSurface]

    # Seeds
    seed_plan: SeedPlan

    # Resources
    resource_plan: ResourcePlan

    # Goals
    success_criteria: SuccessCriteria
    checkpoints: List[Checkpoint]

    # Estimates
    estimated_duration_hours: float
    risk_assessment: RiskAssessment

    # AI reasoning
    reasoning: str
    confidence: float

    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CampaignState:
    """Current state of a fuzzing campaign."""
    campaign_id: str
    status: str  # planning, running, paused, completed
    current_strategy: FuzzingStrategy

    # Metrics
    total_executions: int
    executions_per_second: float
    coverage_percentage: float
    corpus_size: int

    # Crashes
    total_crashes: int
    unique_crashes: int
    exploitable_crashes: int

    # Time
    started_at: datetime
    elapsed_hours: float

    # Trends
    coverage_trend: TrendDirection
    crash_trend: TrendDirection

    # History
    recent_coverage: List[float] = field(default_factory=list)  # Last N samples
    recent_crashes: int = 0  # Crashes in last hour


@dataclass
class Decision:
    """An AI decision."""
    decision_id: str
    decision_type: DecisionType
    parameters: Dict[str, Any]
    reasoning: str
    confidence: float

    # Context
    campaign_state_snapshot: Optional[Dict[str, Any]] = None

    # Outcome tracking
    executed: bool = False
    outcome: Optional[str] = None  # effective, ineffective, pending

    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class StrategyDecision:
    """Decision about strategy change."""
    should_change: bool
    current_strategy: FuzzingStrategy
    new_strategy: Optional[FuzzingStrategy]
    reasoning: str
    confidence: float
    supporting_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CoverageAdvice:
    """AI advice on coverage improvement."""
    current_coverage: float
    coverage_trend: TrendDirection

    # Insights
    uncovered_interesting: List[str]
    blocking_constraints: List[str]
    recommended_inputs: List[SeedSuggestion]

    # Recommendations
    mutation_adjustments: Dict[str, float]
    should_switch_strategy: bool
    recommended_strategy: Optional[FuzzingStrategy]

    reasoning: str
    confidence: float


# =============================================================================
# AI Client (Updated for google.genai SDK - Jan 2026)
# =============================================================================

class BinaryAIClient:
    """
    Client for AI model interactions using the google.genai SDK.

    Uses Gemini 3 Flash for fast, intelligent fuzzing decisions.
    API Reference: https://ai.google.dev/gemini-api/docs/models/gemini-v3
    """

    def __init__(self, model: str = "gemini-3-flash-preview"):
        """
        Initialize the AI client.

        Args:
            model: Model to use. Options:
                - "gemini-3-flash-preview" (fast, recommended for fuzzing)
                - "gemini-3-pro-preview" (more capable, slower)
        """
        self.model = model
        self._client = None

    def _get_client(self):
        """Get or create Gemini client using google.genai SDK."""
        if self._client is None:
            try:
                from google import genai

                # Initialize client with API key from settings
                if settings.gemini_api_key:
                    self._client = genai.Client(api_key=settings.gemini_api_key)
                else:
                    # Will use GOOGLE_API_KEY environment variable
                    self._client = genai.Client()

                logger.info(f"Initialized Gemini client with model: {self.model}")
            except ImportError:
                logger.error("google-genai package not installed. Run: pip install google-genai")
                raise
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
                raise
        return self._client

    async def generate(self, prompt: str, json_response: bool = True) -> Dict[str, Any]:
        """
        Generate AI response using Gemini 3.

        Args:
            prompt: The prompt to send to the model
            json_response: If True, parse response as JSON

        Returns:
            Dict containing the response or error
        """
        try:
            client = self._get_client()

            if json_response:
                prompt += "\n\nRespond ONLY with valid JSON, no markdown or explanation."

            # Use the async API (client.aio.models.generate_content)
            # For simpler tasks, use thinking_level="low" for faster responses
            from google.genai import types

            response = await client.aio.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="low")
                ),
            )

            text = response.text.strip() if response.text else ""

            if json_response:
                # Extract JSON from response
                text = self._extract_json(text)
                return json.loads(text)

            return {"text": text}

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            return {"error": f"JSON parse error: {str(e)}"}
        except Exception as e:
            logger.error(f"AI generation failed: {e}")
            return {"error": str(e)}

    def generate_sync(self, prompt: str, json_response: bool = True) -> Dict[str, Any]:
        """
        Synchronous version of generate for non-async contexts.
        """
        try:
            client = self._get_client()

            if json_response:
                prompt += "\n\nRespond ONLY with valid JSON, no markdown or explanation."

            from google.genai import types

            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="low")
                ),
            )

            text = response.text.strip() if response.text else ""

            if json_response:
                text = self._extract_json(text)
                return json.loads(text)

            return {"text": text}

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            return {"error": f"JSON parse error: {str(e)}"}
        except Exception as e:
            logger.error(f"AI generation failed: {e}")
            return {"error": str(e)}

    def _extract_json(self, text: str) -> str:
        """Extract JSON from text that might have markdown."""
        # Remove markdown code blocks
        if "```json" in text:
            match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
            if match:
                return match.group(1)
        if "```" in text:
            match = re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
            if match:
                return match.group(1)
        return text


# =============================================================================
# Campaign Planner
# =============================================================================

class CampaignPlanner:
    """AI-driven campaign planning."""

    def __init__(self, ai_client=None):
        # Use provided client or create new one
        self.ai_client = ai_client if ai_client else BinaryAIClient()

    async def create_plan(
        self,
        profile: BinaryProfile,
        config: Optional[Dict[str, Any]] = None,
    ) -> CampaignPlan:
        """Create a comprehensive fuzzing campaign plan."""
        config = config or {}

        prompt = self._build_planning_prompt(profile, config)
        response = await self.ai_client.generate(prompt)

        if "error" in response:
            # Fallback to heuristic planning
            return self._heuristic_plan(profile, config)

        return self._parse_plan_response(response, profile, config)

    def _build_planning_prompt(self, profile: BinaryProfile, config: Dict[str, Any]) -> str:
        """Build the campaign planning prompt."""
        return f"""You are an expert binary security researcher. Analyze this binary and create a fuzzing campaign plan.

Binary Information:
- File: {profile.file_path}
- Type: {profile.file_type} ({profile.architecture}, {profile.bits}-bit)
- Size: {profile.file_size} bytes
- Entry Point: {hex(profile.entry_point)}

Imports ({len(profile.imports)} total):
{chr(10).join(f'  - {imp}' for imp in profile.imports[:30])}
{'  ... and more' if len(profile.imports) > 30 else ''}

Exports ({len(profile.exports)} total):
{chr(10).join(f'  - {exp}' for exp in profile.exports[:20])}

Interesting Strings:
{chr(10).join(f'  - {s}' for s in profile.strings_of_interest[:20])}

Security Features:
- ASLR: {profile.protections.aslr}
- DEP/NX: {profile.protections.dep_nx}
- Stack Canary: {profile.protections.stack_canary}
- RELRO: {profile.protections.relro}
- PIE: {profile.protections.pie}

Static Analysis:
- Functions: {profile.function_count}
- Input handlers detected: {len(profile.input_handlers)}
- Vulnerability hints: {len(profile.vulnerability_hints)}
- Attack surface score: {profile.attack_surface_score:.2f}

User Configuration:
- Max duration: {config.get('max_duration_hours', 24)} hours
- Target coverage: {config.get('target_coverage', 70)}%
- CPU cores available: {config.get('cpu_cores', 4)}

Create a comprehensive fuzzing campaign plan including:

1. attack_surfaces: Top 5 attack surfaces to target (name, entry_point, input_type, priority 1-10, description)

2. initial_strategy: One of [coverage_guided, directed_fuzzing, concolic_execution, grammar_based, protocol_fuzzing, hybrid]

3. seed_generation:
   - format_type: Detected input format (binary, text, json, xml, custom)
   - initial_seeds: 3-5 seed descriptions (content_description, rationale, format)
   - dictionary_tokens: 5-10 useful tokens/strings found

4. resource_allocation:
   - parallel_instances: Number of parallel fuzzers
   - timeout_per_exec_ms: Execution timeout
   - max_input_size: Maximum input size in bytes

5. success_criteria:
   - min_coverage_pct: Target coverage percentage
   - coverage_plateau_hours: Hours of no progress before strategy change

6. checkpoints: Decision points (time_hours, coverage_threshold, check_type)

7. estimated_duration_hours: Realistic estimate

8. risk_assessment:
   - crash_likelihood: 0-1
   - hang_likelihood: 0-1
   - estimated_difficulty: easy/medium/hard

9. reasoning: Explain your strategic choices

10. confidence: Your confidence in this plan (0-1)

Respond in JSON format."""

    def _parse_plan_response(
        self,
        response: Dict[str, Any],
        profile: BinaryProfile,
        config: Dict[str, Any],
    ) -> CampaignPlan:
        """Parse AI response into CampaignPlan."""
        plan_id = hashlib.md5(f"{profile.file_hash}:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]

        # Parse attack surfaces
        attack_surfaces = []
        for surface in response.get("attack_surfaces", []):
            attack_surfaces.append(AttackSurface(
                name=surface.get("name", "unknown"),
                entry_point=surface.get("entry_point", ""),
                input_type=surface.get("input_type", "unknown"),
                priority=surface.get("priority", 5),
                description=surface.get("description", ""),
            ))

        # Parse strategy
        strategy_str = response.get("initial_strategy", "coverage_guided")
        try:
            initial_strategy = FuzzingStrategy(strategy_str)
        except ValueError:
            initial_strategy = FuzzingStrategy.COVERAGE_GUIDED

        # Parse seed plan
        seed_gen = response.get("seed_generation", {})
        seed_plan = SeedPlan(
            initial_seeds=[
                SeedSuggestion(
                    content=b"",  # Actual content generated later
                    rationale=seed.get("rationale", ""),
                    format_type=seed.get("format", "binary"),
                )
                for seed in seed_gen.get("initial_seeds", [])
            ],
            dictionary_tokens=[
                token.encode() if isinstance(token, str) else token
                for token in seed_gen.get("dictionary_tokens", [])
            ],
        )

        # Parse resource plan
        res = response.get("resource_allocation", {})
        resource_plan = ResourcePlan(
            cpu_cores=config.get("cpu_cores", 4),
            memory_mb=config.get("memory_mb", 4096),
            timeout_per_exec_ms=res.get("timeout_per_exec_ms", 1000),
            max_input_size=res.get("max_input_size", 1024 * 1024),
            parallel_instances=res.get("parallel_instances", 4),
        )

        # Parse success criteria
        criteria = response.get("success_criteria", {})
        success_criteria = SuccessCriteria(
            min_coverage_pct=criteria.get("min_coverage_pct", 70.0),
            max_duration_hours=config.get("max_duration_hours", 24.0),
            coverage_plateau_hours=criteria.get("coverage_plateau_hours", 2.0),
        )

        # Parse checkpoints
        checkpoints = [
            Checkpoint(
                time_hours=cp.get("time_hours", 1.0),
                coverage_threshold=cp.get("coverage_threshold", 0.0),
                check_type=cp.get("check_type", "time"),
            )
            for cp in response.get("checkpoints", [])
        ]

        # Parse risk assessment
        risk = response.get("risk_assessment", {})
        risk_assessment = RiskAssessment(
            crash_likelihood=risk.get("crash_likelihood", 0.5),
            hang_likelihood=risk.get("hang_likelihood", 0.2),
            resource_exhaustion_risk=risk.get("resource_exhaustion_risk", 0.1),
            estimated_difficulty=risk.get("estimated_difficulty", "medium"),
        )

        return CampaignPlan(
            plan_id=plan_id,
            binary_profile=profile,
            initial_strategy=initial_strategy,
            attack_surfaces=attack_surfaces,
            seed_plan=seed_plan,
            resource_plan=resource_plan,
            success_criteria=success_criteria,
            checkpoints=checkpoints,
            estimated_duration_hours=response.get("estimated_duration_hours", 24.0),
            risk_assessment=risk_assessment,
            reasoning=response.get("reasoning", "AI-generated plan"),
            confidence=response.get("confidence", 0.7),
        )

    def _heuristic_plan(self, profile: BinaryProfile, config: Dict[str, Any]) -> CampaignPlan:
        """Fallback heuristic-based planning."""
        plan_id = hashlib.md5(f"{profile.file_hash}:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]

        # Determine strategy based on binary characteristics
        if any("network" in imp.lower() or "socket" in imp.lower() for imp in profile.imports):
            strategy = FuzzingStrategy.PROTOCOL
        elif any("parse" in imp.lower() or "xml" in imp.lower() or "json" in imp.lower() for imp in profile.imports):
            strategy = FuzzingStrategy.GRAMMAR_BASED
        else:
            strategy = FuzzingStrategy.COVERAGE_GUIDED

        return CampaignPlan(
            plan_id=plan_id,
            binary_profile=profile,
            initial_strategy=strategy,
            attack_surfaces=[
                AttackSurface(
                    name="main_entry",
                    entry_point=hex(profile.entry_point),
                    input_type="stdin",
                    priority=5,
                    description="Main entry point",
                )
            ],
            seed_plan=SeedPlan(
                initial_seeds=[SeedSuggestion(content=b"test", rationale="Basic test input")],
                dictionary_tokens=[],
            ),
            resource_plan=ResourcePlan(
                cpu_cores=config.get("cpu_cores", 4),
                memory_mb=4096,
                timeout_per_exec_ms=1000,
                max_input_size=1024 * 1024,
                parallel_instances=4,
            ),
            success_criteria=SuccessCriteria(),
            checkpoints=[Checkpoint(time_hours=1.0, coverage_threshold=0, check_type="time")],
            estimated_duration_hours=24.0,
            risk_assessment=RiskAssessment(
                crash_likelihood=0.5,
                hang_likelihood=0.2,
                resource_exhaustion_risk=0.1,
                estimated_difficulty="medium",
            ),
            reasoning="Heuristic-based plan (AI unavailable)",
            confidence=0.5,
        )


# =============================================================================
# Strategy Selector
# =============================================================================

class StrategySelector:
    """AI-driven strategy selection."""

    def __init__(self, ai_client=None):
        # Use provided client or create new one
        self.ai_client = ai_client if ai_client else BinaryAIClient()

    async def select_strategy(
        self,
        campaign_state: CampaignState,
        plan: CampaignPlan,
    ) -> StrategyDecision:
        """Decide if strategy should change."""
        prompt = self._build_strategy_prompt(campaign_state, plan)
        response = await self.ai_client.generate(prompt)

        if "error" in response:
            return self._heuristic_strategy(campaign_state)

        return self._parse_strategy_response(response, campaign_state)

    def _build_strategy_prompt(self, state: CampaignState, plan: CampaignPlan) -> str:
        """Build strategy selection prompt."""
        return f"""You are managing an autonomous fuzzing campaign. Based on the current state, decide if we should change strategy.

Current Strategy: {state.current_strategy.value}
Time Elapsed: {state.elapsed_hours:.1f} hours
Time Budget: {plan.success_criteria.max_duration_hours} hours

Coverage Metrics:
- Current coverage: {state.coverage_percentage:.1f}%
- Target coverage: {plan.success_criteria.min_coverage_pct}%
- Trend: {state.coverage_trend.value}
- Recent samples: {state.recent_coverage[-5:] if state.recent_coverage else 'N/A'}

Crash Metrics:
- Total unique crashes: {state.unique_crashes}
- Exploitable crashes: {state.exploitable_crashes}
- Crashes in last hour: {state.recent_crashes}

Performance:
- Executions/sec: {state.executions_per_second:.0f}
- Corpus size: {state.corpus_size}
- Total executions: {state.total_executions}

Campaign Goals:
- Find crashes: {'Yes' if plan.success_criteria.target_crashes > 0 else 'Any'}
- Plateau threshold: {plan.success_criteria.coverage_plateau_hours} hours

Available Strategies:
1. coverage_guided - Standard AFL-style fuzzing
2. directed_fuzzing - Target specific functions
3. concolic_execution - Add symbolic execution for constraints
4. grammar_based - Use input grammar for structured mutation
5. exploit_oriented - Focus on reproducing/exploiting crashes
6. hybrid - Combine multiple approaches

Should we change strategy? Consider:
- Is coverage plateauing?
- Are we finding crashes?
- Is the current strategy effective?
- How much time remains?

Respond in JSON:
{{
    "should_change": true/false,
    "new_strategy": "strategy_name" or null,
    "reasoning": "explanation",
    "confidence": 0.0-1.0,
    "supporting_data": {{}}
}}"""

    def _parse_strategy_response(self, response: Dict, state: CampaignState) -> StrategyDecision:
        """Parse AI strategy response."""
        should_change = response.get("should_change", False)
        new_strategy_str = response.get("new_strategy")

        new_strategy = None
        if new_strategy_str:
            try:
                new_strategy = FuzzingStrategy(new_strategy_str)
            except ValueError:
                new_strategy = None

        return StrategyDecision(
            should_change=should_change,
            current_strategy=state.current_strategy,
            new_strategy=new_strategy,
            reasoning=response.get("reasoning", ""),
            confidence=response.get("confidence", 0.5),
            supporting_data=response.get("supporting_data", {}),
        )

    def _heuristic_strategy(self, state: CampaignState) -> StrategyDecision:
        """Fallback heuristic strategy selection."""
        should_change = False
        new_strategy = None
        reasoning = "Heuristic decision"

        # Check for plateau
        if state.coverage_trend == TrendDirection.PLATEAU:
            if state.current_strategy == FuzzingStrategy.COVERAGE_GUIDED:
                should_change = True
                new_strategy = FuzzingStrategy.CONCOLIC
                reasoning = "Coverage plateaued, enabling concolic execution"
            elif state.current_strategy == FuzzingStrategy.CONCOLIC:
                should_change = True
                new_strategy = FuzzingStrategy.DIRECTED
                reasoning = "Concolic not helping, trying directed fuzzing"

        # If we have crashes, focus on them
        if state.unique_crashes > 0 and state.exploitable_crashes == 0:
            if state.current_strategy != FuzzingStrategy.EXPLOIT_ORIENTED:
                should_change = True
                new_strategy = FuzzingStrategy.EXPLOIT_ORIENTED
                reasoning = "Found crashes, switching to exploit-oriented mode"

        return StrategyDecision(
            should_change=should_change,
            current_strategy=state.current_strategy,
            new_strategy=new_strategy,
            reasoning=reasoning,
            confidence=0.6,
        )


# =============================================================================
# Coverage Advisor
# =============================================================================

class CoverageAdvisor:
    """AI-powered coverage analysis and advice."""

    def __init__(self, ai_client=None):
        # Use provided client or create new one
        self.ai_client = ai_client if ai_client else BinaryAIClient()

    async def get_advice(
        self,
        campaign_state: CampaignState,
        profile: BinaryProfile,
        coverage_data: Optional[Dict[str, Any]] = None,
    ) -> CoverageAdvice:
        """Get AI advice on improving coverage."""
        prompt = self._build_advice_prompt(campaign_state, profile, coverage_data)
        response = await self.ai_client.generate(prompt)

        if "error" in response:
            return self._heuristic_advice(campaign_state)

        return self._parse_advice_response(response, campaign_state)

    def _build_advice_prompt(
        self,
        state: CampaignState,
        profile: BinaryProfile,
        coverage_data: Optional[Dict[str, Any]],
    ) -> str:
        """Build coverage advice prompt."""
        return f"""You are analyzing fuzzing coverage to provide improvement advice.

Binary: {profile.file_path}
Architecture: {profile.architecture} {profile.bits}-bit

Current Coverage State:
- Coverage: {state.coverage_percentage:.1f}%
- Trend: {state.coverage_trend.value}
- Corpus size: {state.corpus_size}
- Executions/sec: {state.executions_per_second:.0f}

Recent coverage history: {state.recent_coverage[-10:] if state.recent_coverage else 'N/A'}

Known Input Handlers:
{chr(10).join(f'  - {h.function_name} ({h.input_type})' for h in profile.input_handlers[:10])}

Vulnerability Hints:
{chr(10).join(f'  - {h.type} at {h.location}' for h in profile.vulnerability_hints[:10])}

Provide advice on improving coverage:

1. uncovered_interesting: List of function names that are high-value but likely uncovered
2. blocking_constraints: What might be preventing coverage (magic bytes, checksums, etc.)
3. recommended_inputs: 3 seed suggestions with rationale
4. mutation_adjustments: Recommended mutation weight changes (strategy: weight 0-1)
5. should_switch_strategy: boolean
6. recommended_strategy: strategy name if switching
7. reasoning: Explain your analysis
8. confidence: 0-1

Respond in JSON format."""

    def _parse_advice_response(self, response: Dict, state: CampaignState) -> CoverageAdvice:
        """Parse AI advice response."""
        recommended_inputs = []

        for seed in response.get("recommended_inputs", []):
            # Extract seed content from various formats the AI might return
            content = b""

            if isinstance(seed, dict):
                # Try to get content from different field names
                seed_content = (
                    seed.get("content") or
                    seed.get("data") or
                    seed.get("seed") or
                    seed.get("input") or
                    seed.get("bytes") or
                    ""
                )

                # Convert to bytes if string
                if isinstance(seed_content, str):
                    # Check if it's a hex string
                    if seed_content.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in seed_content[:20]):
                        try:
                            content = bytes.fromhex(seed_content.replace("0x", "").replace(" ", ""))
                        except ValueError:
                            content = seed_content.encode("utf-8", errors="replace")
                    else:
                        content = seed_content.encode("utf-8", errors="replace")
                elif isinstance(seed_content, bytes):
                    content = seed_content
                elif isinstance(seed_content, list):
                    # List of bytes
                    content = bytes(seed_content[:1024])

                # Generate seed from description if no content but has rationale
                if not content and seed.get("rationale"):
                    rationale = seed.get("rationale", "")
                    # Generate a basic seed based on the rationale hints
                    if "null" in rationale.lower() or "zero" in rationale.lower():
                        content = b"\x00" * 100
                    elif "overflow" in rationale.lower():
                        content = b"A" * 1024
                    elif "format" in rationale.lower():
                        content = b"%s%s%s%s%s%s%s%s%n%n%n%n"
                    elif "negative" in rationale.lower():
                        content = b"-1" + b"\xff" * 4
                    else:
                        # Default: generate test input
                        content = b"TEST_INPUT_" + rationale[:20].encode("utf-8", errors="replace")

            elif isinstance(seed, str):
                content = seed.encode("utf-8", errors="replace")

            # Only add if we have actual content
            if content:
                recommended_inputs.append(SeedSuggestion(
                    content=content,
                    rationale=seed.get("rationale", "") if isinstance(seed, dict) else "AI generated",
                    target_path=seed.get("target_path") if isinstance(seed, dict) else None,
                ))

        new_strategy = None
        if response.get("recommended_strategy"):
            try:
                new_strategy = FuzzingStrategy(response["recommended_strategy"])
            except ValueError:
                logger.debug(f"Invalid strategy value: {response.get('recommended_strategy')}")

        return CoverageAdvice(
            current_coverage=state.coverage_percentage,
            coverage_trend=state.coverage_trend,
            uncovered_interesting=response.get("uncovered_interesting", []),
            blocking_constraints=response.get("blocking_constraints", []),
            recommended_inputs=recommended_inputs,
            mutation_adjustments=response.get("mutation_adjustments", {}),
            should_switch_strategy=response.get("should_switch_strategy", False),
            recommended_strategy=new_strategy,
            reasoning=response.get("reasoning", ""),
            confidence=response.get("confidence", 0.5),
        )

    def _heuristic_advice(self, state: CampaignState) -> CoverageAdvice:
        """Fallback heuristic advice."""
        return CoverageAdvice(
            current_coverage=state.coverage_percentage,
            coverage_trend=state.coverage_trend,
            uncovered_interesting=[],
            blocking_constraints=["Unable to analyze - AI unavailable"],
            recommended_inputs=[],
            mutation_adjustments={},
            should_switch_strategy=state.coverage_trend == TrendDirection.PLATEAU,
            recommended_strategy=FuzzingStrategy.CONCOLIC if state.coverage_trend == TrendDirection.PLATEAU else None,
            reasoning="Heuristic advice - AI unavailable",
            confidence=0.3,
        )


# =============================================================================
# Decision Generator
# =============================================================================

class DecisionGenerator:
    """Generate decisions based on AI analysis."""

    def __init__(self, ai_client=None):
        # Accept ai_client for consistency with other components
        # StrategySelector and CoverageAdvisor create their own clients internally
        self.ai_client = ai_client
        self.strategy_selector = StrategySelector()
        self.coverage_advisor = CoverageAdvisor()

    async def generate_decisions(
        self,
        campaign_state: CampaignState,
        plan: CampaignPlan,
        profile: BinaryProfile,
    ) -> List[Decision]:
        """Generate decisions for the current campaign state."""
        decisions = []

        # Check strategy
        strategy_decision = await self.strategy_selector.select_strategy(campaign_state, plan)
        if strategy_decision.should_change and strategy_decision.new_strategy:
            decisions.append(Decision(
                decision_id=hashlib.md5(f"strategy:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12],
                decision_type=DecisionType.SWITCH_STRATEGY,
                parameters={"new_strategy": strategy_decision.new_strategy.value},
                reasoning=strategy_decision.reasoning,
                confidence=strategy_decision.confidence,
            ))

        # Check coverage
        if campaign_state.coverage_trend == TrendDirection.PLATEAU:
            advice = await self.coverage_advisor.get_advice(campaign_state, profile)

            if advice.mutation_adjustments:
                decisions.append(Decision(
                    decision_id=hashlib.md5(f"mutation:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12],
                    decision_type=DecisionType.ADJUST_MUTATION_WEIGHTS,
                    parameters={"weights": advice.mutation_adjustments},
                    reasoning=advice.reasoning,
                    confidence=advice.confidence,
                ))

            if advice.recommended_inputs:
                decisions.append(Decision(
                    decision_id=hashlib.md5(f"seeds:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12],
                    decision_type=DecisionType.GENERATE_SEEDS,
                    parameters={"seeds": [s.rationale for s in advice.recommended_inputs]},
                    reasoning="Generate new seeds to break plateau",
                    confidence=advice.confidence,
                ))

        # Check for crashes needing triage
        if campaign_state.unique_crashes > campaign_state.exploitable_crashes:
            decisions.append(Decision(
                decision_id=hashlib.md5(f"triage:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12],
                decision_type=DecisionType.TRIAGE_CRASH,
                parameters={},
                reasoning="New crashes need triage",
                confidence=0.9,
            ))

        # Default: continue
        if not decisions:
            decisions.append(Decision(
                decision_id=hashlib.md5(f"continue:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12],
                decision_type=DecisionType.CONTINUE,
                parameters={},
                reasoning="Campaign progressing normally",
                confidence=0.9,
            ))

        return decisions
