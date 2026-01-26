"""
Agentic Binary Fuzzer Service

Main service that provides a unified interface to the AI-powered binary fuzzing system.
Orchestrates all components for autonomous vulnerability discovery.
"""

import asyncio
import hashlib
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union
import json

from backend.services.binary_ai_reasoning import (
    BinaryProfile,
    BinaryAIClient,
    CampaignPlan,
    CampaignState,
    Decision,
    DecisionType,
    FuzzingStrategy,
    ExploitabilityScore,
    SecurityFeatures,
)
from backend.services.binary_analysis_service import BinaryAnalysisService
from backend.services.crash_triage_service import (
    CrashTriageService,
    CrashContext,
    CrashAnalysisResult,
    AccessType,
)
from backend.services.seed_intelligence_service import (
    SeedIntelligenceService,
    SeedGenerationResult,
)
from backend.services.exploit_synthesis_service import (
    ExploitSynthesizer,
    ExploitSynthesisResult,
    RopGadget,
    BypassStrategy,
)
from backend.services.binary_campaign_controller import (
    BinaryCampaignController,
    CampaignConfig,
    CampaignStatus,
    CampaignResult,
    AggregatedFeedback,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class AgenticFuzzerConfig:
    """Configuration for the agentic binary fuzzer."""
    # AI configuration
    enable_ai: bool = True
    ai_model: str = "gemini-3-flash-preview"
    ai_temperature: float = 0.3

    # Campaign defaults
    default_max_duration: timedelta = timedelta(hours=2)  # 2 hours default, not 24
    decision_interval: int = 300  # AI decision every 5 minutes (was 60 seconds)
    checkpoint_interval: int = 300

    # Resource limits
    max_concurrent_campaigns: int = 4
    max_engines_per_campaign: int = 4
    memory_limit_mb: int = 4096

    # Analysis settings
    auto_triage_crashes: bool = True
    auto_generate_exploits: bool = False
    min_exploitability_for_exploit: ExploitabilityScore = ExploitabilityScore.PROBABLY_EXPLOITABLE

    # Storage
    data_dir: str = "/tmp/agentic_fuzzer"
    persist_campaigns: bool = True


# =============================================================================
# Event Types
# =============================================================================

@dataclass
class FuzzerEvent:
    """Base class for fuzzer events."""
    event_type: str = ""
    campaign_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignStartedEvent(FuzzerEvent):
    """Event when a campaign starts."""
    event_type: str = "campaign_started"
    binary_name: str = ""
    strategy: str = ""


@dataclass
class CampaignProgressEvent(FuzzerEvent):
    """Event for campaign progress updates."""
    event_type: str = "campaign_progress"
    coverage: float = 0.0
    crashes: int = 0
    executions: int = 0


@dataclass
class CrashFoundEvent(FuzzerEvent):
    """Event when a new crash is found."""
    event_type: str = "crash_found"
    crash_id: str = ""
    crash_type: str = ""
    exploitability: str = ""


@dataclass
class DecisionMadeEvent(FuzzerEvent):
    """Event when AI makes a decision."""
    event_type: str = "decision_made"
    decision_type: str = ""
    reasoning: str = ""


@dataclass
class CampaignCompletedEvent(FuzzerEvent):
    """Event when a campaign completes."""
    event_type: str = "campaign_completed"
    final_coverage: float = 0.0
    total_crashes: int = 0
    exploitable_crashes: int = 0


# =============================================================================
# Analysis Results
# =============================================================================

@dataclass
class QuickAnalysisResult:
    """Result of quick binary analysis."""
    binary_name: str
    file_type: str
    architecture: str
    size_bytes: int
    hash: str

    # Security features
    protections: Dict[str, bool]

    # Quick assessment
    attack_surface_score: float
    recommended_strategy: FuzzingStrategy
    estimated_difficulty: str  # easy, medium, hard

    # Key findings
    dangerous_functions: List[str]
    input_handlers: List[str]
    interesting_strings: List[str]

    # AI recommendation
    ai_recommendation: str


@dataclass
class FullAnalysisResult:
    """Result of full binary analysis."""
    profile: BinaryProfile
    seed_suggestions: List[Dict[str, Any]]
    campaign_plan: Optional[CampaignPlan]

    # Detailed analysis
    function_analysis: Dict[str, Any]
    vulnerability_hints: List[Dict[str, Any]]
    attack_vectors: List[Dict[str, Any]]


# =============================================================================
# Main Agentic Binary Fuzzer Service
# =============================================================================

class AgenticBinaryFuzzer:
    """
    AI-powered autonomous binary fuzzing system.

    Provides a unified interface for:
    - Binary analysis with AI enhancement
    - Autonomous fuzzing campaign management
    - AI-powered crash triage and exploitability assessment
    - Exploit skeleton generation
    - Real-time progress streaming
    """

    def __init__(self, config: Optional[AgenticFuzzerConfig] = None):
        self.config = config or AgenticFuzzerConfig()

        # Initialize AI client
        self.ai_client: Optional[BinaryAIClient] = None
        if self.config.enable_ai:
            self.ai_client = BinaryAIClient(model=self.config.ai_model)

        # Initialize services
        self.binary_analyzer = BinaryAnalysisService(self.ai_client)
        self.crash_triage = CrashTriageService(self.ai_client)
        self.seed_intelligence = SeedIntelligenceService(self.ai_client)
        self.exploit_synthesizer = ExploitSynthesizer(self.ai_client)
        self.campaign_controller = BinaryCampaignController(
            ai_client=self.ai_client,
            binary_analyzer=self.binary_analyzer,
            crash_triage=self.crash_triage,
            seed_intelligence=self.seed_intelligence,
            exploit_synthesizer=self.exploit_synthesizer,
        )

        # Event subscribers
        self._event_subscribers: List[asyncio.Queue] = []

        # Statistics
        self._stats = {
            "total_campaigns": 0,
            "completed_campaigns": 0,
            "total_crashes_found": 0,
            "exploitable_crashes": 0,
            "total_coverage_achieved": 0.0,
        }

        # Setup data directory
        os.makedirs(self.config.data_dir, exist_ok=True)

    # =========================================================================
    # Binary Analysis
    # =========================================================================

    async def quick_analyze(self, binary_data: bytes, filename: str = "binary") -> QuickAnalysisResult:
        """
        Perform quick analysis of a binary.

        This is a lightweight analysis suitable for initial assessment
        before starting a full fuzzing campaign.
        """
        logger.info(f"Quick analyzing binary: {filename}")

        # Validate input
        try:
            from backend.services.binary_fuzzer_utils import (
                validate_binary_data,
                detect_binary_format,
                safe_extract_strings,
                safe_find_imports,
                heuristic_attack_surface,
                heuristic_strategy_recommendation,
            )
            is_valid, error = validate_binary_data(binary_data, filename)
            if not is_valid:
                raise ValueError(error)
        except ImportError:
            # Fallback if utils not available
            if not binary_data or len(binary_data) < 64:
                raise ValueError("Invalid binary data")

        # Basic file info
        file_hash = hashlib.sha256(binary_data).hexdigest()

        # Detect file type (use robust detection if available)
        try:
            file_type, architecture, is_valid = detect_binary_format(binary_data)
            if not is_valid:
                file_type, architecture = self._detect_binary_type(binary_data)
        except NameError:
            file_type, architecture = self._detect_binary_type(binary_data)

        # Quick security feature detection
        protections = self._quick_security_check(binary_data)

        # Find dangerous functions (use robust extraction if available)
        try:
            dangerous_funcs = safe_find_imports(binary_data, file_type)
            if not dangerous_funcs:
                dangerous_funcs = self._find_dangerous_imports(binary_data)
        except NameError:
            dangerous_funcs = self._find_dangerous_imports(binary_data)

        # Find input handlers
        input_handlers = self._find_input_handlers(binary_data)

        # Find interesting strings (use robust extraction if available)
        try:
            interesting = safe_extract_strings(binary_data, min_length=4, max_strings=100)
            interesting = [s for s in interesting if any(
                p in s.lower() for p in ["password", "secret", "key", "token", "auth", "http", "file", "path"]
            )][:20]
            if not interesting:
                interesting = self._extract_interesting_strings(binary_data)
        except NameError:
            interesting = self._extract_interesting_strings(binary_data)

        # Calculate attack surface score (use heuristic if available)
        try:
            score, factors = heuristic_attack_surface(dangerous_funcs, input_handlers, protections)
        except NameError:
            score = self._calculate_attack_surface(
                dangerous_funcs,
                input_handlers,
                protections,
            )

        # Determine recommended strategy (use heuristic if available)
        try:
            has_network = any(f in dangerous_funcs for f in ["socket", "connect", "recv", "send"])
            has_file_io = any(f in dangerous_funcs for f in ["fopen", "fread", "read", "open"])
            strategy_name, _ = heuristic_strategy_recommendation(
                file_type, architecture, score, has_network, has_file_io
            )
            strategy = FuzzingStrategy(strategy_name)
        except (NameError, ValueError):
            strategy = self._recommend_strategy(
                file_type,
                protections,
                dangerous_funcs,
            )

        # Estimate difficulty
        difficulty = self._estimate_difficulty(protections, score)

        # Get AI recommendation if available
        ai_rec = ""
        if self.ai_client:
            ai_rec = await self._get_ai_recommendation(
                filename, file_type, architecture, protections, score
            )

        return QuickAnalysisResult(
            binary_name=filename,
            file_type=file_type,
            architecture=architecture,
            size_bytes=len(binary_data),
            hash=file_hash,
            protections=protections,
            attack_surface_score=score,
            recommended_strategy=strategy,
            estimated_difficulty=difficulty,
            dangerous_functions=dangerous_funcs[:10],
            input_handlers=input_handlers[:10],
            interesting_strings=interesting[:20],
            ai_recommendation=ai_rec,
        )

    async def full_analyze(
        self,
        binary_data: bytes,
        filename: str = "binary",
    ) -> FullAnalysisResult:
        """
        Perform comprehensive analysis of a binary.

        This includes deep static analysis, AI enhancement,
        and campaign planning.
        """
        logger.info(f"Full analyzing binary: {filename}")

        # Get full profile
        profile = await self.binary_analyzer.analyze(binary_data, filename)

        # Generate seed suggestions
        seed_result = await self.seed_intelligence.generate_seeds(
            profile,
            count=10,
        )
        seed_suggestions = [
            {"data": s.content.hex() if s.content else "", "rationale": s.rationale}
            for s in seed_result.seeds
        ]

        # Create campaign plan if AI available
        campaign_plan = None
        if self.ai_client:
            from backend.services.binary_ai_reasoning import CampaignPlanner
            planner = CampaignPlanner(self.ai_client)
            try:
                campaign_plan = await planner.create_plan(profile)
            except Exception as e:
                logger.warning(f"Campaign planning failed: {e}")

        # Extract detailed analysis
        function_analysis = {
            "total_functions": len(profile.functions),
            "input_handlers": profile.input_handlers,
            "dangerous_calls": profile.vulnerability_hints,
        }

        vulnerability_hints = [
            {"type": h.type, "location": h.location, "confidence": h.confidence}
            for h in profile.vulnerability_hints
        ]

        attack_vectors = self._identify_attack_vectors(profile)

        return FullAnalysisResult(
            profile=profile,
            seed_suggestions=seed_suggestions,
            campaign_plan=campaign_plan,
            function_analysis=function_analysis,
            vulnerability_hints=vulnerability_hints,
            attack_vectors=attack_vectors,
        )

    # =========================================================================
    # Campaign Management
    # =========================================================================

    async def start_campaign(
        self,
        binary_data: bytes,
        filename: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Start an autonomous fuzzing campaign.

        Returns the campaign ID for tracking.
        """
        # Save binary to data directory
        binary_hash = hashlib.sha256(binary_data).hexdigest()[:16]
        binary_path = os.path.join(
            self.config.data_dir,
            "binaries",
            f"{filename}_{binary_hash}",
        )
        os.makedirs(os.path.dirname(binary_path), exist_ok=True)

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        # Make executable
        os.chmod(binary_path, 0o755)

        # Build campaign config
        campaign_config = CampaignConfig(
            binary_path=binary_path,
            max_duration=self.config.default_max_duration,
            decision_interval=self.config.decision_interval,
            checkpoint_interval=self.config.checkpoint_interval,
            max_engines=self.config.max_engines_per_campaign,
            enable_ai=self.config.enable_ai,
        )

        # Override with provided config
        if config:
            if "max_duration_hours" in config:
                campaign_config.max_duration = timedelta(hours=config["max_duration_hours"])
            if "strategy" in config:
                campaign_config.initial_strategy = FuzzingStrategy(config["strategy"])
            if "max_engines" in config:
                campaign_config.max_engines = config["max_engines"]
            if "target_coverage" in config:
                campaign_config.target_coverage = config["target_coverage"]
            if "stop_on_exploitable" in config:
                campaign_config.stop_on_exploitable = config["stop_on_exploitable"]

        # Start campaign
        campaign_id = await self.campaign_controller.start_campaign(
            binary_path,
            campaign_config,
        )

        self._stats["total_campaigns"] += 1

        # Emit event
        await self._emit_event(CampaignStartedEvent(
            campaign_id=campaign_id,
            binary_name=filename,
            strategy=campaign_config.initial_strategy.value if campaign_config.initial_strategy else "coverage_guided",
        ))

        return campaign_id

    async def pause_campaign(self, campaign_id: str) -> bool:
        """Pause a running campaign."""
        return await self.campaign_controller.pause_campaign(campaign_id)

    async def resume_campaign(self, campaign_id: str) -> bool:
        """Resume a paused campaign."""
        return await self.campaign_controller.resume_campaign(campaign_id)

    async def stop_campaign(self, campaign_id: str) -> bool:
        """Stop a campaign."""
        result = await self.campaign_controller.stop_campaign(campaign_id)

        if result:
            await self._emit_event(CampaignCompletedEvent(
                campaign_id=campaign_id,
            ))

        return result

    def get_campaign_status(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a campaign."""
        return self.campaign_controller.get_campaign_status(campaign_id)

    def get_campaign_decisions(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Get AI decisions made during a campaign."""
        return self.campaign_controller.get_campaign_decisions(campaign_id)

    def get_campaign_crashes(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Get crashes found during a campaign."""
        return self.campaign_controller.get_campaign_crashes(campaign_id)

    async def get_campaign_result(self, campaign_id: str) -> Optional[CampaignResult]:
        """Get final result of a completed campaign."""
        return await self.campaign_controller.get_campaign_result(campaign_id)

    def list_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns."""
        return self.campaign_controller.list_campaigns()

    # =========================================================================
    # Crash Analysis
    # =========================================================================

    async def triage_crash(
        self,
        crash_data: bytes,
        binary_profile: Optional[BinaryProfile] = None,
        crash_context: Optional[Dict[str, Any]] = None,
    ) -> CrashAnalysisResult:
        """
        Analyze a crash and assess its exploitability.
        """
        logger.info("Triaging crash")

        # Build crash context if not provided
        if not crash_context:
            crash_context = {
                "input_data": crash_data,
                "input_size": len(crash_data),
            }

        # Convert access_type string to enum
        access_type_str = crash_context.get("access_type", "unknown")
        try:
            access_type_enum = AccessType(access_type_str)
        except ValueError:
            access_type_enum = AccessType.UNKNOWN

        # Create crash context object
        context = CrashContext(
            crash_id=hashlib.sha256(crash_data).hexdigest()[:16],
            timestamp=datetime.utcnow(),
            crash_address=crash_context.get("crash_address", 0),
            crash_instruction=crash_context.get("instruction", ""),
            access_address=crash_context.get("access_address"),
            access_type=access_type_enum,
            input_data=crash_data,
            input_size=len(crash_data),
        )

        # Triage the crash
        result = await self.crash_triage.triage(context, binary_profile)

        # Update stats
        self._stats["total_crashes_found"] += 1
        if result.exploitability in [
            ExploitabilityScore.EXPLOITABLE,
            ExploitabilityScore.PROBABLY_EXPLOITABLE,
        ]:
            self._stats["exploitable_crashes"] += 1

        # Emit event
        await self._emit_event(CrashFoundEvent(
            campaign_id="manual",
            crash_id=context.crash_id,
            crash_type=result.crash_type,
            exploitability=result.exploitability.value,
        ))

        return result

    async def batch_triage(
        self,
        crashes: List[Tuple[bytes, Dict[str, Any]]],
        binary_profile: Optional[BinaryProfile] = None,
    ) -> List[CrashAnalysisResult]:
        """
        Triage multiple crashes in batch.
        """
        results = []

        for crash_data, context in crashes:
            try:
                result = await self.triage_crash(crash_data, binary_profile, context)
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to triage crash: {e}")

        return results

    # =========================================================================
    # Exploit Generation
    # =========================================================================

    async def generate_exploit(
        self,
        crash_analysis: CrashAnalysisResult,
        binary_profile: BinaryProfile,
        binary_data: Optional[bytes] = None,
    ) -> ExploitSynthesisResult:
        """
        Generate an exploit skeleton from a crash analysis.
        """
        logger.info(f"Generating exploit for crash {crash_analysis.crash_id}")

        result = await self.exploit_synthesizer.synthesize_exploit(
            crash_analysis,
            binary_profile,
            binary_data,
        )

        return result

    async def find_gadgets(
        self,
        binary_data: bytes,
        architecture: str = "x64",
    ) -> List[RopGadget]:
        """
        Find ROP gadgets in a binary.
        """
        from backend.services.exploit_synthesis_service import find_gadgets_in_binary

        return find_gadgets_in_binary(binary_data, architecture=architecture)

    async def suggest_bypasses(
        self,
        protections: SecurityFeatures,
        primitives: List[str],
    ) -> List[BypassStrategy]:
        """
        Suggest bypass strategies for security mitigations.
        """
        from backend.services.exploit_synthesis_service import (
            suggest_bypasses,
            ExploitPrimitive,
        )
        from backend.services.crash_triage_service import ExploitPrimitive as EP

        # Convert string primitives to enum
        primitive_enums = []
        for p in primitives:
            try:
                primitive_enums.append(EP(p))
            except ValueError:
                pass

        return suggest_bypasses(protections, primitive_enums)

    # =========================================================================
    # Seed Generation
    # =========================================================================

    async def generate_seeds(
        self,
        binary_profile: BinaryProfile,
        count: int = 10,
        format_hint: Optional[str] = None,
    ) -> SeedGenerationResult:
        """
        Generate intelligent fuzzing seeds for a binary.
        """
        return await self.seed_intelligence.generate_seeds(
            binary_profile,
            count=count,
            format_hint=format_hint,
        )

    async def generate_dictionary(
        self,
        binary_profile: BinaryProfile,
    ) -> List[bytes]:
        """
        Generate a fuzzing dictionary from binary analysis.
        """
        result = await self.seed_intelligence.generate_dictionary(binary_profile)
        return [entry.value for entry in result]

    # =========================================================================
    # Real-time Streaming
    # =========================================================================

    async def stream_events(
        self,
        campaign_id: Optional[str] = None,
    ) -> AsyncGenerator[FuzzerEvent, None]:
        """
        Stream real-time events from fuzzing campaigns.
        """
        queue: asyncio.Queue = asyncio.Queue()
        self._event_subscribers.append(queue)

        try:
            while True:
                event = await queue.get()

                # Filter by campaign if specified
                if campaign_id and event.campaign_id != campaign_id:
                    continue

                yield event
        finally:
            self._event_subscribers.remove(queue)

    async def _emit_event(self, event: FuzzerEvent) -> None:
        """Emit an event to all subscribers."""
        for queue in self._event_subscribers:
            try:
                await asyncio.wait_for(queue.put(event), timeout=1.0)
            except asyncio.TimeoutError:
                pass

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get overall fuzzer statistics."""
        return {
            **self._stats,
            "active_campaigns": len([
                c for c in self.campaign_controller.list_campaigns()
                if c["status"] == "running"
            ]),
        }

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _detect_binary_type(self, data: bytes) -> Tuple[str, str]:
        """Detect binary file type and architecture."""
        if data[:4] == b"\x7fELF":
            # ELF
            arch_byte = data[18] if len(data) > 18 else 0
            arch_map = {0x03: "x86", 0x3e: "x64", 0x28: "arm", 0xb7: "arm64"}
            arch = arch_map.get(arch_byte, "unknown")
            return "ELF", arch

        elif data[:2] == b"MZ":
            # PE
            if len(data) > 64:
                pe_offset = int.from_bytes(data[60:64], "little")
                if len(data) > pe_offset + 6:
                    machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
                    arch_map = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}
                    arch = arch_map.get(machine, "unknown")
                    return "PE", arch
            return "PE", "unknown"

        elif data[:4] in [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                          b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]:
            # Mach-O
            return "Mach-O", "x64" if data[3] in [0xcf, 0xfe] else "x86"

        return "unknown", "unknown"

    def _quick_security_check(self, data: bytes) -> Dict[str, bool]:
        """Quick check for security features."""
        return {
            "aslr": True,  # Assume enabled by default
            "dep": True,
            "stack_canary": b"__stack_chk_fail" in data,
            "pie": data[:4] == b"\x7fELF" and data[16] == 3,  # ET_DYN
            "relro": b"__libc_start_main" in data,
        }

    def _find_dangerous_imports(self, data: bytes) -> List[str]:
        """Find dangerous function imports."""
        dangerous = [
            b"strcpy", b"strcat", b"sprintf", b"gets", b"scanf",
            b"memcpy", b"memmove", b"strncpy", b"strncat",
            b"vsprintf", b"vsnprintf", b"realpath", b"getwd",
        ]
        found = []
        for func in dangerous:
            if func in data:
                found.append(func.decode())
        return found

    def _find_input_handlers(self, data: bytes) -> List[str]:
        """Find input handling functions."""
        handlers = [
            b"read", b"fread", b"recv", b"recvfrom", b"fgets",
            b"getline", b"getdelim", b"fscanf", b"sscanf",
        ]
        found = []
        for func in handlers:
            if func in data:
                found.append(func.decode())
        return found

    def _extract_interesting_strings(self, data: bytes) -> List[str]:
        """Extract interesting strings from binary."""
        interesting = []

        # Find printable string sequences
        import re
        strings = re.findall(b"[\\x20-\\x7e]{4,}", data)

        for s in strings[:100]:  # Limit to first 100
            decoded = s.decode("ascii", errors="ignore")

            # Filter for interesting patterns
            if any(pattern in decoded.lower() for pattern in [
                "password", "secret", "key", "token", "auth",
                "http", "file", "path", "/bin/", "root",
                "format", "error", "debug", "admin",
            ]):
                interesting.append(decoded)

        return interesting[:20]

    def _calculate_attack_surface(
        self,
        dangerous: List[str],
        inputs: List[str],
        protections: Dict[str, bool],
    ) -> float:
        """Calculate attack surface score (0-1)."""
        score = 0.0

        # Dangerous functions increase score
        score += min(len(dangerous) * 0.05, 0.3)

        # Input handlers increase score
        score += min(len(inputs) * 0.03, 0.2)

        # Missing protections increase score
        if not protections.get("stack_canary"):
            score += 0.2
        if not protections.get("pie"):
            score += 0.15
        if not protections.get("relro"):
            score += 0.1

        return min(score, 1.0)

    def _recommend_strategy(
        self,
        file_type: str,
        protections: Dict[str, bool],
        dangerous: List[str],
    ) -> FuzzingStrategy:
        """Recommend initial fuzzing strategy."""
        # If many dangerous functions, use coverage-guided
        if len(dangerous) > 5:
            return FuzzingStrategy.COVERAGE_GUIDED

        # If few protections, simpler approach may work
        protection_count = sum(protections.values())
        if protection_count < 2:
            return FuzzingStrategy.COVERAGE_GUIDED

        # Default to coverage-guided with potential for directed
        return FuzzingStrategy.COVERAGE_GUIDED

    def _estimate_difficulty(
        self,
        protections: Dict[str, bool],
        attack_score: float,
    ) -> str:
        """Estimate fuzzing difficulty."""
        protection_count = sum(protections.values())

        if attack_score > 0.6 and protection_count < 3:
            return "easy"
        elif attack_score > 0.3 or protection_count < 4:
            return "medium"
        else:
            return "hard"

    async def _get_ai_recommendation(
        self,
        filename: str,
        file_type: str,
        arch: str,
        protections: Dict[str, bool],
        score: float,
    ) -> str:
        """Get AI recommendation for fuzzing approach."""
        if not self.ai_client:
            return ""

        prompt = f"""Analyze this binary for fuzzing:

Binary: {filename}
Type: {file_type} ({arch})
Attack Surface Score: {score:.2f}
Protections:
- Stack Canary: {protections.get('stack_canary')}
- PIE: {protections.get('pie')}
- RELRO: {protections.get('relro')}

Provide a brief (2-3 sentence) recommendation for the best fuzzing approach."""

        try:
            result = await self.ai_client.generate(prompt)
            return result.get("recommendation", "") if result else ""
        except Exception as e:
            logger.warning(f"AI recommendation failed: {e}")
            return ""

    def _identify_attack_vectors(self, profile: BinaryProfile) -> List[Dict[str, Any]]:
        """Identify potential attack vectors from profile."""
        vectors = []

        # Check for common vulnerability patterns from hints
        if hasattr(profile, 'vulnerability_hints') and profile.vulnerability_hints:
            for hint in profile.vulnerability_hints:
                vectors.append({
                    "type": hint.type,
                    "location": hint.location,
                    "severity": "high" if hint.confidence > 0.7 else "medium",
                    "description": f"Potential {hint.type} vulnerability",
                })

        # Add vectors based on dangerous functions found in imports
        dangerous_patterns = [
            "strcpy", "strcat", "sprintf", "gets", "scanf",
            "memcpy", "memmove", "strncpy", "strncat",
            "system", "popen", "exec", "eval",
        ]

        if hasattr(profile, 'imports') and profile.imports:
            for imp in profile.imports:
                imp_lower = imp.lower()
                for pattern in dangerous_patterns:
                    if pattern in imp_lower:
                        vectors.append({
                            "type": "dangerous_function",
                            "location": imp,
                            "severity": "medium",
                            "description": f"Uses potentially unsafe function: {imp}",
                        })
                        break

        # Add vectors based on vulnerability hints with dangerous functions
        if hasattr(profile, 'vulnerability_hints') and profile.vulnerability_hints:
            for hint in profile.vulnerability_hints[:5]:
                if hasattr(hint, 'dangerous_function') and hint.dangerous_function:
                    vectors.append({
                        "type": "dangerous_function",
                        "location": hint.dangerous_function,
                        "severity": "medium",
                        "description": f"Uses potentially unsafe function: {hint.dangerous_function}",
                    })

        return vectors


# =============================================================================
# Convenience Functions
# =============================================================================

def create_fuzzer(enable_ai: bool = True) -> AgenticBinaryFuzzer:
    """Create an agentic binary fuzzer with default configuration."""
    config = AgenticFuzzerConfig(enable_ai=enable_ai)
    return AgenticBinaryFuzzer(config)


async def quick_fuzz(
    binary_data: bytes,
    filename: str = "target",
    duration_hours: int = 1,
) -> CampaignResult:
    """
    Quick-start a fuzzing campaign and wait for completion.

    This is a convenience function for simple fuzzing tasks.
    """
    fuzzer = create_fuzzer()

    # Start campaign
    campaign_id = await fuzzer.start_campaign(
        binary_data,
        filename,
        config={"max_duration_hours": duration_hours},
    )

    # Wait for completion
    while True:
        status = fuzzer.get_campaign_status(campaign_id)
        if status and status.get("status") in ["completed", "failed"]:
            break
        await asyncio.sleep(10)

    # Get result
    return await fuzzer.get_campaign_result(campaign_id)


async def analyze_and_fuzz(
    binary_path: str,
    duration_hours: int = 24,
) -> Tuple[FullAnalysisResult, Optional[CampaignResult]]:
    """
    Analyze a binary and optionally start fuzzing based on analysis.
    """
    # Read binary
    with open(binary_path, "rb") as f:
        binary_data = f.read()

    filename = os.path.basename(binary_path)

    # Create fuzzer
    fuzzer = create_fuzzer()

    # Full analysis
    analysis = await fuzzer.full_analyze(binary_data, filename)

    # Check if worth fuzzing
    if analysis.profile.attack_surface_score < 0.1:
        logger.info("Low attack surface, skipping fuzzing")
        return analysis, None

    # Start fuzzing
    campaign_id = await fuzzer.start_campaign(
        binary_data,
        filename,
        config={"max_duration_hours": duration_hours},
    )

    # Return analysis immediately, campaign runs in background
    return analysis, None  # Campaign result would need to be retrieved later
