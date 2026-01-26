"""
Binary Campaign Controller

Autonomous campaign management with AI decision-making.
Orchestrates fuzzing engines, collects feedback, and executes AI decisions.

This module now uses robust engine wrappers and database persistence for
improved reliability and recovery capabilities.
"""

import asyncio
import hashlib
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import json
import traceback

from backend.services.binary_ai_reasoning import (
    BinaryProfile,
    BinaryAIClient,
    CampaignPlan,
    CampaignState,
    Decision,
    DecisionType,
    FuzzingStrategy,
    StrategyDecision,
    CoverageAdvice,
    TrendDirection,
    CampaignPlanner,
    StrategySelector,
    CoverageAdvisor,
    DecisionGenerator,
)
from backend.services.binary_analysis_service import BinaryAnalysisService
from backend.services.crash_triage_service import CrashTriageService, CrashAnalysisResult
from backend.services.seed_intelligence_service import SeedIntelligenceService
from backend.services.exploit_synthesis_service import ExploitSynthesizer

# Import robust engine wrappers
from backend.services.fuzzing_engine_wrapper import (
    FuzzingEngine,
    EngineConfig,
    EngineStats,
    EngineType,
    EngineStatus,
    EnginePool,
    CrashInfo,
    create_engine,
    check_fuzzer_availability,
)

# Import persistence service
from backend.services.campaign_persistence import (
    CampaignPersistenceService,
    get_persistence_service,
)

# Import AI feedback loop for learning
from backend.services.ai_feedback_loop import (
    AIFeedbackLoop,
    SuggestionType,
    OutcomeType,
    get_feedback_loop,
    record_suggestion,
    record_outcome,
)

# Import power schedule service for intelligent seed prioritization
from backend.services.power_schedule_service import (
    PowerScheduleService,
    PowerSchedule,
    SeedInfo,
    get_power_schedule_service,
)

# Import crash deduplication for efficient crash bucketing
from backend.services.crash_deduplication_service import (
    CrashDeduplicationService,
    get_crash_deduplication_service,
    CrashSeverity,
)

# Import CMPLOG for comparison logging
from backend.services.comparison_logging_service import (
    ComparisonLoggingService,
    get_comparison_logging_service,
)

# Import persistent mode for 10-100x speedup
from backend.services.persistent_mode_service import (
    PersistentModeService,
    PersistentConfig,
    PersistentModeType,
    get_persistent_mode_service,
)

# Import AGENTIC reasoning engine - the brain of the system
from backend.services.agentic_reasoning_engine import (
    AgenticReasoningEngine,
    AgentMemory,
    ChainOfThoughtReasoner,
    ExplorationManager,
    get_agentic_engine,
    AFLPPFeatureSelector,
    get_feature_selector,
)

# Import AFL++ full integration service for advanced features
from backend.services.aflpp_full_integration import (
    AFLPlusPlusFullService,
    AFLPPConfig,
    AFLPPStats,
    AFLPowerSchedule,
    AFLMutator,
    AFLFuzzMode,
    AFLSanitizer,
    get_aflpp_service,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Campaign timing
DEFAULT_DECISION_INTERVAL = 60  # seconds between AI decisions
DEFAULT_CHECKPOINT_INTERVAL = 300  # seconds between checkpoints
DEFAULT_STATS_INTERVAL = 10  # seconds between stats collection

# Resource limits
MAX_CONCURRENT_ENGINES = 8
MAX_CORPUS_SIZE = 100000
MAX_CRASHES_TO_KEEP = 10000

# Campaign thresholds
COVERAGE_PLATEAU_THRESHOLD = 0.01  # 1% growth required
COVERAGE_PLATEAU_WINDOW = 3600  # 1 hour window
CRASH_BURST_THRESHOLD = 10  # crashes per minute triggers analysis


# =============================================================================
# Data Classes
# =============================================================================

class CampaignStatus(str, Enum):
    """Campaign lifecycle states."""
    INITIALIZING = "initializing"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"


# NOTE: EngineType, EngineConfig, EngineStats are now imported from fuzzing_engine_wrapper


@dataclass
class AggregatedFeedback:
    """Aggregated feedback from all fuzzing engines."""
    timestamp: datetime

    # Coverage metrics
    total_coverage: float
    coverage_delta: float
    new_edges: int

    # Crash metrics
    total_crashes: int
    unique_crashes: int

    # Performance metrics
    executions_per_second: float
    total_executions: int
    corpus_size: int

    # Fields with defaults must come after non-default fields
    coverage_by_function: Dict[str, float] = field(default_factory=dict)
    new_crashes: List[Dict[str, Any]] = field(default_factory=list)
    crash_rate: float = 0.0

    # Engine-specific
    engine_stats: Dict[str, EngineStats] = field(default_factory=dict)

    # Trends
    coverage_trend: TrendDirection = TrendDirection.STABLE
    crash_trend: TrendDirection = TrendDirection.STABLE
    performance_trend: TrendDirection = TrendDirection.STABLE


@dataclass
class CampaignCheckpoint:
    """Campaign checkpoint for persistence."""
    campaign_id: str
    timestamp: datetime

    # State
    status: CampaignStatus
    current_strategy: FuzzingStrategy
    elapsed_time: timedelta

    # Metrics
    total_executions: int
    coverage_pct: float
    unique_crashes: int
    exploitable_crashes: int

    # AI state
    decisions_made: int
    strategy_changes: int
    last_decision: Optional[Decision] = None

    # Corpus state
    corpus_hashes: Set[str] = field(default_factory=set)
    crash_hashes: Set[str] = field(default_factory=set)


@dataclass
class CampaignConfig:
    """Configuration for a fuzzing campaign."""
    # Target
    binary_path: str
    input_type: str = "file"  # file, stdin, network, args

    # Timing
    max_duration: Optional[timedelta] = None
    decision_interval: int = DEFAULT_DECISION_INTERVAL
    checkpoint_interval: int = DEFAULT_CHECKPOINT_INTERVAL

    # Resources
    max_engines: int = 4
    memory_limit_mb: int = 4096
    cpu_cores: int = 4

    # Strategy
    initial_strategy: Optional[FuzzingStrategy] = None
    allowed_strategies: List[FuzzingStrategy] = field(default_factory=lambda: list(FuzzingStrategy))

    # Seeds
    seed_dir: Optional[str] = None
    generate_seeds: bool = True
    dictionary_path: Optional[str] = None

    # Goals
    target_coverage: Optional[float] = None
    target_crashes: Optional[int] = None
    stop_on_exploitable: bool = False

    # AI
    enable_ai: bool = True
    ai_model: str = "claude-3-haiku"


@dataclass
class CampaignResult:
    """Final result of a completed campaign."""
    campaign_id: str
    binary_name: str
    status: CampaignStatus

    # Timing
    started_at: datetime
    ended_at: datetime
    duration: timedelta

    # Final metrics
    total_executions: int
    final_coverage: float
    unique_crashes: int
    exploitable_crashes: int

    # AI metrics
    total_decisions: int
    strategy_changes: int
    decisions_by_type: Dict[str, int] = field(default_factory=dict)

    # Artifacts
    crash_analyses: List[CrashAnalysisResult] = field(default_factory=list)
    corpus_stats: Dict[str, Any] = field(default_factory=dict)

    # AI summary
    ai_summary: str = ""


# NOTE: FuzzingEngine and AFLEngine are now imported from fuzzing_engine_wrapper
# with improved robustness, automatic health checking, and mock mode support


# =============================================================================
# Feedback Aggregator
# =============================================================================

class FeedbackAggregator:
    """Collect and normalize feedback from all fuzzing engines with error handling."""

    def __init__(self):
        self._history: List[AggregatedFeedback] = []
        self._max_history = 1000
        self._last_crash_count = 0

    async def collect(self, engines: List[FuzzingEngine]) -> AggregatedFeedback:
        """Collect and aggregate feedback from all engines with robust error handling."""
        engine_stats: Dict[str, EngineStats] = {}

        # Collect stats from each engine with error handling
        for engine in engines:
            try:
                stats = await asyncio.wait_for(engine.get_stats(), timeout=10.0)
                engine_stats[engine.engine_id] = stats
            except asyncio.TimeoutError:
                logger.warning(f"Stats collection timed out for {engine.engine_id}")
            except Exception as e:
                logger.warning(f"Failed to collect stats from {engine.engine_id}: {e}")

        # Aggregate metrics
        total_exec = sum(s.executions for s in engine_stats.values())
        total_exec_per_sec = sum(s.executions_per_sec for s in engine_stats.values())
        total_edges = max((s.edges_found for s in engine_stats.values()), default=0)
        total_corpus = sum(s.corpus_size for s in engine_stats.values())
        total_crashes = sum(s.crashes_found for s in engine_stats.values())
        unique_crashes = sum(s.unique_crashes for s in engine_stats.values())

        # Calculate coverage percentage
        max_edges = max((s.edges_total for s in engine_stats.values() if s.edges_total > 0), default=1)
        coverage_pct = (total_edges / max_edges * 100) if max_edges > 0 else 0

        # Calculate delta from previous
        coverage_delta = 0.0
        new_crashes: List[Dict[str, Any]] = []

        if self._history:
            prev = self._history[-1]
            coverage_delta = coverage_pct - prev.total_coverage

        # Determine trends
        coverage_trend = self._calculate_trend([f.total_coverage for f in self._history[-10:]] + [coverage_pct])
        crash_trend = self._calculate_trend([f.total_crashes for f in self._history[-10:]] + [total_crashes])
        perf_trend = self._calculate_trend([f.executions_per_second for f in self._history[-10:]] + [total_exec_per_sec])

        feedback = AggregatedFeedback(
            timestamp=datetime.utcnow(),
            total_coverage=coverage_pct,
            coverage_delta=coverage_delta,
            new_edges=total_edges - (self._history[-1].new_edges if self._history else 0),
            total_crashes=total_crashes,
            unique_crashes=unique_crashes,
            new_crashes=new_crashes,
            crash_rate=total_crashes / (total_exec / 3600) if total_exec > 0 else 0,
            executions_per_second=total_exec_per_sec,
            total_executions=total_exec,
            corpus_size=total_corpus,
            engine_stats=engine_stats,
            coverage_trend=coverage_trend,
            crash_trend=crash_trend,
            performance_trend=perf_trend,
        )

        # Add to history
        self._history.append(feedback)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        return feedback

    def _calculate_trend(self, values: List[float]) -> TrendDirection:
        """Calculate trend direction from recent values."""
        if len(values) < 3:
            return TrendDirection.STABLE

        recent_avg = sum(values[-3:]) / 3
        older_avg = sum(values[:3]) / 3

        if recent_avg > older_avg * 1.05:
            return TrendDirection.INCREASING
        elif recent_avg < older_avg * 0.95:
            return TrendDirection.DECREASING
        return TrendDirection.STABLE

    def get_coverage_history(self, minutes: int = 60) -> List[Tuple[datetime, float]]:
        """Get coverage history for the specified time window."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return [(f.timestamp, f.total_coverage) for f in self._history if f.timestamp > cutoff]

    def get_crash_history(self, minutes: int = 60) -> List[Tuple[datetime, int]]:
        """Get crash count history for the specified time window."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return [(f.timestamp, f.total_crashes) for f in self._history if f.timestamp > cutoff]

    def is_coverage_plateau(self) -> bool:
        """Check if coverage has plateaued."""
        if len(self._history) < 10:
            return False

        window = self._history[-60:]  # Last hour of samples
        if not window:
            return False

        coverage_values = [f.total_coverage for f in window]
        growth = coverage_values[-1] - coverage_values[0]

        return growth < COVERAGE_PLATEAU_THRESHOLD


# =============================================================================
# Decision Executor
# =============================================================================

class DecisionExecutor:
    """Execute AI-generated decisions on fuzzing engines."""

    def __init__(
        self,
        engines: List[FuzzingEngine],
        seed_intelligence: SeedIntelligenceService,
        crash_triage: CrashTriageService,
        exploit_synth: ExploitSynthesizer,
        aflpp_service: Optional[AFLPlusPlusFullService] = None,
    ):
        self.engines = engines
        self.seed_intelligence = seed_intelligence
        self.crash_triage = crash_triage
        self.exploit_synth = exploit_synth
        self.aflpp_service = aflpp_service
        self._decision_history: List[Tuple[Decision, str]] = []

    async def execute(self, decisions: List[Decision]) -> List[Tuple[Decision, str]]:
        """Execute a list of AI decisions."""
        results = []

        for decision in decisions:
            try:
                result = await self._execute_single(decision)
                results.append((decision, result))
                self._decision_history.append((decision, result))
            except Exception as e:
                logger.error(f"Failed to execute decision {decision.decision_type}: {e}")
                results.append((decision, f"failed: {str(e)}"))

        return results

    async def _execute_single(self, decision: Decision) -> str:
        """Execute a single decision."""
        dtype = decision.decision_type
        params = decision.parameters

        if dtype == DecisionType.SWITCH_STRATEGY:
            return await self._switch_strategy(params)

        elif dtype == DecisionType.ADJUST_MUTATION_WEIGHTS:
            return await self._adjust_mutations(params)

        elif dtype == DecisionType.GENERATE_SEEDS:
            return await self._generate_seeds(params)

        elif dtype == DecisionType.FOCUS_FUNCTION:
            return await self._focus_function(params)

        elif dtype == DecisionType.ENABLE_CONCOLIC:
            return await self._enable_concolic(params)

        elif dtype == DecisionType.ENABLE_TAINT:
            return await self._enable_taint(params)

        elif dtype == DecisionType.MINIMIZE_CORPUS:
            return await self._minimize_corpus(params)

        elif dtype == DecisionType.ADD_DICTIONARY:
            return await self._add_dictionary(params)

        elif dtype == DecisionType.SCALE_UP:
            return await self._scale_up(params)

        elif dtype == DecisionType.SCALE_DOWN:
            return await self._scale_down(params)

        elif dtype == DecisionType.TRIAGE_CRASH:
            return await self._triage_crash(params)

        elif dtype == DecisionType.GENERATE_EXPLOIT:
            return await self._generate_exploit(params)

        elif dtype == DecisionType.DIRECTED_FUZZING:
            return await self._directed_fuzzing(params)

        elif dtype == DecisionType.CHECKPOINT:
            return "checkpoint_requested"

        elif dtype == DecisionType.PAUSE:
            return "pause_requested"

        elif dtype == DecisionType.TERMINATE:
            return "terminate_requested"

        else:
            return f"unknown_decision_type: {dtype}"

    async def _switch_strategy(self, params: Dict[str, Any]) -> str:
        """Switch fuzzing strategy - ACTUALLY reconfigure engines."""
        new_strategy = params.get("strategy")
        configured_count = 0

        for engine in self.engines:
            try:
                if new_strategy == FuzzingStrategy.COVERAGE_GUIDED:
                    # Standard coverage-guided: maximize edge coverage
                    if hasattr(engine, 'config'):
                        engine.config.mutation_strategy = "havoc"
                        engine.config.power_schedule = "fast"
                    configured_count += 1

                elif new_strategy == FuzzingStrategy.DIRECTED_FUZZING:
                    # Focus on specific targets - increase mutation rate on paths to targets
                    target_funcs = params.get("target_functions", [])
                    if hasattr(engine, 'config'):
                        engine.config.mutation_strategy = "directed"
                        engine.config.target_functions = target_funcs
                        engine.config.power_schedule = "explore"
                    configured_count += 1

                elif new_strategy == FuzzingStrategy.EXPLOIT_ORIENTED:
                    # Focus on crash exploration - more aggressive mutations
                    if hasattr(engine, 'config'):
                        engine.config.mutation_strategy = "exploit"
                        engine.config.mutation_depth = 8  # More aggressive
                        engine.config.crash_exploration = True
                    configured_count += 1

                elif new_strategy == FuzzingStrategy.HYBRID:
                    # Enable symbolic execution integration
                    if hasattr(engine, 'config'):
                        engine.config.mutation_strategy = "hybrid"
                        engine.config.enable_concolic = True
                    configured_count += 1

                # Apply the config change
                if hasattr(engine, 'apply_config'):
                    await engine.apply_config()

            except Exception as e:
                logger.warning(f"Failed to configure engine for {new_strategy}: {e}")

        logger.info(f"Switched {configured_count}/{len(self.engines)} engines to {new_strategy}")
        return f"switched_{configured_count}_engines_to_{new_strategy}"

    async def _adjust_mutations(self, params: Dict[str, Any]) -> str:
        """Adjust mutation weights/probabilities - ACTUALLY apply to engines."""
        weights = params.get("weights", {})
        adjusted_count = 0

        # Default mutation weights if not specified
        default_weights = {
            "bit_flip": 0.1,
            "byte_flip": 0.15,
            "arithmetic": 0.15,
            "interesting_values": 0.1,
            "dictionary": 0.1,
            "havoc": 0.3,
            "splice": 0.1,
        }

        # Merge with provided weights
        final_weights = {**default_weights, **weights}

        for engine in self.engines:
            try:
                if hasattr(engine, 'config') and hasattr(engine.config, 'mutation_weights'):
                    engine.config.mutation_weights = final_weights
                    adjusted_count += 1
                elif hasattr(engine, 'set_mutation_weights'):
                    await engine.set_mutation_weights(final_weights)
                    adjusted_count += 1
            except Exception as e:
                logger.warning(f"Failed to adjust mutations for engine: {e}")

        logger.info(f"Adjusted mutation weights for {adjusted_count} engines: {list(final_weights.keys())}")
        return f"adjusted_mutations_on_{adjusted_count}_engines"

    async def _generate_seeds(self, params: Dict[str, Any]) -> str:
        """Generate new seeds using AI - ACTUALLY create and add seeds."""
        count = params.get("count", 10)
        format_hint = params.get("format")
        seeds_added = 0

        # Try to use seed intelligence service for smart seed generation
        generated_seeds = []
        if self.seed_intelligence:
            try:
                # Get AI-generated seeds based on format and coverage gaps
                ai_seeds = await self.seed_intelligence.generate_seeds(
                    count=count,
                    format_hint=format_hint,
                    coverage_gaps=params.get("coverage_gaps", []),
                )
                generated_seeds.extend(ai_seeds)
            except Exception as e:
                logger.warning(f"AI seed generation failed: {e}")

        # Fallback: Generate structured random seeds
        if len(generated_seeds) < count:
            remaining = count - len(generated_seeds)
            for _ in range(remaining):
                if format_hint == "text":
                    seed = bytes([random.randint(0x20, 0x7e) for _ in range(random.randint(16, 256))])
                elif format_hint == "binary":
                    seed = os.urandom(random.randint(64, 512))
                elif format_hint == "json":
                    seed = b'{"key": "' + os.urandom(16).hex().encode() + b'"}'
                elif format_hint == "xml":
                    seed = b'<root><data>' + os.urandom(16).hex().encode() + b'</data></root>'
                else:
                    # Mix of printable and binary
                    seed = os.urandom(random.randint(32, 256))
                generated_seeds.append(seed)

        # Add seeds to all engines
        for engine in self.engines:
            for seed in generated_seeds:
                try:
                    if await engine.add_seed(seed):
                        seeds_added += 1
                except Exception as e:
                    logger.debug(f"Failed to add seed to engine: {e}")

        logger.info(f"Generated and added {seeds_added} seeds across {len(self.engines)} engines")
        return f"generated_{len(generated_seeds)}_seeds_added_{seeds_added}_total"

    async def _focus_function(self, params: Dict[str, Any]) -> str:
        """Focus fuzzing on specific function - ACTUALLY configure directed fuzzing."""
        function = params.get("function")
        function_addr = params.get("address")

        configured = 0
        for engine in self.engines:
            try:
                if hasattr(engine, 'config'):
                    engine.config.target_functions = [function] if function else []
                    engine.config.target_addresses = [function_addr] if function_addr else []
                    engine.config.power_schedule = "exploit"  # Focus on target paths
                    configured += 1

                if hasattr(engine, 'set_focus_target'):
                    await engine.set_focus_target(function, function_addr)

            except Exception as e:
                logger.warning(f"Failed to focus engine on {function}: {e}")

        logger.info(f"Focused {configured} engines on function: {function}")
        return f"focused_{configured}_engines_on_{function}"

    async def _enable_concolic(self, params: Dict[str, Any]) -> str:
        """Enable concolic/symbolic execution - ACTUALLY integrate angr."""
        enabled = 0

        try:
            from backend.services.symbolic_execution_service import get_symbolic_execution_service
            symbolic_service = get_symbolic_execution_service()

            if symbolic_service.is_available:
                for engine in self.engines:
                    if hasattr(engine, 'config'):
                        engine.config.enable_concolic = True
                        engine.config.symbolic_service = symbolic_service
                        enabled += 1

                logger.info(f"Enabled concolic execution on {enabled} engines")
                return f"concolic_enabled_on_{enabled}_engines"
            else:
                logger.warning("angr not available for concolic execution")
                return "concolic_unavailable_angr_not_installed"

        except ImportError:
            logger.warning("Symbolic execution service not available")
            return "concolic_unavailable_service_missing"

    async def _enable_taint(self, params: Dict[str, Any]) -> str:
        """Enable taint tracking - configure engines for taint-guided fuzzing."""
        enabled = 0

        for engine in self.engines:
            try:
                if hasattr(engine, 'config'):
                    engine.config.enable_taint = True
                    engine.config.taint_sources = params.get("sources", ["stdin", "file"])
                    engine.config.taint_sinks = params.get("sinks", ["memcpy", "strcpy", "system"])
                    enabled += 1
            except Exception as e:
                logger.warning(f"Failed to enable taint on engine: {e}")

        logger.info(f"Enabled taint tracking on {enabled} engines")
        return f"taint_enabled_on_{enabled}_engines"

    async def _minimize_corpus(self, params: Dict[str, Any]) -> str:
        """Minimize the corpus using AFL++ full integration service."""
        minimized_total = 0
        original_total = 0

        for engine in self.engines:
            try:
                # Get corpus size before
                corpus_dir = None
                binary_path = None

                if hasattr(engine, 'get_corpus_size'):
                    original = await engine.get_corpus_size()
                    original_total += original

                if hasattr(engine, 'config'):
                    corpus_dir = os.path.join(engine.config.output_dir, 'queue')
                    binary_path = engine.config.binary_path

                # Use AFL++ full integration service for proper minimization
                if self.aflpp_service and corpus_dir and binary_path and os.path.exists(corpus_dir):
                    import tempfile
                    minimized_dir = tempfile.mkdtemp(prefix="minimized_")

                    try:
                        original_count, minimized_count = await self.aflpp_service.minimize_corpus(
                            binary_path=binary_path,
                            input_dir=corpus_dir,
                            output_dir=minimized_dir,
                            timeout_ms=1000,
                            memory_mb=2048,
                        )

                        # Replace corpus with minimized version
                        if minimized_count > 0 and minimized_count < original_count:
                            import shutil
                            # Backup and replace
                            backup_dir = corpus_dir + ".backup"
                            if os.path.exists(backup_dir):
                                shutil.rmtree(backup_dir)
                            os.rename(corpus_dir, backup_dir)
                            os.rename(minimized_dir, corpus_dir)
                            minimized_total += original_count - minimized_count

                            logger.info(
                                f"Corpus minimized: {original_count} -> {minimized_count} "
                                f"({(1 - minimized_count/original_count)*100:.1f}% reduction)"
                            )
                        else:
                            shutil.rmtree(minimized_dir)

                    except Exception as e:
                        logger.warning(f"AFL++ corpus minimization failed: {e}")
                        import shutil
                        if os.path.exists(minimized_dir):
                            shutil.rmtree(minimized_dir)

                elif hasattr(engine, 'minimize_corpus'):
                    removed = await engine.minimize_corpus()
                    minimized_total += removed

            except Exception as e:
                logger.warning(f"Corpus minimization failed for engine: {e}")

        logger.info(f"Corpus minimization complete: removed ~{minimized_total} of {original_total} cases")
        return f"corpus_minimized_removed_{minimized_total}"

    async def _add_dictionary(self, params: Dict[str, Any]) -> str:
        """Add tokens to fuzzing dictionary - ACTUALLY write to engine dict files."""
        tokens = params.get("tokens", [])
        if not tokens:
            return "no_tokens_provided"

        added_total = 0

        for engine in self.engines:
            try:
                if hasattr(engine, 'add_dictionary_tokens'):
                    added = await engine.add_dictionary_tokens(tokens)
                    added_total += added
                elif hasattr(engine, 'config') and hasattr(engine.config, 'dict_file'):
                    # Write to AFL dictionary file
                    dict_path = engine.config.dict_file
                    with open(dict_path, 'a') as f:
                        for token in tokens:
                            if isinstance(token, bytes):
                                f.write(f'"{token.hex()}"\n')
                            else:
                                f.write(f'"{token}"\n')
                    added_total += len(tokens)

            except Exception as e:
                logger.warning(f"Failed to add dictionary tokens: {e}")

        logger.info(f"Added {added_total} dictionary tokens")
        return f"added_{added_total}_dictionary_entries"

    async def _scale_up(self, params: Dict[str, Any]) -> str:
        """Scale up fuzzing resources - ACTUALLY spawn new engine instances."""
        additional = params.get("engines", 1)
        spawned = 0

        # Get reference config from first engine
        if not self.engines:
            return "no_engines_to_scale_from"

        base_config = self.engines[0].config if hasattr(self.engines[0], 'config') else None

        for i in range(additional):
            try:
                new_id = f"engine_{len(self.engines) + i}_{int(time.time())}"

                # Create new engine with similar config
                from backend.services.fuzzing_engine_wrapper import create_engine
                new_engine = create_engine(new_id, base_config)

                if new_engine:
                    await new_engine.start()
                    self.engines.append(new_engine)
                    spawned += 1

            except Exception as e:
                logger.warning(f"Failed to spawn additional engine: {e}")

        logger.info(f"Scaled up by {spawned} engines (requested {additional})")
        return f"scaled_up_by_{spawned}_engines"

    async def _scale_down(self, params: Dict[str, Any]) -> str:
        """Scale down fuzzing resources - ACTUALLY stop engine instances."""
        reduce_by = min(params.get("engines", 1), len(self.engines) - 1)  # Keep at least 1

        if reduce_by <= 0:
            return "cannot_scale_below_1_engine"

        stopped = 0
        engines_to_remove = self.engines[-reduce_by:]  # Remove from end

        for engine in engines_to_remove:
            try:
                await engine.stop()
                self.engines.remove(engine)
                stopped += 1
            except Exception as e:
                logger.warning(f"Failed to stop engine: {e}")

        logger.info(f"Scaled down by {stopped} engines")
        return f"scaled_down_by_{stopped}_engines"

    async def _triage_crash(self, params: Dict[str, Any]) -> str:
        """
        Triage a specific crash with verification and optional minimization.

        Steps:
        1. Verify crash is reproducible
        2. Minimize crash input (optional)
        3. Analyze and classify exploitability
        """
        crash_id = params.get("crash_id")
        crash_data = params.get("crash_data")
        crash_input = params.get("input")
        crash_input_path = params.get("input_path")
        binary_path = params.get("binary_path")
        minimize = params.get("minimize", True)

        if not crash_id:
            return "no_crash_id_provided"

        # Step 1: Verify crash using AFL++ service if available
        if self.aflpp_service and crash_input_path and binary_path:
            try:
                verification = await self.aflpp_service.verify_crash(
                    binary_path=binary_path,
                    crash_input_path=crash_input_path,
                    timeout_ms=5000,
                )

                if not verification.verified:
                    logger.warning(f"Crash {crash_id} could not be verified (not reproducible)")
                    return f"crash_{crash_id}_not_reproducible"

                logger.info(
                    f"Crash {crash_id} verified: type={verification.crash_type}, "
                    f"reproducible={verification.reproducible}"
                )

                # Step 2: Minimize crash input if requested
                if minimize and verification.reproducible:
                    import tempfile
                    minimized_path = os.path.join(
                        tempfile.gettempdir(),
                        f"minimized_{crash_id}"
                    )

                    min_result = await self.aflpp_service.minimize_crash(
                        binary_path=binary_path,
                        crash_input_path=crash_input_path,
                        output_path=minimized_path,
                        timeout_ms=5000,
                    )

                    if min_result.minimized_input:
                        reduction = (1 - min_result.minimized_size / min_result.original_size) * 100
                        logger.info(
                            f"Crash {crash_id} minimized: "
                            f"{min_result.original_size} -> {min_result.minimized_size} bytes "
                            f"({reduction:.1f}% reduction)"
                        )
                        # Update crash_input with minimized version
                        crash_input = min_result.minimized_input

            except Exception as e:
                logger.warning(f"Crash verification/minimization failed: {e}")

        # Step 3: Triage crash for exploitability
        if self.crash_triage:
            try:
                result = await self.crash_triage.triage_crash(
                    crash_id=crash_id,
                    crash_data=crash_data,
                    triggering_input=crash_input,
                )
                exploitability = result.exploitability.value if result else "unknown"
                logger.info(f"Triaged crash {crash_id}: {exploitability}")
                return f"triaged_{crash_id}_as_{exploitability}"
            except Exception as e:
                logger.error(f"Crash triage failed: {e}")
                return f"triage_failed_{crash_id}"
        else:
            return "crash_triage_service_unavailable"

    async def _generate_exploit(self, params: Dict[str, Any]) -> str:
        """Generate exploit for crash - ACTUALLY synthesize and optionally verify."""
        crash_id = params.get("crash_id")
        crash_analysis = params.get("crash_analysis")
        binary_profile = params.get("binary_profile")
        verify = params.get("verify", False)

        if not crash_id:
            return "no_crash_id_provided"

        if self.exploit_synth:
            try:
                result = await self.exploit_synth.synthesize_exploit(
                    crash_analysis=crash_analysis,
                    binary_profile=binary_profile,
                )

                if result and result.exploit_skeleton:
                    logger.info(f"Generated exploit for {crash_id}, confidence: {result.confidence}")

                    # Optionally verify the exploit
                    if verify:
                        try:
                            from backend.services.exploit_verification_service import verify_exploit
                            verification = await verify_exploit(
                                target_binary=binary_profile.file_path if binary_profile else "",
                                payload_data=result.exploit_skeleton.code.encode(),
                                goal="crash",
                            )
                            return f"exploit_generated_for_{crash_id}_verified_{verification.status}"
                        except Exception as ve:
                            logger.warning(f"Exploit verification failed: {ve}")

                    return f"exploit_generated_for_{crash_id}_confidence_{result.confidence:.0%}"
                else:
                    return f"exploit_synthesis_failed_for_{crash_id}"

            except Exception as e:
                logger.error(f"Exploit generation failed: {e}")
                return f"exploit_failed_{crash_id}"
        else:
            return "exploit_synthesizer_unavailable"

    async def _directed_fuzzing(self, params: Dict[str, Any]) -> str:
        """Configure directed fuzzing toward targets - ACTUALLY set up AFLGo-style directed fuzzing."""
        targets = params.get("targets", [])  # List of (function, address) tuples
        distance_weights = params.get("distance_weights", True)

        if not targets:
            return "no_targets_provided"

        configured = 0
        for engine in self.engines:
            try:
                if hasattr(engine, 'config'):
                    engine.config.directed_mode = True
                    engine.config.target_locations = targets
                    engine.config.use_distance_weights = distance_weights
                    engine.config.power_schedule = "exploit"  # Prioritize paths to targets
                    configured += 1

                if hasattr(engine, 'set_directed_targets'):
                    await engine.set_directed_targets(targets)

            except Exception as e:
                logger.warning(f"Failed to configure directed fuzzing: {e}")

        logger.info(f"Configured {configured} engines for directed fuzzing to {len(targets)} targets")
        return f"directed_{configured}_engines_to_{len(targets)}_targets"


# =============================================================================
# Binary Campaign Controller
# =============================================================================

class BinaryCampaignController:
    """
    Autonomous campaign management with AI decision-making.

    This controller now uses:
    - EnginePool for robust engine management with automatic failover
    - CampaignPersistenceService for database persistence and recovery
    - Comprehensive error handling throughout the autonomous loop
    """

    def __init__(
        self,
        ai_client: Optional[BinaryAIClient] = None,
        binary_analyzer: Optional[BinaryAnalysisService] = None,
        crash_triage: Optional[CrashTriageService] = None,
        seed_intelligence: Optional[SeedIntelligenceService] = None,
        exploit_synthesizer: Optional[ExploitSynthesizer] = None,
        persistence_service: Optional[CampaignPersistenceService] = None,
        use_mock_engines: bool = False,
    ):
        self.ai_client = ai_client
        self.use_mock_engines = use_mock_engines

        # Services - initialize with error handling
        try:
            self.binary_analyzer = binary_analyzer or BinaryAnalysisService(ai_client)
        except Exception as e:
            logger.warning(f"Failed to init binary analyzer: {e}")
            self.binary_analyzer = None

        try:
            self.crash_triage = crash_triage or CrashTriageService(ai_client)
        except Exception as e:
            logger.warning(f"Failed to init crash triage: {e}")
            self.crash_triage = None

        try:
            self.seed_intelligence = seed_intelligence or SeedIntelligenceService(ai_client)
        except Exception as e:
            logger.warning(f"Failed to init seed intelligence: {e}")
            self.seed_intelligence = None

        try:
            self.exploit_synthesizer = exploit_synthesizer or ExploitSynthesizer(ai_client)
        except Exception as e:
            logger.warning(f"Failed to init exploit synthesizer: {e}")
            self.exploit_synthesizer = None

        # Persistence service for database operations
        try:
            self.persistence = persistence_service or get_persistence_service()
        except Exception as e:
            logger.warning(f"Failed to init persistence service: {e}")
            self.persistence = None

        # AI reasoning components - optional
        self.campaign_planner = CampaignPlanner(ai_client) if ai_client else None
        self.strategy_selector = StrategySelector(ai_client) if ai_client else None
        self.coverage_advisor = CoverageAdvisor(ai_client) if ai_client else None
        self.decision_generator = DecisionGenerator(ai_client) if ai_client else None

        # State
        self._campaigns: Dict[str, Dict[str, Any]] = {}
        self._active_campaign: Optional[str] = None
        self._engine_pools: Dict[str, EnginePool] = {}  # Engine pool per campaign

        # AI feedback loop for learning from outcomes
        self.feedback_loop = get_feedback_loop()

        # Power schedule service for intelligent seed prioritization
        try:
            self.power_schedule = get_power_schedule_service(PowerSchedule.EXPLORE)
            logger.info("Power schedule service initialized (EXPLORE mode)")
        except Exception as e:
            logger.warning(f"Failed to init power schedule: {e}")
            self.power_schedule = None

        # Crash deduplication service for efficient crash bucketing
        try:
            self.crash_dedup = get_crash_deduplication_service()
            logger.info("Crash deduplication service initialized")
        except Exception as e:
            logger.warning(f"Failed to init crash deduplication: {e}")
            self.crash_dedup = None

        # CMPLOG service for comparison operand tracking
        try:
            self.cmplog = get_comparison_logging_service()
            logger.info("CMPLOG service initialized")
        except Exception as e:
            logger.warning(f"Failed to init CMPLOG service: {e}")
            self.cmplog = None

        # Persistent mode service for 10-100x speedup
        try:
            self.persistent_mode = get_persistent_mode_service(PersistentConfig(
                mode_type=PersistentModeType.AFL_LOOP,
                iterations_per_loop=10000,
                use_shared_memory=True,
                deferred_forkserver=True,
            ))
            speedup, explanation = self.persistent_mode.estimate_speedup()
            logger.info(f"Persistent mode service initialized (estimated {speedup:.0f}x speedup)")
        except Exception as e:
            logger.warning(f"Failed to init persistent mode: {e}")
            self.persistent_mode = None

        # AGENTIC REASONING ENGINE - The brain of the fuzzer
        # This provides:
        # 1. Memory - Remembers past decisions and their outcomes
        # 2. Chain-of-thought reasoning - Multi-step thinking
        # 3. Exploration vs exploitation - Strategic action selection
        # 4. Learning - Improves decisions based on feedback
        try:
            self.agentic_engine = get_agentic_engine(
                ai_client=ai_client,
                feedback_loop=self.feedback_loop,
            )
            logger.info("Agentic reasoning engine initialized - TRUE AGENTIC AI ENABLED")
        except Exception as e:
            logger.warning(f"Failed to init agentic engine: {e}")
            self.agentic_engine = None

        # AFL++ FEATURE SELECTOR - Intelligent AFL++ configuration
        # Uses agentic memory to select optimal AFL++ features based on:
        # 1. Campaign state (coverage, crashes, elapsed time)
        # 2. Target characteristics (binary type, size, complexity)
        # 3. Historical performance data (what worked before)
        try:
            # Share memory with agentic engine for unified learning
            agentic_memory = self.agentic_engine.memory if self.agentic_engine else None
            self.feature_selector = get_feature_selector(agentic_memory)
            logger.info("AFL++ feature selector initialized - INTELLIGENT AFL++ CONFIG ENABLED")
        except Exception as e:
            logger.warning(f"Failed to init feature selector: {e}")
            self.feature_selector = None

        # AFL++ FULL INTEGRATION SERVICE - All AFL++ capabilities
        # Provides access to:
        # - All power schedules (fast, coe, explore, exploit, rare, etc.)
        # - CMPLOG for automatic comparison solving
        # - Parallel fuzzing with corpus sync (-M/-S)
        # - Corpus minimization (afl-cmin, afl-tmin)
        # - Dictionary generation
        # - Coverage analysis
        try:
            self.aflpp_service = get_aflpp_service()
            available = [k for k, v in self.aflpp_service.available_tools.items() if v]
            logger.info(f"AFL++ full integration initialized - Tools: {available[:5]}...")
        except Exception as e:
            logger.warning(f"Failed to init AFL++ full service: {e}")
            self.aflpp_service = None

        # Check fuzzer availability
        self._fuzzer_availability = check_fuzzer_availability()
        if not any(self._fuzzer_availability.values()):
            logger.info("No real fuzzers available, will use mock mode")
            self.use_mock_engines = True

    async def start_campaign(
        self,
        binary_path: str,
        config: CampaignConfig,
    ) -> str:
        """
        Initialize and start a new fuzzing campaign with robust error handling.

        Uses EnginePool for engine management and persists state to database.
        Falls back gracefully when components are unavailable.
        """
        campaign_id = str(uuid.uuid4())[:8]

        logger.info(f"Starting campaign {campaign_id} for {binary_path}")

        # Validate binary path
        if not binary_path or not os.path.exists(binary_path):
            raise ValueError(f"Invalid binary path: {binary_path}")

        # Read binary for hashing
        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()
            binary_hash = hashlib.sha256(binary_data).hexdigest()[:16]
        except Exception as e:
            logger.error(f"Failed to read binary: {e}")
            raise ValueError(f"Cannot read binary: {e}")

        # Initialize campaign state
        campaign = {
            "id": campaign_id,
            "config": config,
            "binary_path": binary_path,
            "binary_hash": binary_hash,
            "binary_name": os.path.basename(binary_path),
            "status": CampaignStatus.INITIALIZING,
            "started_at": datetime.utcnow(),
            "engine_pool": None,
            "engines": [],  # For backward compatibility
            "profile": None,
            "plan": None,
            "state": None,
            "feedback_aggregator": FeedbackAggregator(),
            "decision_executor": None,
            "decisions": [],
            "crashes": [],
            "checkpoints": [],
            "error_count": 0,
            "max_errors": 10,  # Max errors before pausing
        }

        self._campaigns[campaign_id] = campaign
        self._active_campaign = campaign_id

        # Create engine pool for this campaign
        engine_pool = EnginePool(max_engines=config.max_engines)
        self._engine_pools[campaign_id] = engine_pool
        campaign["engine_pool"] = engine_pool

        try:
            # Phase 0: Prepare binary (check instrumentation, enable QEMU if needed)
            campaign["status"] = CampaignStatus.PLANNING
            try:
                prepared_binary, use_qemu, use_frida = await self._ensure_instrumented_binary(
                    binary_path, config
                )
                campaign["prepared_binary"] = prepared_binary
                campaign["use_qemu_mode"] = use_qemu
                campaign["use_frida_mode"] = use_frida

                # Update binary path to use prepared binary
                if prepared_binary != binary_path:
                    config.binary_path = prepared_binary
                    binary_path = prepared_binary
                    logger.info(f"Using prepared binary: {prepared_binary}")

            except Exception as e:
                logger.warning(f"Binary preparation failed: {e}, using original binary")
                campaign["prepared_binary"] = binary_path
                campaign["use_qemu_mode"] = False
                campaign["use_frida_mode"] = False

            # Phase 1: Analyze binary (with timeout)
            try:
                profile = await asyncio.wait_for(
                    self._analyze_binary(binary_path, config),
                    timeout=120.0  # 2 minute timeout for analysis
                )
                campaign["profile"] = profile
            except asyncio.TimeoutError:
                logger.warning("Binary analysis timed out, using minimal profile")
                profile = self._create_minimal_profile(binary_path, binary_data)
                campaign["profile"] = profile
            except Exception as e:
                logger.warning(f"Binary analysis failed: {e}, using minimal profile")
                profile = self._create_minimal_profile(binary_path, binary_data)
                campaign["profile"] = profile

            # Phase 2: Create campaign plan with AI (optional)
            try:
                plan = await asyncio.wait_for(
                    self._create_plan(profile, config),
                    timeout=60.0
                )
                campaign["plan"] = plan
            except Exception as e:
                logger.warning(f"AI planning failed: {e}, using default plan")
                plan = None
                campaign["plan"] = None

            # Phase 2.5: Auto-generate dictionary for better fuzzing
            dictionary_path = await self._auto_generate_dictionary(
                binary_path, config, profile, campaign_id
            )
            if dictionary_path:
                config.dictionary_path = dictionary_path
                campaign["dictionary_path"] = dictionary_path

            # Phase 3: Initialize fuzzing engines using EnginePool
            # Pass QEMU/FRIDA flags from binary preparation
            engines = await self._setup_engines_pool(
                campaign_id, plan, config,
                use_qemu=campaign.get("use_qemu_mode", False),
                use_frida=campaign.get("use_frida_mode", False),
            )
            campaign["engines"] = engines

            if not engines:
                raise RuntimeError("Failed to start any fuzzing engines")

            # Phase 4: Generate initial seeds
            await self._generate_initial_seeds(profile, plan, engines)

            # Phase 5: Set up decision executor with AFL++ service
            campaign["decision_executor"] = DecisionExecutor(
                engines,
                self.seed_intelligence,
                self.crash_triage,
                self.exploit_synthesizer,
                self.aflpp_service,  # Pass AFL++ full integration service
            )

            # Phase 6: Initialize campaign state
            campaign["state"] = CampaignState(
                campaign_id=campaign_id,
                current_strategy=plan.initial_strategy if plan else FuzzingStrategy.COVERAGE_GUIDED,
                elapsed_time=timedelta(0),
                total_executions=0,
                coverage_percentage=0,
                unique_crashes=0,
                exploitable_crashes=0,
                corpus_size=0,
                edges_discovered=0,
            )

            # Phase 7: Persist campaign to database
            if self.persistence:
                try:
                    await self.persistence.save_campaign(
                        campaign_id=campaign_id,
                        binary_hash=binary_hash,
                        binary_name=campaign["binary_name"],
                        status=CampaignStatus.RUNNING.value,
                        config=self._config_to_dict(config),
                        profile=self._profile_to_dict(profile) if profile else None,
                        plan=self._plan_to_dict(plan) if plan else None,
                    )
                except Exception as e:
                    logger.warning(f"Failed to persist campaign: {e}")

            # Phase 8: Start autonomous loop
            campaign["status"] = CampaignStatus.RUNNING
            campaign["loop_task"] = asyncio.create_task(
                self._run_autonomous_loop(campaign_id)
            )

            logger.info(f"Campaign {campaign_id} started successfully with {len(engines)} engines")
            return campaign_id

        except Exception as e:
            logger.error(f"Failed to start campaign: {e}\n{traceback.format_exc()}")
            campaign["status"] = CampaignStatus.FAILED
            campaign["error"] = str(e)

            # Clean up engine pool
            if campaign_id in self._engine_pools:
                try:
                    await self._engine_pools[campaign_id].stop_all()
                except Exception:
                    pass

            # Update persistence
            if self.persistence:
                try:
                    await self.persistence.update_campaign_status(
                        campaign_id, CampaignStatus.FAILED.value
                    )
                except Exception:
                    pass

            raise

    async def _auto_instrument_binary(
        self,
        source_path: str,
        output_path: str,
        create_cmplog: bool = True,
    ) -> Optional[str]:
        """
        Automatically compile/instrument a target for fuzzing.

        This enables "source-to-fuzz" workflow where users provide source code
        and we handle all instrumentation automatically.

        Args:
            source_path: Path to source file (.c, .cpp, .cc)
            output_path: Path for instrumented output binary
            create_cmplog: Whether to create a CMPLOG binary too

        Returns:
            Path to instrumented binary, or None if failed
        """
        if not self.aflpp_service:
            logger.warning("AFL++ service not available for auto-instrumentation")
            return None

        # Check if source file exists
        if not os.path.exists(source_path):
            logger.error(f"Source file not found: {source_path}")
            return None

        # Determine if it's a source file
        ext = os.path.splitext(source_path)[1].lower()
        if ext not in ['.c', '.cpp', '.cc', '.cxx']:
            logger.info(f"Not a source file ({ext}), skipping instrumentation")
            return None

        logger.info(f"AUTO-INSTRUMENTING: {source_path} -> {output_path}")

        try:
            from backend.services.aflpp_full_integration import AFLInstrumentMode, AFLSanitizer

            # Compile with instrumentation
            result = await self.aflpp_service.compile_target(
                source_path=source_path,
                output_path=output_path,
                instrument_mode=AFLInstrumentMode.PCGUARD,  # Best for modern coverage
                sanitizers=[AFLSanitizer.ASAN],  # Address sanitizer for crash detection
                create_cmplog=create_cmplog,
                extra_flags=["-g", "-O2"],  # Debug info + optimization
            )

            if result.success:
                logger.info(
                    f"AUTO-INSTRUMENTATION SUCCESS: "
                    f"binary={result.instrumented_binary}, "
                    f"cmplog={result.cmplog_binary or 'N/A'}, "
                    f"time={result.compile_time_seconds:.1f}s"
                )
                return result.instrumented_binary
            else:
                logger.error(f"AUTO-INSTRUMENTATION FAILED: {result.error_message}")
                return None

        except Exception as e:
            logger.error(f"Auto-instrumentation error: {e}")
            return None

    async def _check_binary_instrumented(self, binary_path: str) -> bool:
        """
        Check if a binary is already AFL++ instrumented.

        Looks for AFL++ instrumentation markers in the binary.
        """
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()

            # Check for AFL++ instrumentation markers
            afl_markers = [
                b'__AFL_SHM_ID',
                b'__afl_area_ptr',
                b'__afl_prev_loc',
                b'__afl_fuzz_ptr',
                b'AFL',
            ]

            for marker in afl_markers:
                if marker in binary_data:
                    logger.info(f"Binary appears to be AFL++ instrumented (found {marker.decode(errors='ignore')})")
                    return True

            return False

        except Exception as e:
            logger.debug(f"Error checking instrumentation: {e}")
            return False

    async def _ensure_instrumented_binary(
        self,
        binary_path: str,
        config: CampaignConfig,
    ) -> Tuple[str, bool, bool]:
        """
        Ensure we have an instrumented binary for fuzzing.

        If the provided binary is not instrumented, attempt to find
        source and compile it, or enable QEMU/FRIDA mode for uninstrumented binaries.

        Returns:
            Tuple of (binary_path, use_qemu_mode, use_frida_mode)
        """
        # Check if already instrumented
        if await self._check_binary_instrumented(binary_path):
            logger.info(f"Binary is already instrumented: {binary_path}")
            return binary_path, False, False

        # Check for source file with same name
        source_extensions = ['.c', '.cpp', '.cc', '.cxx']
        base_path = os.path.splitext(binary_path)[0]

        for ext in source_extensions:
            source_path = base_path + ext
            if os.path.exists(source_path):
                logger.info(f"Found source file: {source_path}")

                # Create instrumented binary
                instrumented_path = binary_path + ".afl"
                result = await self._auto_instrument_binary(
                    source_path=source_path,
                    output_path=instrumented_path,
                    create_cmplog=True,
                )

                if result:
                    return result, False, False

        # No source found - determine best emulation mode
        # Check if FRIDA is available (faster than QEMU)
        import shutil
        use_frida = shutil.which("frida") is not None or shutil.which("frida-trace") is not None
        use_qemu = shutil.which("qemu-x86_64") is not None or shutil.which("afl-qemu-trace") is not None

        if use_frida:
            logger.info(
                f"Binary not instrumented - enabling FRIDA mode "
                f"(faster than QEMU for uninstrumented binaries)"
            )
            return binary_path, False, True
        elif use_qemu:
            logger.info(
                f"Binary not instrumented - enabling QEMU mode "
                f"(allows fuzzing without source code)"
            )
            return binary_path, True, False
        else:
            logger.warning(
                f"Binary not instrumented and no emulation mode available. "
                f"Install afl++-qemu or frida for uninstrumented binary support. "
                f"Fuzzing may not work correctly."
            )
            return binary_path, False, False

    async def _auto_generate_dictionary(
        self,
        binary_path: str,
        config: CampaignConfig,
        profile: BinaryProfile,
        campaign_id: str,
    ) -> Optional[str]:
        """
        Auto-generate a fuzzing dictionary from the binary and profile.

        Extracts useful tokens from:
        1. Binary strings (magic bytes, format strings, keywords)
        2. Known input handlers from profile
        3. Sample inputs if available

        Returns path to generated dictionary, or None if generation failed.
        """
        # Skip if dictionary already provided
        if hasattr(config, 'dictionary_path') and config.dictionary_path:
            if os.path.exists(config.dictionary_path):
                logger.info(f"Using provided dictionary: {config.dictionary_path}")
                return config.dictionary_path

        # Skip if AFL++ service not available
        if not self.aflpp_service:
            logger.debug("AFL++ service not available for dictionary generation")
            return None

        try:
            import tempfile
            dict_dir = os.path.join(tempfile.gettempdir(), f"dict_{campaign_id}")
            os.makedirs(dict_dir, exist_ok=True)
            dict_path = os.path.join(dict_dir, "auto_generated.dict")

            # Collect sample inputs if seed directory exists
            sample_inputs = []
            if config.seed_dir and os.path.exists(config.seed_dir):
                for f in os.listdir(config.seed_dir)[:10]:  # Limit to 10 samples
                    sample_path = os.path.join(config.seed_dir, f)
                    if os.path.isfile(sample_path):
                        sample_inputs.append(sample_path)

            # Generate dictionary using AFL++ service
            num_tokens = await self.aflpp_service.generate_dictionary(
                binary_path=binary_path,
                output_path=dict_path,
                sample_inputs=sample_inputs if sample_inputs else None,
            )

            if num_tokens > 0:
                # Enhance dictionary with profile information
                await self._enhance_dictionary_from_profile(dict_path, profile)

                logger.info(
                    f"AUTO-GENERATED DICTIONARY: {num_tokens}+ tokens at {dict_path}"
                )
                return dict_path
            else:
                logger.debug("Dictionary generation produced no tokens")
                return None

        except Exception as e:
            logger.warning(f"Dictionary auto-generation failed: {e}")
            return None

    async def _enhance_dictionary_from_profile(
        self,
        dict_path: str,
        profile: BinaryProfile,
    ) -> None:
        """Enhance dictionary with tokens from binary profile analysis."""
        try:
            additional_tokens = set()

            # Extract tokens from input handlers
            if hasattr(profile, 'input_handlers'):
                for handler in profile.input_handlers:
                    if hasattr(handler, 'format_hints'):
                        for hint in handler.format_hints:
                            if isinstance(hint, str) and 2 <= len(hint) <= 32:
                                additional_tokens.add(hint)

            # Extract from vulnerability hints
            if hasattr(profile, 'vulnerability_hints'):
                for hint in profile.vulnerability_hints:
                    if hasattr(hint, 'context'):
                        # Extract potential magic bytes or keywords
                        context = str(hint.context)
                        for word in context.split():
                            if 2 <= len(word) <= 16 and word.isalnum():
                                additional_tokens.add(word)

            # Extract from strings in profile
            if hasattr(profile, 'interesting_strings'):
                for s in profile.interesting_strings[:50]:
                    if isinstance(s, str) and 2 <= len(s) <= 32:
                        additional_tokens.add(s)

            # Append to dictionary
            if additional_tokens:
                with open(dict_path, 'a') as f:
                    for i, token in enumerate(sorted(additional_tokens)):
                        escaped = token.replace('\\', '\\\\').replace('"', '\\"')
                        f.write(f'profile_token_{i}="{escaped}"\n')

                logger.debug(f"Added {len(additional_tokens)} tokens from profile to dictionary")

        except Exception as e:
            logger.debug(f"Failed to enhance dictionary from profile: {e}")

    async def _analyze_binary(
        self,
        binary_path: str,
        config: CampaignConfig,
    ) -> BinaryProfile:
        """Analyze the target binary."""
        logger.info(f"Analyzing binary: {binary_path}")

        # Read binary data
        with open(binary_path, "rb") as f:
            binary_data = f.read()

        # Run analysis
        profile = await self.binary_analyzer.analyze(
            binary_data,
            os.path.basename(binary_path),
        )

        return profile

    async def _create_plan(
        self,
        profile: BinaryProfile,
        config: CampaignConfig,
    ) -> Optional[CampaignPlan]:
        """Create campaign plan using AI."""
        if not self.campaign_planner:
            logger.warning("No AI client - using default plan")
            return None

        logger.info("Creating AI campaign plan")

        try:
            plan = await self.campaign_planner.create_plan(
                profile=profile,
                time_budget=config.max_duration,
                resource_config={
                    "max_engines": config.max_engines,
                    "memory_limit": config.memory_limit_mb,
                    "cpu_cores": config.cpu_cores,
                },
            )
            return plan
        except Exception as e:
            logger.warning(f"AI planning failed: {e}, using defaults")
            return None

    async def _setup_engines_pool(
        self,
        campaign_id: str,
        plan: Optional[CampaignPlan],
        config: CampaignConfig,
        use_qemu: bool = False,
        use_frida: bool = False,
    ) -> List[FuzzingEngine]:
        """
        Set up fuzzing engines using EnginePool for robust management.

        Args:
            campaign_id: Unique campaign identifier
            plan: Optional campaign plan from AI
            config: Campaign configuration
            use_qemu: Enable QEMU mode for uninstrumented binaries
            use_frida: Enable FRIDA mode for uninstrumented binaries

        Falls back to mock mode if real fuzzers are unavailable.
        """
        engine_pool = self._engine_pools.get(campaign_id)
        if not engine_pool:
            engine_pool = EnginePool(max_engines=config.max_engines)
            self._engine_pools[campaign_id] = engine_pool

        engines = []

        # Determine number of engines
        num_engines = min(config.max_engines, MAX_CONCURRENT_ENGINES)

        # Create output directories (cross-platform)
        import tempfile
        base_output = os.path.join(tempfile.gettempdir(), f"fuzzing_{campaign_id}")
        os.makedirs(base_output, exist_ok=True)

        # Set up seed directory
        seed_dir = config.seed_dir or os.path.join(base_output, "seeds")
        os.makedirs(seed_dir, exist_ok=True)

        # Add a minimal seed if directory is empty
        if not os.listdir(seed_dir):
            with open(os.path.join(seed_dir, "seed_default"), "wb") as f:
                f.write(b"AAAA")

        # =======================================================================
        # INTELLIGENT AFL++ FEATURE SELECTION
        # Use the AFLPPFeatureSelector to dynamically choose optimal config
        # =======================================================================

        # Check for CMPLOG binary (target compiled with afl-clang-fast -c)
        cmplog_binary = None
        cmplog_path = config.binary_path + ".cmplog"
        if os.path.exists(cmplog_path):
            cmplog_binary = cmplog_path
            logger.info(f"Found CMPLOG binary: {cmplog_path}")

        # Check for dictionary
        dictionary_path = config.dictionary_path if hasattr(config, 'dictionary_path') else None

        # Build target info for intelligent selection
        target_info = {
            "binary_path": config.binary_path,
            "has_cmplog_binary": cmplog_binary is not None,
            "has_dictionary": dictionary_path is not None,
            "input_format": config.input_type,
            "has_magic_bytes": True,  # Assume yes, CMPLOG will help
        }

        # Build initial campaign state
        initial_campaign_state = {
            "campaign_id": campaign_id,
            "coverage_percentage": 0,
            "unique_crashes": 0,
            "executions_per_second": 0,
            "total_executions": 0,
            "coverage_trend": "unknown",
            "elapsed_fraction": 0,  # Just starting
        }

        # Get intelligent configuration from feature selector
        if self.feature_selector:
            try:
                optimal_config = self.feature_selector.get_optimal_config(
                    campaign_state=initial_campaign_state,
                    target_info=target_info,
                    available_cpus=num_engines,
                )
                logger.info(
                    f"AFL++ INTELLIGENT CONFIG: "
                    f"schedule={optimal_config['power_schedule']}, "
                    f"cmplog={optimal_config['enable_cmplog']} "
                    f"({optimal_config['cmplog_reason']}), "
                    f"parallel={optimal_config['parallel']['num_instances']} instances"
                )

                # Use the optimal parallel configuration
                parallel_configs = optimal_config.get('parallel', {}).get('configs', [])
                mutation_config = optimal_config.get('mutation', {})

            except Exception as e:
                logger.warning(f"Intelligent config failed: {e}, using defaults")
                optimal_config = None
                parallel_configs = []
                mutation_config = {}
        else:
            optimal_config = None
            parallel_configs = []
            mutation_config = {}

        # Set up engines with intelligent or default configuration
        for i in range(num_engines):
            engine_id = f"engine_{campaign_id}_{i}"
            output_dir = os.path.join(base_output, f"output_{i}")
            os.makedirs(output_dir, exist_ok=True)

            # Get configuration for this engine instance
            if parallel_configs and i < len(parallel_configs):
                # Use intelligent config for this instance
                instance_config = parallel_configs[i]
                engine_power_schedule = instance_config.get("power_schedule", "explore")
                skip_deterministic = instance_config.get("skip_deterministic", i > 0)
                is_main = instance_config.get("role") == "main"
            elif optimal_config:
                # Use optimal config's main schedule with diversity
                engine_schedules = ["explore", "rare", "fast", "coe", "exploit", "seek", "mmopt", "quad"]
                engine_power_schedule = optimal_config.get("power_schedule", engine_schedules[i % len(engine_schedules)])
                skip_deterministic = i > 0
                is_main = i == 0
            else:
                # Fallback to diverse schedules
                engine_schedules = ["explore", "rare", "fast", "coe", "exploit", "seek", "mmopt", "quad"]
                engine_power_schedule = engine_schedules[i % len(engine_schedules)]
                skip_deterministic = i > 0
                is_main = i == 0

            # Determine if CMPLOG should be enabled for this instance
            use_cmplog = cmplog_binary is not None
            if optimal_config:
                # Only enable CMPLOG on main instance if intelligent config says so
                use_cmplog = cmplog_binary is not None and optimal_config.get("enable_cmplog", True) and is_main

            # Build engine configuration
            engine_config = EngineConfig(
                engine_type=EngineType.AFLPP,
                binary_path=config.binary_path,
                seed_dir=seed_dir,
                output_dir=output_dir,
                timeout_ms=1000,
                memory_limit_mb=config.memory_limit_mb,
                mock_mode=self.use_mock_engines,
                # ============================================================
                # INTELLIGENT AFL++ NATIVE FEATURES
                # ============================================================
                power_schedule=engine_power_schedule,  # Intelligently selected
                cmplog_binary=cmplog_binary if use_cmplog else None,  # CMPLOG when beneficial
                use_mopt=mutation_config.get("use_mopt", True),  # Native AFL++ MOpt
                dictionary_path=dictionary_path,  # Native AFL++ dictionary support
                skip_deterministic=skip_deterministic,  # Only main does deterministic
                # ============================================================
                # QEMU/FRIDA MODE FOR UNINSTRUMENTED BINARIES
                # ============================================================
                qemu_mode=use_qemu,  # Auto-enabled if binary not instrumented
                frida_mode=use_frida,  # Faster than QEMU if FRIDA available
            )

            try:
                engine = await engine_pool.add_engine(
                    engine_id,
                    engine_config,
                    prefer_mock=self.use_mock_engines,
                )
                if engine:
                    engines.append(engine)
                    mode_str = "QEMU" if use_qemu else ("FRIDA" if use_frida else "native")
                    logger.info(
                        f"Started engine {engine_id} (INTELLIGENT, {mode_str}): "
                        f"schedule={engine_power_schedule}, "
                        f"mopt={mutation_config.get('use_mopt', True)}, "
                        f"cmplog={use_cmplog}, "
                        f"{'MAIN' if is_main else 'secondary'}"
                    )
                else:
                    logger.warning(f"Failed to add engine {engine_id}")
            except Exception as e:
                logger.error(f"Error setting up engine {engine_id}: {e}")

        logger.info(f"Set up {len(engines)} fuzzing engines for campaign {campaign_id}")
        return engines

    async def _setup_engines(
        self,
        plan: Optional[CampaignPlan],
        config: CampaignConfig,
    ) -> List[FuzzingEngine]:
        """Legacy method - redirects to _setup_engines_pool."""
        campaign_id = str(uuid.uuid4())[:8]
        return await self._setup_engines_pool(campaign_id, plan, config)

    async def _setup_native_parallel_fuzzing(
        self,
        campaign_id: str,
        config: CampaignConfig,
        num_instances: int,
    ) -> List[str]:
        """
        Set up native AFL++ parallel fuzzing with corpus synchronization.

        Uses AFL++'s built-in -M (main) and -S (secondary) modes for
        optimal parallel fuzzing with automatic corpus sharing.

        This provides:
        - Automatic corpus synchronization between instances
        - Diverse power schedule strategies for maximum coverage
        - Efficient CPU utilization via core pinning

        Returns list of instance IDs for monitoring.
        """
        if not self.aflpp_service:
            logger.warning("AFL++ service not available for native parallel fuzzing")
            return []

        # Get intelligent parallel configuration
        campaign_state = {
            "campaign_id": campaign_id,
            "coverage_percentage": 0,
            "unique_crashes": 0,
            "elapsed_fraction": 0,
        }

        target_info = {
            "binary_path": config.binary_path,
            "has_magic_bytes": True,
            "input_format": config.input_type,
        }

        if self.feature_selector:
            try:
                optimal_config = self.feature_selector.get_optimal_config(
                    campaign_state=campaign_state,
                    target_info=target_info,
                    available_cpus=num_instances,
                )
            except Exception as e:
                logger.warning(f"Feature selector failed: {e}")
                optimal_config = None
        else:
            optimal_config = None

        # Create sync directory for corpus sharing
        import tempfile
        sync_dir = os.path.join(tempfile.gettempdir(), f"sync_{campaign_id}")
        os.makedirs(sync_dir, exist_ok=True)

        # Set up seed directory
        seed_dir = config.seed_dir or os.path.join(sync_dir, "seeds")
        os.makedirs(seed_dir, exist_ok=True)

        # Add minimal seed if empty
        if not os.listdir(seed_dir):
            with open(os.path.join(seed_dir, "seed_default"), "wb") as f:
                f.write(b"AAAA")

        # Check for CMPLOG binary
        cmplog_binary = None
        cmplog_path = config.binary_path + ".cmplog"
        if os.path.exists(cmplog_path):
            cmplog_binary = cmplog_path

        # Check for dictionary
        dictionary_path = config.dictionary_path if hasattr(config, 'dictionary_path') else None

        # Build base configuration
        base_aflpp_config = AFLPPConfig(
            binary_path=config.binary_path,
            input_dir=seed_dir,
            output_dir=sync_dir,
            timeout_ms=1000,
            memory_limit_mb=config.memory_limit_mb,
            power_schedule=AFLPowerSchedule.EXPLORE,
            cmplog_binary=cmplog_binary,
            cmplog_level=2 if cmplog_binary else 0,
            mutator=AFLMutator.MOpt,
            dictionary_path=dictionary_path,
        )

        try:
            # Start parallel fuzzing using AFL++ native sync
            instance_ids = await self.aflpp_service.start_parallel_fuzzing(
                base_config=base_aflpp_config,
                num_instances=num_instances,
                sync_dir=sync_dir,
            )

            logger.info(
                f"NATIVE PARALLEL FUZZING: Started {len(instance_ids)} instances "
                f"with corpus sync in {sync_dir}"
            )

            # Store sync dir for monitoring
            campaign = self._campaigns.get(campaign_id)
            if campaign:
                campaign["sync_dir"] = sync_dir
                campaign["parallel_instance_ids"] = instance_ids

            return instance_ids

        except Exception as e:
            logger.error(f"Failed to start native parallel fuzzing: {e}")
            return []

    async def get_parallel_status(self, campaign_id: str) -> Dict[str, Any]:
        """Get status of parallel fuzzing instances for a campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}

        sync_dir = campaign.get("sync_dir")
        if not sync_dir or not self.aflpp_service:
            return {"error": "Parallel fuzzing not active"}

        try:
            status = await self.aflpp_service.get_parallel_status(sync_dir)
            return status
        except Exception as e:
            return {"error": str(e)}

    async def _generate_initial_seeds(
        self,
        profile: BinaryProfile,
        plan: Optional[CampaignPlan],
        engines: List[FuzzingEngine],
    ) -> None:
        """Generate initial seeds for fuzzing with power schedule integration."""
        logger.info("Generating initial seeds")

        seeds_added = 0

        try:
            # Use seed intelligence service
            result = await self.seed_intelligence.generate_seeds(
                profile,
                count=20,
            )

            # Distribute seeds to engines and register with power schedule
            for seed in result.seeds:
                seed_data = seed.data if hasattr(seed, 'data') else seed

                # Register seed with power schedule for energy calculation
                if self.power_schedule:
                    try:
                        # Initial edges_hit will be empty until we get coverage feedback
                        seed_info = self.power_schedule.add_seed(
                            seed_data=seed_data,
                            edges_hit=set(),  # Will be updated after first execution
                            exec_time_us=0,
                            depth=0,
                        )
                        logger.debug(f"Registered seed {seed_info.seed_id} with energy={seed_info.energy:.1f}")
                    except Exception as e:
                        logger.debug(f"Failed to register seed with power schedule: {e}")

                # Add to engines
                for engine in engines:
                    try:
                        await engine.add_seed(seed_data, seed.name if hasattr(seed, 'name') else None)
                        seeds_added += 1
                    except Exception as e:
                        logger.debug(f"Failed to add seed to engine: {e}")

        except Exception as e:
            logger.warning(f"Seed generation failed: {e}, using minimal seeds")
            # Add minimal default seeds
            default_seeds = [b"", b"A" * 100, b"\x00" * 100, b"test"]
            for seed_data in default_seeds:
                # Register with power schedule
                if self.power_schedule:
                    try:
                        self.power_schedule.add_seed(seed_data, edges_hit=set(), exec_time_us=0, depth=0)
                    except Exception:
                        pass

                for engine in engines:
                    try:
                        await engine.add_seed(seed_data)
                        seeds_added += 1
                    except Exception:
                        pass

        # Generate CMPLOG-guided mutations for magic byte handling
        if self.cmplog and seeds_added > 0:
            try:
                # Get a representative seed
                sample_seed = result.seeds[0].data if result and result.seeds else b"test"

                # Generate solving mutations that inject magic bytes
                solving_mutations = self.cmplog.generate_solving_mutations(
                    input_data=sample_seed,
                    max_mutations=10,
                )

                # Add CMPLOG-guided seeds
                for mutation in solving_mutations:
                    if self.power_schedule:
                        self.power_schedule.add_seed(mutation, edges_hit=set(), exec_time_us=0, depth=1)

                    for engine in engines:
                        try:
                            await engine.add_seed(mutation)
                            seeds_added += 1
                        except Exception:
                            pass

                logger.info(f"Added {len(solving_mutations)} CMPLOG-guided mutations with magic bytes")

            except Exception as e:
                logger.debug(f"CMPLOG mutation generation failed: {e}")

        logger.info(f"Initial seed generation complete: {seeds_added} seeds distributed")

    def _create_minimal_profile(self, binary_path: str, binary_data: bytes) -> BinaryProfile:
        """Create a minimal binary profile when full analysis fails."""
        import struct

        # Basic format detection
        format_type = "unknown"
        arch = "unknown"

        if binary_data[:4] == b'\x7fELF':
            format_type = "elf"
            arch = "x86_64" if binary_data[4] == 2 else "x86"
        elif binary_data[:2] == b'MZ':
            format_type = "pe"
            arch = "x86_64"  # Assume 64-bit for Windows
        elif binary_data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                   b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            format_type = "macho"
            arch = "x86_64"

        return BinaryProfile(
            name=os.path.basename(binary_path),
            format=format_type,
            architecture=arch,
            size=len(binary_data),
            hash=hashlib.sha256(binary_data).hexdigest()[:16],
            functions=[],
            imports=[],
            exports=[],
            strings=[],
            security_features={},
            vulnerabilities=[],
        )

    def _config_to_dict(self, config: CampaignConfig) -> Dict[str, Any]:
        """Convert CampaignConfig to dictionary for persistence."""
        try:
            return {
                "binary_path": config.binary_path,
                "input_type": config.input_type,
                "max_duration": str(config.max_duration) if config.max_duration else None,
                "decision_interval": config.decision_interval,
                "checkpoint_interval": config.checkpoint_interval,
                "max_engines": config.max_engines,
                "memory_limit_mb": config.memory_limit_mb,
                "cpu_cores": config.cpu_cores,
                "initial_strategy": config.initial_strategy.value if config.initial_strategy else None,
                "seed_dir": config.seed_dir,
                "generate_seeds": config.generate_seeds,
                "target_coverage": config.target_coverage,
                "target_crashes": config.target_crashes,
                "stop_on_exploitable": config.stop_on_exploitable,
                "enable_ai": config.enable_ai,
            }
        except Exception as e:
            logger.warning(f"Error converting config to dict: {e}")
            return {}

    def _profile_to_dict(self, profile: BinaryProfile) -> Dict[str, Any]:
        """Convert BinaryProfile to dictionary for persistence."""
        try:
            return {
                "name": profile.name,
                "format": profile.format,
                "architecture": profile.architecture,
                "size": profile.size,
                "hash": profile.hash,
                "functions_count": len(profile.functions) if profile.functions else 0,
                "imports_count": len(profile.imports) if profile.imports else 0,
                "security_features": profile.security_features or {},
            }
        except Exception as e:
            logger.warning(f"Error converting profile to dict: {e}")
            return {}

    def _plan_to_dict(self, plan: CampaignPlan) -> Dict[str, Any]:
        """Convert CampaignPlan to dictionary for persistence."""
        try:
            return {
                "initial_strategy": plan.initial_strategy.value if plan.initial_strategy else None,
                "phases": [str(p) for p in plan.phases] if plan.phases else [],
                "focus_areas": plan.focus_areas or [],
                "mutation_weights": plan.mutation_weights or {},
            }
        except Exception as e:
            logger.warning(f"Error converting plan to dict: {e}")
            return {}

    async def _run_autonomous_loop(self, campaign_id: str) -> None:
        """
        Main autonomous fuzzing loop with AI decisions.

        Features robust error handling:
        - Continues on individual iteration errors
        - Tracks error count to auto-pause on repeated failures
        - Persists state regularly for recovery
        - Uses EnginePool for automatic engine failover
        """
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            logger.error(f"Campaign {campaign_id} not found")
            return

        config = campaign["config"]
        engines = campaign["engines"]
        aggregator = campaign["feedback_aggregator"]
        executor = campaign["decision_executor"]
        engine_pool = campaign.get("engine_pool")

        decision_interval = config.decision_interval
        checkpoint_interval = config.checkpoint_interval
        last_checkpoint = datetime.utcnow()
        last_metrics_persist = datetime.utcnow()
        metrics_persist_interval = 30  # Persist metrics every 30 seconds

        logger.info(f"Starting autonomous loop for campaign {campaign_id}")

        # Engines are already started via EnginePool, no need to start again
        # Just verify they're running
        running_count = sum(1 for e in engines if e.is_running)
        logger.info(f"Autonomous loop starting with {running_count}/{len(engines)} engines running")

        iteration = 0
        consecutive_errors = 0
        max_consecutive_errors = 5

        try:
            while campaign["status"] == CampaignStatus.RUNNING:
                iteration += 1

                try:
                    # Check stopping conditions
                    if self._should_stop(campaign):
                        logger.info(f"Campaign {campaign_id} stopping condition met")
                        campaign["status"] = CampaignStatus.STOPPING
                        break

                    # Check if too many consecutive errors
                    if consecutive_errors >= max_consecutive_errors:
                        logger.warning(f"Campaign {campaign_id} pausing due to {consecutive_errors} consecutive errors")
                        campaign["status"] = CampaignStatus.PAUSED
                        campaign["error_count"] = campaign.get("error_count", 0) + consecutive_errors
                        break

                    # Check engine health via EnginePool
                    if engine_pool:
                        healthy_count = engine_pool.get_healthy_count()
                        if healthy_count == 0 and len(engines) > 0:
                            logger.warning("No healthy engines, waiting for recovery...")
                            await asyncio.sleep(5)
                            continue

                    # Collect feedback from all engines with timeout
                    try:
                        feedback = await asyncio.wait_for(
                            aggregator.collect(engines),
                            timeout=30.0
                        )
                    except asyncio.TimeoutError:
                        logger.warning("Feedback collection timed out")
                        consecutive_errors += 1
                        await asyncio.sleep(5)
                        continue

                    # Update campaign state
                    try:
                        self._update_campaign_state(campaign, feedback)
                    except Exception as e:
                        logger.warning(f"Failed to update campaign state: {e}")

                    # AI decision making with error handling
                    if config.enable_ai and self.decision_generator:
                        try:
                            decisions = await asyncio.wait_for(
                                self._make_ai_decisions(campaign, feedback),
                                timeout=30.0
                            )
                            campaign["decisions"].extend(decisions)

                            # Execute decisions
                            if executor and decisions:
                                try:
                                    results = await asyncio.wait_for(
                                        executor.execute(decisions),
                                        timeout=60.0
                                    )

                                    # Persist decisions
                                    if self.persistence:
                                        for decision, result in results:
                                            try:
                                                await self.persistence.save_decision(
                                                    campaign_id=campaign_id,
                                                    decision_id=decision.decision_id,
                                                    decision_type=decision.decision_type.value,
                                                    reasoning=decision.reasoning,
                                                    parameters=decision.parameters,
                                                    coverage_at_decision=campaign["state"].coverage_percentage,
                                                    crashes_at_decision=campaign["state"].unique_crashes,
                                                )
                                            except Exception as pe:
                                                logger.debug(f"Failed to persist decision: {pe}")

                                    # Handle special decisions
                                    for decision, result in results:
                                        if result == "pause_requested":
                                            campaign["status"] = CampaignStatus.PAUSED
                                        elif result == "terminate_requested":
                                            campaign["status"] = CampaignStatus.STOPPING
                                except asyncio.TimeoutError:
                                    logger.warning("Decision execution timed out")
                        except asyncio.TimeoutError:
                            logger.warning("AI decision making timed out")
                        except Exception as e:
                            logger.warning(f"AI decision error: {e}")

                    # Handle new crashes with error handling
                    try:
                        await self._handle_crashes(campaign, feedback)
                    except Exception as e:
                        logger.warning(f"Crash handling error: {e}")

                    # Periodic checkpoint
                    checkpoint_elapsed = (datetime.utcnow() - last_checkpoint).total_seconds()
                    if checkpoint_elapsed > checkpoint_interval:
                        try:
                            await self._save_checkpoint(campaign)
                            last_checkpoint = datetime.utcnow()
                        except Exception as e:
                            logger.warning(f"Checkpoint save error: {e}")

                    # Periodic metrics persistence
                    metrics_elapsed = (datetime.utcnow() - last_metrics_persist).total_seconds()
                    if metrics_elapsed > metrics_persist_interval and self.persistence:
                        try:
                            state = campaign["state"]
                            await self.persistence.update_campaign_metrics(
                                campaign_id=campaign_id,
                                total_executions=state.total_executions,
                                coverage_percentage=state.coverage_percentage,
                                edges_discovered=state.edges_discovered,
                                unique_crashes=state.unique_crashes,
                                exploitable_crashes=state.exploitable_crashes,
                                corpus_size=state.corpus_size,
                                current_strategy=state.current_strategy.value if state.current_strategy else "unknown",
                            )
                            # Also save coverage snapshot for trend analysis
                            await self.persistence.save_coverage_snapshot(
                                campaign_id=campaign_id,
                                coverage_percentage=state.coverage_percentage,
                                edges_discovered=state.edges_discovered,
                                total_executions=state.total_executions,
                                corpus_size=state.corpus_size,
                                execs_per_sec=feedback.executions_per_second,
                                unique_crashes=state.unique_crashes,
                                current_strategy=state.current_strategy.value if state.current_strategy else "unknown",
                            )
                            last_metrics_persist = datetime.utcnow()
                        except Exception as e:
                            logger.debug(f"Metrics persistence error: {e}")

                    # Reset consecutive errors on successful iteration
                    consecutive_errors = 0

                    # Log progress periodically
                    if iteration % 10 == 0:
                        state = campaign["state"]
                        logger.info(
                            f"Campaign {campaign_id} - iteration {iteration}: "
                            f"coverage={state.coverage_percentage:.1f}%, "
                            f"crashes={state.unique_crashes}, "
                            f"execs={state.total_executions}"
                        )

                except Exception as iter_error:
                    consecutive_errors += 1
                    logger.error(f"Error in iteration {iteration}: {iter_error}")
                    logger.debug(traceback.format_exc())

                # Wait for next decision interval
                await asyncio.sleep(decision_interval)

        except asyncio.CancelledError:
            logger.info(f"Campaign {campaign_id} loop cancelled")
            campaign["status"] = CampaignStatus.STOPPING

        except Exception as e:
            logger.error(f"Fatal error in autonomous loop: {e}\n{traceback.format_exc()}")
            campaign["status"] = CampaignStatus.FAILED
            campaign["error"] = str(e)

        finally:
            # Stop all engines via EnginePool
            if engine_pool:
                try:
                    await engine_pool.stop_all()
                except Exception as e:
                    logger.warning(f"Error stopping engine pool: {e}")
            else:
                for engine in engines:
                    try:
                        await engine.stop()
                    except Exception as e:
                        logger.warning(f"Error stopping engine: {e}")

            # Save final checkpoint
            try:
                await self._save_checkpoint(campaign)
            except Exception as e:
                logger.warning(f"Failed to save final checkpoint: {e}")

            if campaign["status"] == CampaignStatus.STOPPING:
                campaign["status"] = CampaignStatus.COMPLETED

            campaign["ended_at"] = datetime.utcnow()

            # Update final status in persistence
            if self.persistence:
                try:
                    await self.persistence.update_campaign_status(
                        campaign_id=campaign_id,
                        status=campaign["status"].value,
                        ended_at=campaign["ended_at"],
                    )
                except Exception as e:
                    logger.warning(f"Failed to persist final status: {e}")

            logger.info(f"Campaign {campaign_id} finished with status {campaign['status']}")

    def _should_stop(self, campaign: Dict[str, Any]) -> bool:
        """Check if campaign should stop."""
        config = campaign["config"]
        state = campaign["state"]

        # Check max duration
        if config.max_duration:
            elapsed = datetime.utcnow() - campaign["started_at"]
            if elapsed > config.max_duration:
                return True

        # Check target coverage
        if config.target_coverage and state.coverage_percentage >= config.target_coverage:
            return True

        # Check target crashes
        if config.target_crashes and state.unique_crashes >= config.target_crashes:
            return True

        # Check exploitable crash stop
        if config.stop_on_exploitable and state.exploitable_crashes > 0:
            return True

        return False

    def _update_campaign_state(
        self,
        campaign: Dict[str, Any],
        feedback: AggregatedFeedback,
    ) -> None:
        """Update campaign state from feedback with power schedule integration."""
        state = campaign["state"]

        state.elapsed_time = datetime.utcnow() - campaign["started_at"]
        state.total_executions = feedback.total_executions
        state.coverage_percentage = feedback.total_coverage
        state.unique_crashes = feedback.unique_crashes
        state.corpus_size = feedback.corpus_size
        state.executions_per_second = feedback.executions_per_second
        state.coverage_trend = feedback.coverage_trend

        # Update power schedule with coverage information
        if self.power_schedule and feedback.new_edges > 0:
            try:
                # Report new coverage to power schedule for any seeds that found it
                schedule_stats = self.power_schedule.get_statistics()
                state.schedule_stats = {
                    "total_seeds": schedule_stats.total_seeds,
                    "favored_seeds": schedule_stats.favored_seeds,
                    "total_edges": schedule_stats.total_edges,
                    "rare_edges": schedule_stats.rare_edges,
                    "average_energy": schedule_stats.average_energy,
                    "schedule_type": schedule_stats.schedule_type,
                }

                # Log power schedule status periodically
                if state.total_executions % 10000 == 0:
                    logger.info(
                        f"Power Schedule: {schedule_stats.total_seeds} seeds, "
                        f"{schedule_stats.favored_seeds} favored, "
                        f"{schedule_stats.rare_edges} rare edges, "
                        f"avg_energy={schedule_stats.average_energy:.1f}"
                    )
            except Exception as e:
                logger.debug(f"Failed to update power schedule stats: {e}")

        # Update crash deduplication statistics
        if self.crash_dedup:
            try:
                dedup_stats = self.crash_dedup.get_statistics()
                state.dedup_stats = dedup_stats
            except Exception:
                pass

    async def _maybe_reconfigure_aflpp(
        self,
        campaign: Dict[str, Any],
        feedback: AggregatedFeedback,
    ) -> Optional[Dict[str, Any]]:
        """
        Dynamically reconfigure AFL++ features based on campaign progress.

        This is what makes us BETTER than raw AFL++ - we adapt the fuzzer
        configuration as the campaign progresses, using intelligent feature
        selection that learns from outcomes.

        Returns new configuration if changes were made, None otherwise.
        """
        if not self.feature_selector:
            return None

        state = campaign["state"]
        config = campaign["config"]
        engines = campaign.get("engines", [])

        if not engines:
            return None

        # Build campaign state for feature selector
        max_duration_seconds = config.max_duration.total_seconds() if config.max_duration else 86400
        elapsed_seconds = state.elapsed_time.total_seconds() if state.elapsed_time else 0
        elapsed_fraction = elapsed_seconds / max_duration_seconds if max_duration_seconds > 0 else 0

        campaign_state = {
            "campaign_id": campaign["id"],
            "coverage_percentage": state.coverage_percentage,
            "unique_crashes": state.unique_crashes,
            "executions_per_second": state.executions_per_second,
            "total_executions": state.total_executions,
            "coverage_trend": feedback.coverage_trend.value if hasattr(feedback.coverage_trend, 'value') else str(feedback.coverage_trend),
            "elapsed_fraction": elapsed_fraction,
        }

        # Get target info
        target_info = {
            "binary_path": config.binary_path,
            "has_magic_bytes": True,
            "input_format": config.input_type,
        }

        try:
            # Get optimal configuration for current state
            optimal_config = self.feature_selector.get_optimal_config(
                campaign_state=campaign_state,
                target_info=target_info,
                available_cpus=len(engines),
            )

            # Check if we should reconfigure
            current_schedule = getattr(engines[0].config, 'power_schedule', 'explore') if engines else 'explore'
            recommended_schedule = optimal_config.get('power_schedule', current_schedule)

            # Only reconfigure if there's a significant change
            should_reconfigure = False
            changes = []

            if recommended_schedule != current_schedule:
                should_reconfigure = True
                changes.append(f"schedule: {current_schedule} -> {recommended_schedule}")

            if should_reconfigure:
                # Apply new configuration to engines
                for i, engine in enumerate(engines):
                    if hasattr(engine, 'config'):
                        # Get appropriate schedule for this instance
                        parallel_configs = optimal_config.get('parallel', {}).get('configs', [])
                        if parallel_configs and i < len(parallel_configs):
                            new_schedule = parallel_configs[i].get('power_schedule', recommended_schedule)
                        else:
                            # Fallback to main schedule with diversity
                            schedules = [recommended_schedule, "rare", "fast", "coe", "exploit", "seek"]
                            new_schedule = schedules[i % len(schedules)]

                        engine.config.power_schedule = new_schedule

                        # Apply if engine supports it
                        if hasattr(engine, 'apply_config'):
                            await engine.apply_config()

                logger.info(
                    f"AFL++ RECONFIGURED: {', '.join(changes)} "
                    f"(elapsed={elapsed_fraction:.0%}, coverage={state.coverage_percentage:.1f}%)"
                )

                # Record outcome for learning
                if self.feature_selector:
                    self.feature_selector.record_config_outcome(
                        config=optimal_config,
                        coverage_delta=feedback.coverage_delta,
                        crashes_found=len(feedback.new_crashes),
                    )

                return optimal_config

        except Exception as e:
            logger.debug(f"AFL++ reconfiguration check failed: {e}")

        return None

    async def _make_ai_decisions(
        self,
        campaign: Dict[str, Any],
        feedback: AggregatedFeedback,
    ) -> List[Decision]:
        """
        Use AGENTIC AI to make decisions based on current state.

        This now uses the AgenticReasoningEngine which provides:
        1. MEMORY - Remembers past decisions and outcomes
        2. CHAIN-OF-THOUGHT - Multi-step reasoning with explicit trace
        3. EXPLORATION - Balances trying new things vs using what works
        4. LEARNING - Improves decisions based on feedback
        """
        decisions = []
        state = campaign["state"]
        config = campaign["config"]

        # =====================================================================
        # DYNAMIC AFL++ RECONFIGURATION
        # Check periodically if AFL++ features should be adjusted
        # =====================================================================
        if state.total_executions % 100000 == 0 and state.total_executions > 0:
            try:
                reconfig = await self._maybe_reconfigure_aflpp(campaign, feedback)
                if reconfig:
                    logger.info(f"AFL++ dynamically reconfigured based on campaign progress")
            except Exception as e:
                logger.debug(f"AFL++ reconfiguration failed: {e}")

        # =====================================================================
        # USE AGENTIC REASONING ENGINE (if available)
        # =====================================================================
        if self.agentic_engine:
            try:
                # Build campaign state dict for agentic engine
                campaign_state = {
                    "campaign_id": campaign["id"],
                    "coverage_percentage": state.coverage_percentage,
                    "unique_crashes": state.unique_crashes,
                    "exploitable_crashes": state.exploitable_crashes,
                    "executions_per_second": state.executions_per_second,
                    "total_executions": state.total_executions,
                    "corpus_size": state.corpus_size,
                    "coverage_trend": feedback.coverage_trend.value if hasattr(feedback.coverage_trend, 'value') else str(feedback.coverage_trend),
                    "crash_trend": feedback.crash_trend.value if hasattr(feedback.crash_trend, 'value') else str(feedback.crash_trend),
                    "current_strategy": state.current_strategy.value if hasattr(state.current_strategy, 'value') else str(state.current_strategy),
                    "elapsed_hours": state.elapsed_time.total_seconds() / 3600 if state.elapsed_time else 0,
                    "max_duration_hours": config.max_duration.total_seconds() / 3600 if config.max_duration else 24,
                }

                # Get agentic decision with full reasoning chain
                agentic_decision = await self.agentic_engine.decide(campaign_state)

                # Log the reasoning chain
                logger.info(f"AGENTIC DECISION: {agentic_decision['action']} "
                           f"(mode={agentic_decision['mode']}, confidence={agentic_decision['confidence']:.0%})")
                if agentic_decision.get('reasoning_chain'):
                    for line in agentic_decision['reasoning_chain'].split('\n')[:5]:
                        logger.debug(f"  {line}")

                # Convert agentic decision to Decision object
                action_type = agentic_decision.get('action_type', agentic_decision['action'])
                decision_type = self._map_action_to_decision_type(action_type)

                if decision_type:
                    decisions.append(Decision(
                        decision_id=str(uuid.uuid4())[:8],
                        decision_type=decision_type,
                        reasoning=f"[AGENTIC-{agentic_decision['mode'].upper()}] {agentic_decision.get('reasoning_chain', '')[:200]}",
                        parameters=agentic_decision.get('parameters', {}),
                        priority=int(agentic_decision['confidence'] * 10),
                        confidence=agentic_decision['confidence'],
                    ))

                # Log agent state periodically
                if state.total_executions % 50000 == 0:
                    agent_state = self.agentic_engine.get_agent_state()
                    logger.info(f"AGENT STATE: memory={agent_state['memory']['total_memories']}, "
                               f"explore_rate={agent_state['exploration']['exploration_rate']:.0%}")

            except Exception as e:
                logger.warning(f"Agentic decision failed, falling back to heuristics: {e}")
                # Fall through to legacy decision making

        # =====================================================================
        # FALLBACK: Legacy decision making (if agentic engine fails/unavailable)
        # =====================================================================
        if not decisions:
            # Check for coverage plateau
            if feedback.coverage_trend == TrendDirection.STABLE:
                if self.coverage_advisor:
                    try:
                        advice = await self.coverage_advisor.get_advice(state, campaign["profile"])
                        if advice.should_switch_strategy:
                            decisions.append(Decision(
                                decision_id=str(uuid.uuid4())[:8],
                                decision_type=DecisionType.SWITCH_STRATEGY,
                                reasoning=f"[FALLBACK] {advice.reasoning}",
                                parameters={"strategy": advice.recommended_strategy},
                                priority=8,
                            ))
                    except Exception as e:
                        logger.debug(f"Coverage advisor failed: {e}")

            # Check for crash burst
            if feedback.crash_trend == TrendDirection.INCREASING:
                for crash in feedback.new_crashes[:5]:
                    decisions.append(Decision(
                        decision_id=str(uuid.uuid4())[:8],
                        decision_type=DecisionType.TRIAGE_CRASH,
                        reasoning="[FALLBACK] New crash detected, needs triage",
                        parameters={"crash_id": crash.get("id")},
                        priority=9,
                    ))

            # Generate decisions based on current state
            if self.decision_generator and not decisions:
                try:
                    generated = await self.decision_generator.generate_decisions(state, feedback)
                    decisions.extend(generated)
                except Exception as e:
                    logger.debug(f"Decision generator failed: {e}")

        return decisions

    def _map_action_to_decision_type(self, action: str) -> Optional[DecisionType]:
        """Map agentic action to DecisionType enum."""
        mapping = {
            "continue": DecisionType.CONTINUE,
            "switch_strategy": DecisionType.SWITCH_STRATEGY,
            "switch_strategy_coverage": DecisionType.SWITCH_STRATEGY,
            "switch_strategy_directed": DecisionType.SWITCH_STRATEGY,
            "switch_strategy_concolic": DecisionType.ENABLE_CONCOLIC,
            "switch_strategy_exploit": DecisionType.SWITCH_STRATEGY,
            "enable_cmplog": DecisionType.ENABLE_CONCOLIC,
            "enable_concolic": DecisionType.ENABLE_CONCOLIC,
            "generate_seeds": DecisionType.GENERATE_SEEDS,
            "adjust_mutations": DecisionType.ADJUST_MUTATION_WEIGHTS,
            "scale_up": DecisionType.SCALE_UP,
            "scale_down": DecisionType.SCALE_DOWN,
            "minimize_corpus": DecisionType.MINIMIZE_CORPUS,
            "focus_function": DecisionType.FOCUS_FUNCTION,
            "triage_crash": DecisionType.TRIAGE_CRASH,
        }
        return mapping.get(action)

    async def _handle_crashes(
        self,
        campaign: Dict[str, Any],
        feedback: AggregatedFeedback,
    ) -> None:
        """Handle new crashes found during fuzzing with persistence and deduplication."""
        campaign_id = campaign["id"]

        # Also check for crashes from engine pool
        engine_pool = campaign.get("engine_pool")
        if engine_pool:
            try:
                pool_crashes = await engine_pool.get_all_crashes()
                for crash in pool_crashes:
                    crash_dict = crash.to_dict() if hasattr(crash, 'to_dict') else {
                        "id": crash.crash_id if hasattr(crash, 'crash_id') else str(crash),
                        "hash": crash.crash_hash if hasattr(crash, 'crash_hash') else hashlib.sha256(str(crash).encode()).hexdigest()[:16],
                        "crash_type": crash.crash_type if hasattr(crash, 'crash_type') else "unknown",
                        "size": crash.input_size if hasattr(crash, 'input_size') else 0,
                        "stack_frames": crash.stack_frames if hasattr(crash, 'stack_frames') else [],
                        "crash_address": crash.crash_address if hasattr(crash, 'crash_address') else 0,
                    }
                    if crash_dict not in feedback.new_crashes:
                        # Check if not already in feedback
                        if crash_dict.get("hash") not in [c.get("hash") for c in feedback.new_crashes]:
                            feedback.new_crashes.append(crash_dict)
            except Exception as e:
                logger.debug(f"Error getting pool crashes: {e}")

        for crash_info in feedback.new_crashes:
            # Check if already processed
            crash_hash = crash_info.get("hash") or crash_info.get("crash_hash")
            if not crash_hash:
                continue

            # Use crash deduplication service for intelligent bucketing
            is_truly_new = True
            dedup_result = None
            bucket_id = None

            if self.crash_dedup:
                try:
                    # Extract stack frames if available
                    stack_frames = crash_info.get("stack_frames", [])
                    crash_address = crash_info.get("crash_address", 0)
                    crash_type = crash_info.get("crash_type", "unknown")
                    crash_data = crash_info.get("data") or crash_info.get("input_data")

                    dedup_result = self.crash_dedup.deduplicate(
                        crash_id=crash_hash,
                        crash_address=crash_address,
                        crash_type=crash_type,
                        stack_frames=stack_frames,
                        input_data=crash_data if isinstance(crash_data, bytes) else None,
                    )

                    is_truly_new = dedup_result.is_new
                    bucket_id = dedup_result.bucket_id

                    # Update crash info with deduplication results
                    crash_info["bucket_id"] = bucket_id
                    crash_info["signature"] = dedup_result.crash_signature
                    crash_info["severity"] = dedup_result.severity.value if dedup_result.severity else "unknown"
                    crash_info["similarity_score"] = dedup_result.similarity_score

                    if not is_truly_new:
                        logger.debug(f"Crash {crash_hash[:16]} is duplicate of bucket {bucket_id} (similarity: {dedup_result.similarity_score:.2f})")
                        # Still track it but don't count as unique
                        campaign["state"].total_crashes = len(campaign["crashes"]) + 1
                        continue  # Skip further processing for duplicates

                except Exception as e:
                    logger.warning(f"Crash deduplication failed: {e}")

            # Fallback to simple hash-based deduplication
            existing_hashes = [c.get("hash") or c.get("crash_hash") for c in campaign["crashes"]]
            if crash_hash in existing_hashes and is_truly_new:
                continue

            # Add to campaign crashes - this is a truly new crash!
            campaign["crashes"].append(crash_info)
            logger.info(f"NEW UNIQUE CRASH: {crash_hash[:16]} bucket={bucket_id or 'N/A'} severity={crash_info.get('severity', 'unknown')}")

            # Persist crash to database
            if self.persistence:
                try:
                    await self.persistence.save_crash(
                        campaign_id=campaign_id,
                        crash_id=crash_info.get("id") or crash_info.get("crash_id") or f"crash_{len(campaign['crashes'])}",
                        crash_hash=crash_hash,
                        crash_type=crash_info.get("crash_type") or "unknown",
                        exploitability="unknown",  # Will be updated by triage
                        confidence=0.0,
                        input_size=crash_info.get("size") or crash_info.get("input_size") or 0,
                    )
                except Exception as pe:
                    logger.debug(f"Failed to persist crash: {pe}")

            # Auto-triage if AI enabled and crash triage service available
            if campaign["config"].enable_ai and self.crash_triage:
                try:
                    # Get crash input data
                    crash_data = crash_info.get("data") or crash_info.get("input_data")
                    if crash_data and isinstance(crash_data, bytes):
                        # Run triage with timeout
                        triage_result = await asyncio.wait_for(
                            self.crash_triage.analyze_crash(
                                crash_data=crash_data,
                                binary_path=campaign["binary_path"],
                            ),
                            timeout=30.0
                        )

                        # Update crash info with triage result
                        crash_info["triage"] = {
                            "exploitability": triage_result.exploitability if hasattr(triage_result, 'exploitability') else "unknown",
                            "root_cause": triage_result.root_cause if hasattr(triage_result, 'root_cause') else None,
                        }

                        # Update persistence with triage result
                        if self.persistence and hasattr(triage_result, 'exploitability'):
                            try:
                                await self.persistence.save_crash(
                                    campaign_id=campaign_id,
                                    crash_id=crash_info.get("id") or crash_info.get("crash_id") or f"crash_{len(campaign['crashes'])}",
                                    crash_hash=crash_hash,
                                    crash_type=crash_info.get("crash_type") or "unknown",
                                    exploitability=triage_result.exploitability,
                                    confidence=triage_result.confidence if hasattr(triage_result, 'confidence') else 0.5,
                                    input_size=crash_info.get("size") or crash_info.get("input_size") or 0,
                                    root_cause=triage_result.root_cause if hasattr(triage_result, 'root_cause') else None,
                                )

                                # Update exploitable count if exploitable
                                if triage_result.exploitability in ["high", "exploitable"]:
                                    campaign["state"].exploitable_crashes += 1
                            except Exception:
                                pass

                except asyncio.TimeoutError:
                    logger.debug(f"Crash triage timed out for {crash_hash[:16]}")
                except Exception as e:
                    logger.warning(f"Crash triage failed: {e}")

    async def _save_checkpoint(self, campaign: Dict[str, Any]) -> None:
        """Save campaign checkpoint."""
        state = campaign["state"]

        checkpoint = CampaignCheckpoint(
            campaign_id=campaign["id"],
            timestamp=datetime.utcnow(),
            status=campaign["status"],
            current_strategy=state.current_strategy,
            elapsed_time=state.elapsed_time,
            total_executions=state.total_executions,
            coverage_pct=state.coverage_percentage,
            unique_crashes=state.unique_crashes,
            exploitable_crashes=state.exploitable_crashes,
            decisions_made=len(campaign["decisions"]),
            strategy_changes=sum(1 for d in campaign["decisions"]
                               if d.decision_type == DecisionType.SWITCH_STRATEGY),
        )

        campaign["checkpoints"].append(checkpoint)
        logger.debug(f"Checkpoint saved for campaign {campaign['id']}")

    async def pause_campaign(self, campaign_id: str) -> bool:
        """Pause a running campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return False

        if campaign["status"] == CampaignStatus.RUNNING:
            campaign["status"] = CampaignStatus.PAUSED
            return True
        return False

    async def resume_campaign(self, campaign_id: str) -> bool:
        """Resume a paused campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return False

        if campaign["status"] == CampaignStatus.PAUSED:
            campaign["status"] = CampaignStatus.RUNNING
            asyncio.create_task(self._run_autonomous_loop(campaign_id))
            return True
        return False

    async def stop_campaign(self, campaign_id: str) -> bool:
        """Stop a campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return False

        if campaign["status"] in [CampaignStatus.RUNNING, CampaignStatus.PAUSED]:
            campaign["status"] = CampaignStatus.STOPPING
            return True
        return False

    def get_campaign_status(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get current campaign status."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return None

        state = campaign.get("state")
        if not state:
            return {"status": campaign["status"].value}

        return {
            "campaign_id": campaign_id,
            "status": campaign["status"].value,
            "elapsed_time": str(state.elapsed_time),
            "total_executions": state.total_executions,
            "coverage_percentage": state.coverage_percentage,
            "unique_crashes": state.unique_crashes,
            "exploitable_crashes": state.exploitable_crashes,
            "corpus_size": state.corpus_size,
            "executions_per_second": state.executions_per_second,
            "current_strategy": state.current_strategy.value,
            "decisions_made": len(campaign.get("decisions", [])),
        }

    def get_campaign_decisions(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Get all decisions made during campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return []

        return [
            {
                "decision_id": d.decision_id,
                "type": d.decision_type.value,
                "reasoning": d.reasoning,
                "parameters": d.parameters,
                "priority": d.priority,
                "timestamp": d.timestamp.isoformat() if d.timestamp else None,
            }
            for d in campaign.get("decisions", [])
        ]

    def get_campaign_crashes(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Get all crashes found during campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return []

        return campaign.get("crashes", [])

    async def get_campaign_result(self, campaign_id: str) -> Optional[CampaignResult]:
        """Get final campaign result."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign or campaign["status"] not in [
            CampaignStatus.COMPLETED,
            CampaignStatus.FAILED,
        ]:
            return None

        state = campaign.get("state")
        if not state:
            return None

        # Calculate decision statistics
        decisions_by_type: Dict[str, int] = {}
        for decision in campaign.get("decisions", []):
            dtype = decision.decision_type.value
            decisions_by_type[dtype] = decisions_by_type.get(dtype, 0) + 1

        return CampaignResult(
            campaign_id=campaign_id,
            binary_name=os.path.basename(campaign["binary_path"]),
            status=campaign["status"],
            started_at=campaign["started_at"],
            ended_at=campaign.get("ended_at", datetime.utcnow()),
            duration=state.elapsed_time,
            total_executions=state.total_executions,
            final_coverage=state.coverage_percentage,
            unique_crashes=state.unique_crashes,
            exploitable_crashes=state.exploitable_crashes,
            total_decisions=len(campaign.get("decisions", [])),
            strategy_changes=sum(1 for d in campaign.get("decisions", [])
                               if d.decision_type == DecisionType.SWITCH_STRATEGY),
            decisions_by_type=decisions_by_type,
        )

    def list_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns."""
        return [
            {
                "campaign_id": cid,
                "binary": os.path.basename(c["binary_path"]),
                "status": c["status"].value,
                "started_at": c["started_at"].isoformat(),
            }
            for cid, c in self._campaigns.items()
        ]


# =============================================================================
# Convenience Functions
# =============================================================================

async def start_agentic_campaign(
    binary_path: str,
    max_duration: Optional[timedelta] = None,
    enable_ai: bool = True,
    ai_client: Optional[BinaryAIClient] = None,
) -> str:
    """Convenience function to start an agentic fuzzing campaign."""
    controller = BinaryCampaignController(ai_client)

    config = CampaignConfig(
        binary_path=binary_path,
        max_duration=max_duration,
        enable_ai=enable_ai,
    )

    return await controller.start_campaign(binary_path, config)
