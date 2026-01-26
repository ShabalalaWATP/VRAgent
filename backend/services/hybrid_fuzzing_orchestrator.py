"""
Hybrid Fuzzing Orchestrator.

Coordinates multiple fuzzing techniques for maximum effectiveness:
1. AFL++ for coverage-guided mutation fuzzing
2. Concolic execution for solving complex constraints
3. Taint tracking for targeted mutation guidance
4. LAF-Intel for improved coverage feedback

The orchestrator intelligently triggers each technique based on:
- Coverage stagnation detection
- Crash discovery
- Time-based scheduling
- Resource availability
"""

from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
from enum import Enum
import asyncio
import json
import logging
import os
import time
import uuid

from .concolic_execution_service import (
    ConcolicExecutionService,
    ConcolicConfig,
    ConcolicBackend,
    ConcolicResult,
    check_concolic_installation,
)
from .taint_tracking_service import (
    TaintTrackingService,
    TaintConfig,
    TaintBackend,
    TaintAnalysisResult,
    TaintSink,
    check_taint_backend_installation,
)
from .laf_intel_service import (
    LafIntelService,
    LafIntelConfig,
    LafIntelMode,
    get_laf_intel_env_vars,
)

logger = logging.getLogger(__name__)


class HybridMode(str, Enum):
    """Hybrid fuzzing operation modes."""
    AFL_ONLY = "afl_only"  # Just AFL++, no hybrid techniques
    CONCOLIC_ASSISTED = "concolic_assisted"  # AFL++ + concolic
    TAINT_GUIDED = "taint_guided"  # AFL++ + taint tracking
    FULL_HYBRID = "full_hybrid"  # All techniques combined


class TriggerReason(str, Enum):
    """Reasons for triggering hybrid techniques."""
    SCHEDULED = "scheduled"  # Regular time-based trigger
    STAGNATION = "stagnation"  # Coverage stagnation detected
    CRASH_FOUND = "crash_found"  # New crash discovered
    COVERAGE_PLATEAU = "coverage_plateau"  # No new edges for a while
    MANUAL = "manual"  # User-triggered
    INITIAL = "initial"  # Initial analysis at start


@dataclass
class HybridFuzzingConfig:
    """Configuration for hybrid fuzzing orchestration."""
    mode: HybridMode = HybridMode.FULL_HYBRID
    # Target configuration
    target_path: str = ""
    target_args: str = "@@"
    input_dir: str = ""
    output_dir: str = ""
    # AFL++ settings
    timeout_ms: int = 5000
    memory_limit_mb: int = 256
    use_qemu: bool = True
    dictionary_path: Optional[str] = None
    # Concolic settings
    enable_concolic: bool = True
    concolic_interval_seconds: int = 300  # Run concolic every 5 minutes
    concolic_input_selection: str = "coverage"  # coverage, random, age
    max_concolic_inputs_per_cycle: int = 5
    concolic_timeout_seconds: int = 60
    # Taint settings
    enable_taint: bool = True
    taint_interval_seconds: int = 600  # Run taint every 10 minutes
    taint_sample_size: int = 10
    taint_timeout_seconds: int = 30
    # LAF-Intel settings
    enable_laf: bool = True
    laf_modes: List[LafIntelMode] = field(default_factory=lambda: [LafIntelMode.ALL])
    laf_instrumented_path: Optional[str] = None
    # Triggering conditions
    trigger_on_stagnation: bool = True
    stagnation_threshold_seconds: int = 300  # 5 minutes without new coverage
    trigger_on_coverage_plateau: bool = True
    coverage_plateau_threshold: int = 50  # Min new edges before plateau
    trigger_on_crash: bool = True
    # Resource limits
    max_concolic_time_per_cycle_seconds: int = 120
    max_taint_time_per_cycle_seconds: int = 60
    max_memory_mb: int = 4096
    # Telemetry
    telemetry_dir: Optional[str] = None
    telemetry_interval_seconds: float = 2.0


@dataclass
class HybridFuzzingStatus:
    """Current status of hybrid fuzzing session."""
    session_id: str
    mode: HybridMode
    running: bool
    runtime_seconds: float
    # AFL++ status (from external AFL++ process)
    afl_execs_done: int = 0
    afl_paths_total: int = 0
    afl_unique_crashes: int = 0
    afl_execs_per_sec: float = 0.0
    afl_map_coverage: float = 0.0
    # Concolic status
    concolic_enabled: bool = False
    concolic_runs: int = 0
    concolic_inputs_generated: int = 0
    concolic_coverage_contributions: int = 0
    last_concolic_run: Optional[str] = None
    next_concolic_run: Optional[str] = None
    # Taint status
    taint_enabled: bool = False
    taint_analyses: int = 0
    hot_bytes_identified: int = 0
    taint_guided_mutations: int = 0
    last_taint_run: Optional[str] = None
    next_taint_run: Optional[str] = None
    # LAF status
    laf_enabled: bool = False
    laf_instrumented: bool = False
    # Detection states
    stagnation_detected: bool = False
    coverage_plateau_detected: bool = False
    last_new_coverage_time: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "mode": self.mode.value,
            "running": self.running,
            "runtime_seconds": self.runtime_seconds,
            "afl": {
                "execs_done": self.afl_execs_done,
                "paths_total": self.afl_paths_total,
                "unique_crashes": self.afl_unique_crashes,
                "execs_per_sec": self.afl_execs_per_sec,
                "map_coverage": self.afl_map_coverage,
            },
            "concolic": {
                "enabled": self.concolic_enabled,
                "runs": self.concolic_runs,
                "inputs_generated": self.concolic_inputs_generated,
                "coverage_contributions": self.concolic_coverage_contributions,
                "last_run": self.last_concolic_run,
                "next_run": self.next_concolic_run,
            },
            "taint": {
                "enabled": self.taint_enabled,
                "analyses": self.taint_analyses,
                "hot_bytes_identified": self.hot_bytes_identified,
                "guided_mutations": self.taint_guided_mutations,
                "last_run": self.last_taint_run,
                "next_run": self.next_taint_run,
            },
            "laf": {
                "enabled": self.laf_enabled,
                "instrumented": self.laf_instrumented,
            },
            "detection": {
                "stagnation_detected": self.stagnation_detected,
                "coverage_plateau_detected": self.coverage_plateau_detected,
                "last_new_coverage_time": self.last_new_coverage_time,
            },
        }


@dataclass
class CycleResult:
    """Result of a hybrid technique cycle."""
    technique: str  # concolic, taint
    trigger_reason: TriggerReason
    start_time: float
    end_time: float
    inputs_analyzed: int
    inputs_generated: int
    coverage_contributions: int
    errors: List[str]
    warnings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "trigger_reason": self.trigger_reason.value,
            "duration_seconds": self.end_time - self.start_time,
            "inputs_analyzed": self.inputs_analyzed,
            "inputs_generated": self.inputs_generated,
            "coverage_contributions": self.coverage_contributions,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class HybridFuzzingOrchestrator:
    """
    Orchestrates hybrid fuzzing combining AFL++, concolic execution, and taint tracking.

    The orchestrator:
    1. Monitors AFL++ fuzzing progress (external process)
    2. Detects coverage stagnation
    3. Triggers concolic execution to solve constraints
    4. Triggers taint analysis to identify hot bytes
    5. Feeds results back to AFL++

    Example usage:
        config = HybridFuzzingConfig(
            target_path="/path/to/binary",
            input_dir="/fuzzing/seeds",
            output_dir="/fuzzing/output",
            mode=HybridMode.FULL_HYBRID,
        )

        orchestrator = HybridFuzzingOrchestrator(config)

        async for event in orchestrator.start():
            print(event)
            if event["type"] == "stagnation_detected":
                print("AFL++ is stuck, triggering concolic...")
    """

    def __init__(self, config: HybridFuzzingConfig):
        self.config = config
        self.session_id = str(uuid.uuid4())[:8]
        self._running = False
        self._stop_requested = False
        self._start_time: Optional[float] = None

        # Service instances
        self._concolic_service: Optional[ConcolicExecutionService] = None
        self._taint_service: Optional[TaintTrackingService] = None
        self._laf_service: Optional[LafIntelService] = None

        # State tracking
        self._last_paths_total = 0
        self._last_coverage_time = 0.0
        self._last_concolic_time = 0.0
        self._last_taint_time = 0.0
        self._last_crash_count = 0
        self._coverage_history: List[Tuple[float, int]] = []

        # Statistics
        self._stats = {
            "concolic_runs": 0,
            "concolic_inputs_generated": 0,
            "concolic_coverage_contributions": 0,
            "taint_analyses": 0,
            "hot_bytes_identified": 0,
            "taint_guided_mutations": 0,
        }

        # Hot bytes cache for mutation guidance
        self._hot_bytes_map: Dict[str, List[int]] = {}

    def _initialize_services(self) -> None:
        """Initialize hybrid fuzzing services."""
        # Initialize concolic service
        if self.config.enable_concolic and self.config.mode in [
            HybridMode.CONCOLIC_ASSISTED, HybridMode.FULL_HYBRID
        ]:
            concolic_config = ConcolicConfig(
                target_path=self.config.target_path,
                target_args=self.config.target_args,
                timeout_seconds=self.config.concolic_timeout_seconds,
                output_dir=os.path.join(self.config.output_dir, "concolic"),
                afl_queue_dir=os.path.join(self.config.output_dir, "default", "queue"),
            )
            self._concolic_service = ConcolicExecutionService(concolic_config)

        # Initialize taint service
        if self.config.enable_taint and self.config.mode in [
            HybridMode.TAINT_GUIDED, HybridMode.FULL_HYBRID
        ]:
            taint_config = TaintConfig(
                target_path=self.config.target_path,
                target_args=self.config.target_args,
                timeout_seconds=self.config.taint_timeout_seconds,
                output_dir=os.path.join(self.config.output_dir, "taint"),
            )
            self._taint_service = TaintTrackingService(taint_config)

        # Initialize LAF service
        if self.config.enable_laf:
            laf_config = LafIntelConfig(modes=self.config.laf_modes)
            self._laf_service = LafIntelService(laf_config)

    async def start(
        self,
        target_path: Optional[str] = None,
        target_args: Optional[str] = None,
        input_dir: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Start hybrid fuzzing orchestration.

        This does NOT start AFL++ itself - it monitors an existing AFL++ process
        and triggers hybrid techniques as needed.

        Args:
            target_path: Override target path
            target_args: Override target args
            input_dir: Override input directory
            output_dir: Override output directory (AFL++ output)

        Yields:
            Status updates and events
        """
        # Apply overrides
        if target_path:
            self.config.target_path = target_path
        if target_args:
            self.config.target_args = target_args
        if input_dir:
            self.config.input_dir = input_dir
        if output_dir:
            self.config.output_dir = output_dir

        self._running = True
        self._stop_requested = False
        self._start_time = time.time()
        self._last_coverage_time = self._start_time
        self._last_concolic_time = self._start_time
        self._last_taint_time = self._start_time

        # Initialize services
        self._initialize_services()

        # Check capabilities
        capabilities = await self._check_capabilities()

        yield {
            "type": "session_started",
            "session_id": self.session_id,
            "mode": self.config.mode.value,
            "capabilities": capabilities,
            "config": {
                "target": self.config.target_path,
                "concolic_enabled": self.config.enable_concolic and capabilities.get("concolic", {}).get("available", False),
                "taint_enabled": self.config.enable_taint and capabilities.get("taint", {}).get("available", False),
                "laf_enabled": self.config.enable_laf and capabilities.get("laf", {}).get("available", False),
            }
        }

        # Create output directories
        os.makedirs(os.path.join(self.config.output_dir, "concolic"), exist_ok=True)
        os.makedirs(os.path.join(self.config.output_dir, "taint"), exist_ok=True)

        # Main monitoring loop
        while self._running and not self._stop_requested:
            current_time = time.time()
            runtime = current_time - self._start_time

            # Get AFL++ status
            afl_status = await self._get_afl_status()

            # Check for triggers
            triggers = self._check_triggers(afl_status, current_time)

            # Execute triggered techniques
            for trigger_reason in triggers:
                if trigger_reason in [TriggerReason.STAGNATION, TriggerReason.SCHEDULED, TriggerReason.COVERAGE_PLATEAU]:
                    # Trigger concolic if enabled
                    if self._should_run_concolic(current_time):
                        yield {
                            "type": "concolic_triggered",
                            "reason": trigger_reason.value,
                            "runtime_seconds": runtime,
                        }

                        result = await self.trigger_concolic_cycle(trigger_reason)
                        yield {
                            "type": "concolic_completed",
                            "result": result.to_dict(),
                        }

                if trigger_reason == TriggerReason.CRASH_FOUND:
                    # Trigger taint on crashes
                    if self._should_run_taint(current_time):
                        yield {
                            "type": "taint_triggered",
                            "reason": trigger_reason.value,
                            "runtime_seconds": runtime,
                        }

                        result = await self.trigger_taint_cycle(trigger_reason)
                        yield {
                            "type": "taint_completed",
                            "result": result.to_dict(),
                        }

            # Periodic status update
            status = self.get_status()
            status_dict = status.to_dict()
            status_dict["type"] = "status"
            yield status_dict

            # Update tracking
            self._update_tracking(afl_status)

            await asyncio.sleep(self.config.telemetry_interval_seconds)

        # Final status
        yield {
            "type": "session_stopped",
            "session_id": self.session_id,
            "runtime_seconds": time.time() - self._start_time,
            "final_stats": self._stats.copy(),
        }

    async def stop(self) -> None:
        """Stop hybrid fuzzing gracefully."""
        self._stop_requested = True
        self._running = False

        if self._concolic_service:
            await self._concolic_service.stop()
        if self._taint_service:
            await self._taint_service.stop()

    async def _check_capabilities(self) -> Dict[str, Any]:
        """Check available hybrid fuzzing capabilities."""
        capabilities = {
            "concolic": {"available": False},
            "taint": {"available": False},
            "laf": {"available": False},
        }

        # Check concolic
        if self.config.enable_concolic:
            try:
                result = await check_concolic_installation()
                capabilities["concolic"] = {
                    "available": result.get("recommended") is not None,
                    "backend": result.get("recommended"),
                    "details": result,
                }
            except Exception as e:
                capabilities["concolic"]["error"] = str(e)

        # Check taint
        if self.config.enable_taint:
            try:
                result = await check_taint_backend_installation()
                capabilities["taint"] = {
                    "available": result.get("recommended") is not None,
                    "backend": result.get("recommended"),
                    "details": result,
                }
            except Exception as e:
                capabilities["taint"]["error"] = str(e)

        # Check LAF
        if self.config.enable_laf and self._laf_service:
            try:
                result = self._laf_service.check_laf_availability()
                capabilities["laf"] = {
                    "available": result.available,
                    "compiler": result.afl_clang_fast_path or result.afl_clang_lto_path,
                }
            except Exception as e:
                capabilities["laf"]["error"] = str(e)

        return capabilities

    async def _get_afl_status(self) -> Dict[str, Any]:
        """Get current AFL++ status from fuzzer_stats file."""
        stats_path = os.path.join(self.config.output_dir, "default", "fuzzer_stats")

        if not os.path.isfile(stats_path):
            return {
                "running": False,
                "execs_done": 0,
                "paths_total": 0,
                "unique_crashes": 0,
                "execs_per_sec": 0,
                "map_coverage": 0,
            }

        try:
            stats = {}
            with open(stats_path, "r") as f:
                for line in f:
                    if ":" in line:
                        key, value = line.strip().split(":", 1)
                        stats[key.strip()] = value.strip()

            return {
                "running": True,
                "execs_done": int(stats.get("execs_done", 0)),
                "paths_total": int(stats.get("paths_total", 0)),
                "unique_crashes": int(stats.get("saved_crashes", 0)),
                "execs_per_sec": float(stats.get("execs_per_sec", 0)),
                "map_coverage": float(stats.get("bitmap_cvg", "0").rstrip("%")),
            }
        except Exception as e:
            logger.warning(f"Failed to read AFL stats: {e}")
            return {
                "running": False,
                "execs_done": 0,
                "paths_total": 0,
                "unique_crashes": 0,
                "execs_per_sec": 0,
                "map_coverage": 0,
            }

    def _check_triggers(
        self,
        afl_status: Dict[str, Any],
        current_time: float,
    ) -> List[TriggerReason]:
        """Check for conditions that should trigger hybrid techniques."""
        triggers = []

        # Check for new crashes
        current_crashes = afl_status.get("unique_crashes", 0)
        if current_crashes > self._last_crash_count and self.config.trigger_on_crash:
            triggers.append(TriggerReason.CRASH_FOUND)

        # Check for coverage stagnation
        current_paths = afl_status.get("paths_total", 0)
        if current_paths > self._last_paths_total:
            self._last_coverage_time = current_time
        elif self.config.trigger_on_stagnation:
            stagnation_time = current_time - self._last_coverage_time
            if stagnation_time > self.config.stagnation_threshold_seconds:
                triggers.append(TriggerReason.STAGNATION)

        # Check for coverage plateau (using history)
        if self.config.trigger_on_coverage_plateau and len(self._coverage_history) >= 10:
            recent = self._coverage_history[-10:]
            coverage_gain = recent[-1][1] - recent[0][1]
            if coverage_gain < self.config.coverage_plateau_threshold:
                triggers.append(TriggerReason.COVERAGE_PLATEAU)

        # Scheduled triggers
        if self._should_run_concolic(current_time):
            if TriggerReason.STAGNATION not in triggers:
                triggers.append(TriggerReason.SCHEDULED)

        return triggers

    def _should_run_concolic(self, current_time: float) -> bool:
        """Check if concolic should run based on schedule."""
        if not self.config.enable_concolic or not self._concolic_service:
            return False

        time_since_last = current_time - self._last_concolic_time
        return time_since_last >= self.config.concolic_interval_seconds

    def _should_run_taint(self, current_time: float) -> bool:
        """Check if taint should run based on schedule."""
        if not self.config.enable_taint or not self._taint_service:
            return False

        time_since_last = current_time - self._last_taint_time
        return time_since_last >= self.config.taint_interval_seconds

    def _update_tracking(self, afl_status: Dict[str, Any]) -> None:
        """Update internal tracking state."""
        current_paths = afl_status.get("paths_total", 0)
        current_crashes = afl_status.get("unique_crashes", 0)
        current_time = time.time()

        # Update history
        self._coverage_history.append((current_time, current_paths))
        if len(self._coverage_history) > 100:
            self._coverage_history = self._coverage_history[-100:]

        self._last_paths_total = current_paths
        self._last_crash_count = current_crashes

    async def trigger_concolic_cycle(
        self,
        reason: TriggerReason = TriggerReason.MANUAL,
        force: bool = False,
    ) -> CycleResult:
        """
        Trigger a concolic execution cycle.

        Args:
            reason: Why this cycle was triggered
            force: Run even if not scheduled

        Returns:
            CycleResult with cycle statistics
        """
        start_time = time.time()
        errors: List[str] = []
        warnings: List[str] = []
        inputs_analyzed = 0
        inputs_generated = 0
        coverage_contributions = 0

        if not self._concolic_service:
            return CycleResult(
                technique="concolic",
                trigger_reason=reason,
                start_time=start_time,
                end_time=time.time(),
                inputs_analyzed=0,
                inputs_generated=0,
                coverage_contributions=0,
                errors=["Concolic service not initialized"],
                warnings=[],
            )

        try:
            # Select inputs for analysis
            queue_dir = os.path.join(self.config.output_dir, "default", "queue")
            input_paths = self._concolic_service.prioritize_inputs(
                queue_dir,
                max_inputs=self.config.max_concolic_inputs_per_cycle,
            )

            if not input_paths:
                warnings.append("No inputs found in queue")
            else:
                # Analyze each input
                for input_path in input_paths:
                    if time.time() - start_time > self.config.max_concolic_time_per_cycle_seconds:
                        warnings.append("Cycle time limit reached")
                        break

                    try:
                        result = await self._concolic_service.analyze_input(input_path)
                        inputs_analyzed += 1
                        inputs_generated += result.new_inputs_generated

                        # Feed to AFL++
                        if result.generated_inputs:
                            fed = await self._concolic_service.feed_to_afl(
                                result.generated_inputs,
                                queue_dir,
                            )
                            coverage_contributions += fed

                        errors.extend(result.errors)
                        warnings.extend(result.warnings)

                    except Exception as e:
                        errors.append(f"Error analyzing {input_path}: {str(e)}")

        except Exception as e:
            errors.append(f"Concolic cycle error: {str(e)}")

        # Update stats
        self._stats["concolic_runs"] += 1
        self._stats["concolic_inputs_generated"] += inputs_generated
        self._stats["concolic_coverage_contributions"] += coverage_contributions
        self._last_concolic_time = time.time()

        return CycleResult(
            technique="concolic",
            trigger_reason=reason,
            start_time=start_time,
            end_time=time.time(),
            inputs_analyzed=inputs_analyzed,
            inputs_generated=inputs_generated,
            coverage_contributions=coverage_contributions,
            errors=errors,
            warnings=warnings,
        )

    async def trigger_taint_cycle(
        self,
        reason: TriggerReason = TriggerReason.MANUAL,
        force: bool = False,
    ) -> CycleResult:
        """
        Trigger a taint analysis cycle.

        Args:
            reason: Why this cycle was triggered
            force: Run even if not scheduled

        Returns:
            CycleResult with cycle statistics
        """
        start_time = time.time()
        errors: List[str] = []
        warnings: List[str] = []
        inputs_analyzed = 0
        hot_bytes_found = 0

        if not self._taint_service:
            return CycleResult(
                technique="taint",
                trigger_reason=reason,
                start_time=start_time,
                end_time=time.time(),
                inputs_analyzed=0,
                inputs_generated=0,
                coverage_contributions=0,
                errors=["Taint service not initialized"],
                warnings=[],
            )

        try:
            # Select inputs for analysis (prefer crashes)
            crashes_dir = os.path.join(self.config.output_dir, "default", "crashes")
            queue_dir = os.path.join(self.config.output_dir, "default", "queue")

            input_paths = []

            # First, analyze crashes
            if os.path.isdir(crashes_dir):
                for filename in os.listdir(crashes_dir)[:self.config.taint_sample_size // 2]:
                    if filename.lower() != "readme.txt":
                        input_paths.append(os.path.join(crashes_dir, filename))

            # Then queue samples
            if os.path.isdir(queue_dir):
                remaining = self.config.taint_sample_size - len(input_paths)
                for filename in os.listdir(queue_dir)[:remaining]:
                    if filename.lower() != "readme.txt":
                        input_paths.append(os.path.join(queue_dir, filename))

            if not input_paths:
                warnings.append("No inputs found for taint analysis")
            else:
                # Analyze each input
                for input_path in input_paths:
                    if time.time() - start_time > self.config.max_taint_time_per_cycle_seconds:
                        warnings.append("Cycle time limit reached")
                        break

                    try:
                        result = await self._taint_service.analyze_input(input_path)
                        inputs_analyzed += 1
                        hot_bytes_found += len(result.hot_bytes)

                        # Cache hot bytes for mutation guidance
                        if result.hot_bytes:
                            self._hot_bytes_map[input_path] = result.hot_bytes

                        errors.extend(result.errors)
                        warnings.extend(result.warnings)

                    except Exception as e:
                        errors.append(f"Error analyzing {input_path}: {str(e)}")

        except Exception as e:
            errors.append(f"Taint cycle error: {str(e)}")

        # Update stats
        self._stats["taint_analyses"] += inputs_analyzed
        self._stats["hot_bytes_identified"] += hot_bytes_found
        self._last_taint_time = time.time()

        return CycleResult(
            technique="taint",
            trigger_reason=reason,
            start_time=start_time,
            end_time=time.time(),
            inputs_analyzed=inputs_analyzed,
            inputs_generated=0,
            coverage_contributions=0,
            errors=errors,
            warnings=warnings,
        )

    def get_status(self) -> HybridFuzzingStatus:
        """Get current orchestrator status."""
        runtime = time.time() - self._start_time if self._start_time else 0

        # Calculate next run times
        next_concolic = None
        next_taint = None

        if self._running:
            if self._concolic_service:
                next_time = self._last_concolic_time + self.config.concolic_interval_seconds
                next_concolic = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_time))

            if self._taint_service:
                next_time = self._last_taint_time + self.config.taint_interval_seconds
                next_taint = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_time))

        return HybridFuzzingStatus(
            session_id=self.session_id,
            mode=self.config.mode,
            running=self._running,
            runtime_seconds=runtime,
            # Concolic
            concolic_enabled=self.config.enable_concolic and self._concolic_service is not None,
            concolic_runs=self._stats["concolic_runs"],
            concolic_inputs_generated=self._stats["concolic_inputs_generated"],
            concolic_coverage_contributions=self._stats["concolic_coverage_contributions"],
            last_concolic_run=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._last_concolic_time)) if self._last_concolic_time > 0 else None,
            next_concolic_run=next_concolic,
            # Taint
            taint_enabled=self.config.enable_taint and self._taint_service is not None,
            taint_analyses=self._stats["taint_analyses"],
            hot_bytes_identified=self._stats["hot_bytes_identified"],
            taint_guided_mutations=self._stats["taint_guided_mutations"],
            last_taint_run=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._last_taint_time)) if self._last_taint_time > 0 else None,
            next_taint_run=next_taint,
            # LAF
            laf_enabled=self.config.enable_laf and self._laf_service is not None,
            laf_instrumented=self.config.laf_instrumented_path is not None,
            # Detection
            stagnation_detected=(time.time() - self._last_coverage_time) > self.config.stagnation_threshold_seconds if self._running else False,
            coverage_plateau_detected=False,  # Calculated in _check_triggers
            last_new_coverage_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._last_coverage_time)) if self._last_coverage_time > 0 else None,
        )

    def get_laf_env_vars(self) -> Dict[str, str]:
        """Get LAF-Intel environment variables for AFL++ startup."""
        if not self._laf_service:
            self._laf_service = LafIntelService()

        return self._laf_service.get_env_vars(self.config.laf_modes)

    def get_hot_bytes_for_input(self, input_path: str) -> List[int]:
        """Get cached hot bytes for an input (for mutation guidance)."""
        return self._hot_bytes_map.get(input_path, [])

    def get_campaign_controller_actions(self) -> List[Dict[str, Any]]:
        """
        Get recommended actions for campaign controller integration.

        Returns list of actions the campaign controller should consider.
        """
        actions = []
        current_time = time.time()

        # Check if concolic should run
        if self._should_run_concolic(current_time):
            stagnation_time = current_time - self._last_coverage_time
            if stagnation_time > self.config.stagnation_threshold_seconds:
                actions.append({
                    "action": "trigger_concolic_cycle",
                    "priority": "high",
                    "reason": f"Coverage stagnation for {int(stagnation_time)}s",
                })
            else:
                actions.append({
                    "action": "trigger_concolic_cycle",
                    "priority": "medium",
                    "reason": "Scheduled concolic cycle",
                })

        # Check if taint should run
        if self._should_run_taint(current_time):
            if self._last_crash_count > 0:
                actions.append({
                    "action": "trigger_taint_analysis",
                    "priority": "high",
                    "reason": f"Analyze {self._last_crash_count} crashes for hot bytes",
                })
            else:
                actions.append({
                    "action": "trigger_taint_analysis",
                    "priority": "low",
                    "reason": "Scheduled taint analysis",
                })

        # LAF recommendation
        if self.config.enable_laf and not self.config.laf_instrumented_path:
            if self._laf_service and self._laf_service.check_laf_availability().available:
                actions.append({
                    "action": "rebuild_with_laf_intel",
                    "priority": "medium",
                    "reason": "LAF-Intel available but target not instrumented",
                })

        return actions


# Convenience function
async def check_hybrid_capabilities() -> Dict[str, Any]:
    """Check all hybrid fuzzing capabilities."""
    return {
        "concolic": await check_concolic_installation(),
        "taint": await check_taint_backend_installation(),
        "laf": LafIntelService().check_laf_availability().to_dict(),
    }
