"""
Fuzzing Engine Wrapper

Robust wrappers for fuzzing engines (AFL++, honggfuzz, etc.)
with mock mode support for testing and environments without fuzzers installed.
"""

import asyncio
import hashlib
import logging
import os
import random
import shutil
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import json

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

ENGINE_HEALTH_CHECK_INTERVAL = 30  # seconds
ENGINE_RESTART_DELAY = 5  # seconds
MAX_ENGINE_RESTARTS = 3
STATS_POLL_INTERVAL = 5  # seconds


# =============================================================================
# Data Classes
# =============================================================================

class EngineType(str, Enum):
    """Supported fuzzing engine types."""
    AFL = "afl"
    AFLPP = "aflpp"
    HONGGFUZZ = "honggfuzz"
    LIBFUZZER = "libfuzzer"
    MOCK = "mock"  # Simulation mode


class EngineStatus(str, Enum):
    """Engine lifecycle states."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    CRASHED = "crashed"


@dataclass
class EngineConfig:
    """
    Configuration for a fuzzing engine.

    For AFL++, use native features instead of Python reimplementations:
    - power_schedule: Use AFL++'s built-in schedules (fast, coe, explore, rare, etc.)
    - cmplog_binary: Path to CMPLOG-instrumented binary for magic byte solving
    - use_mopt: Enable MOpt adaptive mutation scheduling
    - dictionary_path: Path to dictionary file
    """
    engine_type: EngineType
    binary_path: str
    seed_dir: str
    output_dir: str
    timeout_ms: int = 1000
    memory_limit_mb: int = 2048
    extra_args: Any = field(default_factory=list)  # List[str] or Dict for extended config
    environment: Dict[str, str] = field(default_factory=dict)
    mock_mode: bool = False  # Force mock mode even if fuzzer available

    # AFL++ native features (USE THESE instead of Python reimplementations)
    power_schedule: str = "explore"  # fast, coe, explore, exploit, seek, rare, mmopt, quad
    cmplog_binary: Optional[str] = None  # Path to CMPLOG binary (compile with afl-clang-fast -c)
    use_mopt: bool = True  # Enable MOpt adaptive mutation scheduling
    dictionary_path: Optional[str] = None  # Dictionary for guided mutations
    skip_deterministic: bool = False  # Skip deterministic stage (faster for large inputs)
    quick_mode: bool = False  # Quick & dirty mode (for testing)

    # QEMU/FRIDA mode for uninstrumented binaries
    qemu_mode: bool = False  # Use QEMU for uninstrumented binaries (-Q flag)
    frida_mode: bool = False  # Use FRIDA for uninstrumented binaries (-O flag)
    unicorn_mode: bool = False  # Use Unicorn for emulation (-U flag)
    nyx_mode: bool = False  # Use Nyx for snapshot fuzzing


@dataclass
class EngineStats:
    """Statistics from a fuzzing engine."""
    engine_id: str
    engine_type: EngineType
    status: EngineStatus
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Execution metrics
    executions: int = 0
    executions_per_sec: float = 0.0

    # Coverage metrics
    edges_found: int = 0
    edges_total: int = 0
    coverage_pct: float = 0.0

    # Corpus metrics
    corpus_size: int = 0
    corpus_bytes: int = 0

    # Crash metrics
    crashes_found: int = 0
    unique_crashes: int = 0
    hangs_found: int = 0

    # Health
    is_healthy: bool = True
    last_error: Optional[str] = None
    restart_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "engine_id": self.engine_id,
            "engine_type": self.engine_type.value,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "executions": self.executions,
            "executions_per_sec": self.executions_per_sec,
            "edges_found": self.edges_found,
            "coverage_pct": self.coverage_pct,
            "corpus_size": self.corpus_size,
            "crashes_found": self.crashes_found,
            "unique_crashes": self.unique_crashes,
            "hangs_found": self.hangs_found,
            "is_healthy": self.is_healthy,
            "last_error": self.last_error,
        }


@dataclass
class CrashInfo:
    """Information about a crash."""
    crash_id: str
    crash_hash: str
    input_data: bytes
    input_size: int
    discovered_at: datetime
    crash_type: Optional[str] = None
    signal: Optional[int] = None
    stderr: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "crash_id": self.crash_id,
            "crash_hash": self.crash_hash,
            "input_size": self.input_size,
            "discovered_at": self.discovered_at.isoformat(),
            "crash_type": self.crash_type,
            "signal": self.signal,
        }


# =============================================================================
# Abstract Base Engine
# =============================================================================

class FuzzingEngine(ABC):
    """Abstract base class for fuzzing engine wrappers."""

    def __init__(self, engine_id: str, config: EngineConfig):
        self.engine_id = engine_id
        self.config = config
        self._status = EngineStatus.STOPPED
        self._stats = EngineStats(
            engine_id=engine_id,
            engine_type=config.engine_type,
            status=EngineStatus.STOPPED,
        )
        self._crashes: List[CrashInfo] = []
        self._process: Optional[asyncio.subprocess.Process] = None
        self._restart_count = 0
        self._health_task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None

    @property
    def status(self) -> EngineStatus:
        return self._status

    @property
    def is_running(self) -> bool:
        return self._status == EngineStatus.RUNNING

    @abstractmethod
    async def _do_start(self) -> bool:
        """Implementation-specific start logic."""
        pass

    @abstractmethod
    async def _do_stop(self) -> None:
        """Implementation-specific stop logic."""
        pass

    @abstractmethod
    async def _do_get_stats(self) -> EngineStats:
        """Implementation-specific stats collection."""
        pass

    @abstractmethod
    async def _do_get_crashes(self) -> List[CrashInfo]:
        """Implementation-specific crash collection."""
        pass

    async def start(self) -> bool:
        """Start the fuzzing engine with error handling."""
        if self._status == EngineStatus.RUNNING:
            logger.warning(f"Engine {self.engine_id} already running")
            return True

        self._status = EngineStatus.STARTING
        self._stats.status = EngineStatus.STARTING

        try:
            # Validate configuration
            if not self._validate_config():
                self._status = EngineStatus.ERROR
                self._stats.is_healthy = False
                self._stats.last_error = "Invalid configuration"
                return False

            # Create directories
            self._ensure_directories()

            # Start engine
            success = await self._do_start()

            if success:
                self._status = EngineStatus.RUNNING
                self._stats.status = EngineStatus.RUNNING
                self._stats.is_healthy = True

                # Start background tasks
                self._health_task = asyncio.create_task(self._health_check_loop())
                self._stats_task = asyncio.create_task(self._stats_poll_loop())

                logger.info(f"Engine {self.engine_id} started successfully")
            else:
                self._status = EngineStatus.ERROR
                self._stats.status = EngineStatus.ERROR
                self._stats.is_healthy = False
                logger.error(f"Engine {self.engine_id} failed to start")

            return success

        except Exception as e:
            logger.error(f"Engine {self.engine_id} start error: {e}")
            self._status = EngineStatus.ERROR
            self._stats.status = EngineStatus.ERROR
            self._stats.is_healthy = False
            self._stats.last_error = str(e)
            return False

    async def stop(self) -> None:
        """Stop the fuzzing engine gracefully."""
        if self._status == EngineStatus.STOPPED:
            return

        logger.info(f"Stopping engine {self.engine_id}")
        self._status = EngineStatus.STOPPED

        # Cancel background tasks
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        if self._stats_task:
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass

        # Stop engine
        try:
            await self._do_stop()
        except Exception as e:
            logger.warning(f"Error stopping engine {self.engine_id}: {e}")

        self._stats.status = EngineStatus.STOPPED
        logger.info(f"Engine {self.engine_id} stopped")

    async def get_stats(self) -> EngineStats:
        """Get current engine statistics."""
        try:
            if self._status == EngineStatus.RUNNING:
                self._stats = await self._do_get_stats()
            self._stats.timestamp = datetime.utcnow()
            return self._stats
        except Exception as e:
            logger.warning(f"Error getting stats for {self.engine_id}: {e}")
            self._stats.is_healthy = False
            self._stats.last_error = str(e)
            return self._stats

    async def get_crashes(self) -> List[CrashInfo]:
        """Get crashes found by this engine."""
        try:
            if self._status == EngineStatus.RUNNING:
                new_crashes = await self._do_get_crashes()
                # Deduplicate
                seen = {c.crash_hash for c in self._crashes}
                for crash in new_crashes:
                    if crash.crash_hash not in seen:
                        self._crashes.append(crash)
                        seen.add(crash.crash_hash)
            return self._crashes
        except Exception as e:
            logger.warning(f"Error getting crashes for {self.engine_id}: {e}")
            return self._crashes

    async def add_seed(self, seed_data: bytes, name: Optional[str] = None) -> bool:
        """Add a seed to the engine's corpus."""
        if not seed_data:
            return False

        try:
            if not name:
                name = f"seed_{hashlib.md5(seed_data).hexdigest()[:16]}"

            seed_path = os.path.join(self.config.seed_dir, name)
            with open(seed_path, "wb") as f:
                f.write(seed_data)

            logger.debug(f"Added seed {name} to {self.engine_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to add seed to {self.engine_id}: {e}")
            return False

    def _validate_config(self) -> bool:
        """Validate engine configuration."""
        if not self.config.binary_path:
            logger.error("No binary path specified")
            return False

        if not os.path.exists(self.config.binary_path):
            logger.error(f"Binary not found: {self.config.binary_path}")
            return False

        return True

    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        os.makedirs(self.config.seed_dir, exist_ok=True)
        os.makedirs(self.config.output_dir, exist_ok=True)

    async def _health_check_loop(self) -> None:
        """Background task to monitor engine health."""
        while self._status == EngineStatus.RUNNING:
            try:
                await asyncio.sleep(ENGINE_HEALTH_CHECK_INTERVAL)

                if not await self._check_health():
                    logger.warning(f"Engine {self.engine_id} unhealthy")
                    self._stats.is_healthy = False

                    if self._restart_count < MAX_ENGINE_RESTARTS:
                        await self._attempt_restart()
                    else:
                        logger.error(f"Engine {self.engine_id} exceeded max restarts")
                        self._status = EngineStatus.CRASHED

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")

    async def _stats_poll_loop(self) -> None:
        """Background task to poll statistics."""
        while self._status == EngineStatus.RUNNING:
            try:
                await asyncio.sleep(STATS_POLL_INTERVAL)
                await self.get_stats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Stats poll error: {e}")

    async def _check_health(self) -> bool:
        """Check if engine is healthy."""
        if self._process is None:
            return False

        # Check if process is still running
        if self._process.returncode is not None:
            return False

        return True

    async def _attempt_restart(self) -> None:
        """Attempt to restart the engine."""
        logger.info(f"Attempting restart of {self.engine_id}")
        self._restart_count += 1
        self._stats.restart_count = self._restart_count

        await self._do_stop()
        await asyncio.sleep(ENGINE_RESTART_DELAY)

        success = await self._do_start()
        if success:
            self._status = EngineStatus.RUNNING
            self._stats.is_healthy = True
            logger.info(f"Engine {self.engine_id} restarted successfully")
        else:
            self._status = EngineStatus.ERROR
            logger.error(f"Engine {self.engine_id} restart failed")


# =============================================================================
# Mock Engine (Simulation Mode)
# =============================================================================

class MockFuzzingEngine(FuzzingEngine):
    """
    Mock fuzzing engine for testing and environments without real fuzzers.

    Simulates realistic fuzzing behavior including:
    - Gradual coverage increase
    - Occasional crash discovery
    - Performance variations
    """

    def __init__(self, engine_id: str, config: EngineConfig):
        config.engine_type = EngineType.MOCK
        super().__init__(engine_id, config)

        # Simulation state
        self._sim_start_time: Optional[float] = None
        self._sim_executions = 0
        self._sim_edges = 0
        self._sim_max_edges = random.randint(5000, 20000)
        self._sim_crashes: List[CrashInfo] = []
        self._sim_corpus: List[bytes] = []

    async def _do_start(self) -> bool:
        """Start mock fuzzing simulation."""
        self._sim_start_time = time.time()

        # Initialize with some seeds
        for seed_file in Path(self.config.seed_dir).glob("*"):
            if seed_file.is_file():
                try:
                    self._sim_corpus.append(seed_file.read_bytes())
                except Exception:
                    pass

        if not self._sim_corpus:
            # Add default seed
            self._sim_corpus.append(b"AAAA")

        logger.info(f"Mock engine {self.engine_id} started with {len(self._sim_corpus)} seeds")
        return True

    async def _do_stop(self) -> None:
        """Stop mock fuzzing simulation."""
        self._sim_start_time = None
        logger.info(f"Mock engine {self.engine_id} stopped")

    async def _do_get_stats(self) -> EngineStats:
        """Generate simulated statistics."""
        if self._sim_start_time is None:
            return self._stats

        elapsed = time.time() - self._sim_start_time

        # Simulate execution progress
        base_exec_rate = random.uniform(500, 2000)
        self._sim_executions += int(base_exec_rate * STATS_POLL_INTERVAL)

        # Simulate coverage growth (logarithmic curve)
        coverage_rate = max(0.1, 1.0 - (elapsed / 3600))  # Decreases over time
        new_edges = int(random.uniform(0, 10) * coverage_rate)
        self._sim_edges = min(self._sim_edges + new_edges, self._sim_max_edges)

        # Occasionally discover a crash
        if random.random() < 0.001:  # 0.1% chance per poll
            await self._generate_mock_crash()

        self._stats.executions = self._sim_executions
        self._stats.executions_per_sec = base_exec_rate
        self._stats.edges_found = self._sim_edges
        self._stats.edges_total = self._sim_max_edges
        self._stats.coverage_pct = (self._sim_edges / self._sim_max_edges) * 100
        self._stats.corpus_size = len(self._sim_corpus)
        self._stats.crashes_found = len(self._sim_crashes)
        self._stats.unique_crashes = len(self._sim_crashes)
        self._stats.is_healthy = True

        return self._stats

    async def _do_get_crashes(self) -> List[CrashInfo]:
        """Return simulated crashes."""
        return self._sim_crashes

    async def _generate_mock_crash(self) -> None:
        """Generate a simulated crash."""
        # Create crash input from mutated corpus entry
        if self._sim_corpus:
            base = random.choice(self._sim_corpus)
        else:
            base = b"AAAA"

        # Mutate
        crash_input = bytearray(base)
        for _ in range(random.randint(1, 10)):
            if crash_input:
                idx = random.randint(0, len(crash_input) - 1)
                crash_input[idx] = random.randint(0, 255)

        crash_data = bytes(crash_input)
        crash_hash = hashlib.sha256(crash_data).hexdigest()

        # Check if duplicate
        if any(c.crash_hash == crash_hash for c in self._sim_crashes):
            return

        crash_types = [
            "SEGV", "SIGABRT", "HEAP_OVERFLOW", "STACK_OVERFLOW",
            "USE_AFTER_FREE", "NULL_DEREF", "DOUBLE_FREE"
        ]

        crash = CrashInfo(
            crash_id=f"crash_{len(self._sim_crashes):04d}",
            crash_hash=crash_hash[:16],
            input_data=crash_data,
            input_size=len(crash_data),
            discovered_at=datetime.utcnow(),
            crash_type=random.choice(crash_types),
            signal=random.choice([6, 11, 4, 8]),
        )

        self._sim_crashes.append(crash)
        logger.info(f"Mock crash discovered: {crash.crash_type}")

    async def _check_health(self) -> bool:
        """Mock engine is always healthy."""
        return self._sim_start_time is not None


# =============================================================================
# AFL++ Engine
# =============================================================================

class AFLPlusPlusEngine(FuzzingEngine):
    """
    AFL++ fuzzing engine wrapper with FULL feature support.

    AFL++ is a state-of-the-art fuzzer with many powerful features.
    This wrapper exposes ALL of them for maximum effectiveness.

    Key features enabled:
    - Power schedules (fast, coe, explore, exploit, rare, etc.)
    - CMPLOG for automatic magic byte solving
    - MOpt mutation scheduling
    - Persistent mode support
    - Dictionary support
    - Multiple input modes
    """

    AFL_BINARY = "afl-fuzz"
    AFL_CMIN = "afl-cmin"
    AFL_TMIN = "afl-tmin"
    AFL_SHOWMAP = "afl-showmap"

    # AFL++ power schedules (use native, not Python reimplementation)
    POWER_SCHEDULES = ["fast", "coe", "explore", "exploit", "seek", "rare", "mmopt", "quad"]

    def __init__(self, engine_id: str, config: EngineConfig):
        config.engine_type = EngineType.AFLPP
        super().__init__(engine_id, config)
        self._afl_available = self._check_afl_available()
        self._cmplog_binary: Optional[str] = None
        self._dictionary_path: Optional[str] = None

    def _check_afl_available(self) -> bool:
        """Check if AFL++ is installed."""
        return shutil.which(self.AFL_BINARY) is not None

    def _validate_config(self) -> bool:
        """Validate configuration including AFL availability."""
        if not super()._validate_config():
            return False

        if not self._afl_available:
            logger.error("AFL++ not found in PATH")
            return False

        return True

    def set_cmplog_binary(self, cmplog_binary_path: str):
        """Set CMPLOG-instrumented binary for automatic magic byte solving."""
        if os.path.exists(cmplog_binary_path):
            self._cmplog_binary = cmplog_binary_path
            logger.info(f"CMPLOG binary set: {cmplog_binary_path}")
        else:
            logger.warning(f"CMPLOG binary not found: {cmplog_binary_path}")

    def set_dictionary(self, dictionary_path: str):
        """Set dictionary file for mutation guidance."""
        if os.path.exists(dictionary_path):
            self._dictionary_path = dictionary_path
            logger.info(f"Dictionary set: {dictionary_path}")
        else:
            logger.warning(f"Dictionary not found: {dictionary_path}")

    async def _do_start(self) -> bool:
        """
        Start AFL++ fuzzer with FULL feature set.

        This uses AFL++'s native capabilities instead of reimplementing them:
        - Power schedules via -P flag
        - CMPLOG via -c flag
        - MOpt via -L flag
        - Dictionary via -x flag
        """
        cmd = [
            self.AFL_BINARY,
            "-i", self.config.seed_dir,
            "-o", self.config.output_dir,
            "-t", str(self.config.timeout_ms),
            "-m", str(self.config.memory_limit_mb),
        ]

        # =================================================================
        # AFL++ NATIVE POWER SCHEDULE (instead of our Python implementation)
        # =================================================================
        # -P <schedule> : Use specific power schedule
        # Options: fast, coe, explore, exploit, seek, rare, mmopt, quad
        # Default: explore (good balance)
        # "rare" is best for finding new coverage
        # "exploit" is best when you have crashes and want more
        if self.config.power_schedule in self.POWER_SCHEDULES:
            cmd.extend(["-P", self.config.power_schedule])
            logger.info(f"AFL++ using native power schedule: {self.config.power_schedule}")

        # =================================================================
        # AFL++ NATIVE CMPLOG (instead of our Python implementation)
        # =================================================================
        # -c <cmplog_binary> : Enable comparison logging
        # This is 10-100x more effective than our Python CMPLOG
        # AFL++ will automatically solve magic bytes, checksums, etc.
        cmplog = self._cmplog_binary or self.config.cmplog_binary
        if cmplog and os.path.exists(cmplog):
            cmd.extend(["-c", cmplog])
            # -l <level> : CMPLOG level (2 = arithmetic solving, 3 = transform solving)
            cmd.extend(["-l", "2"])
            logger.info("AFL++ CMPLOG enabled (native magic byte solving)")

        # =================================================================
        # AFL++ MOpt MUTATION SCHEDULING
        # =================================================================
        # -L 0 : Enable MOpt mutation scheduling (learns best mutations)
        # This replaces manual mutation weight tuning
        if self.config.use_mopt:
            cmd.extend(["-L", "0"])
            logger.info("AFL++ MOpt enabled (adaptive mutation scheduling)")

        # =================================================================
        # DICTIONARY SUPPORT
        # =================================================================
        # -x <dict> : Use dictionary for mutations
        dictionary = self._dictionary_path or self.config.dictionary_path
        if dictionary and os.path.exists(dictionary):
            cmd.extend(["-x", dictionary])
            logger.info(f"AFL++ dictionary: {dictionary}")

        # =================================================================
        # PERSISTENT MODE DETECTION
        # =================================================================
        # AFL++ auto-detects persistent mode harnesses
        # No flag needed - just compile target with __AFL_LOOP

        # =================================================================
        # ADDITIONAL PERFORMANCE FLAGS
        # =================================================================
        # -D : Skip deterministic stage (faster for large inputs)
        if self.config.skip_deterministic:
            cmd.extend(["-D"])

        # -d : Quick & dirty mode (skip deterministic, for testing)
        if self.config.quick_mode:
            cmd.extend(["-d"])

        # =================================================================
        # QEMU/FRIDA MODE FOR UNINSTRUMENTED BINARIES
        # =================================================================
        # These modes allow fuzzing binaries without source code
        # -Q : QEMU mode (slower but works on any binary)
        # -O : FRIDA mode (faster than QEMU, requires frida-gum)
        # -U : Unicorn mode (for emulating specific architectures)
        if self.config.qemu_mode:
            cmd.extend(["-Q"])
            logger.info("AFL++ QEMU mode enabled (fuzzing uninstrumented binary)")
        elif self.config.frida_mode:
            cmd.extend(["-O"])
            logger.info("AFL++ FRIDA mode enabled (fuzzing uninstrumented binary)")
        elif self.config.unicorn_mode:
            cmd.extend(["-U"])
            logger.info("AFL++ Unicorn mode enabled")

        # Check for extra args from config
        if isinstance(self.config.extra_args, list):
            cmd.extend(self.config.extra_args)
        elif isinstance(self.config.extra_args, dict):
            # Handle dict-style extra args (from our persistent mode integration)
            if self.config.extra_args.get('persistent_mode'):
                logger.info("Target compiled with persistent mode - AFL++ will auto-detect")
            if self.config.extra_args.get('use_cmplog') and not self._cmplog_binary:
                logger.info("CMPLOG requested but no cmplog binary set - compile target with afl-clang-fast -c")

        # Target binary
        cmd.extend(["--", self.config.binary_path, "@@"])

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, **self.config.environment},
            )

            # Wait briefly to check for immediate failure
            await asyncio.sleep(1)

            if self._process.returncode is not None:
                stderr = await self._process.stderr.read()
                logger.error(f"AFL++ failed to start: {stderr.decode()}")
                return False

            return True

        except FileNotFoundError:
            logger.error(f"AFL++ binary not found: {self.AFL_BINARY}")
            return False
        except Exception as e:
            logger.error(f"Failed to start AFL++: {e}")
            return False

    async def _do_stop(self) -> None:
        """Stop AFL++ fuzzer."""
        if self._process is None:
            return

        try:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        except Exception as e:
            logger.warning(f"Error stopping AFL++: {e}")

        self._process = None

    async def _do_get_stats(self) -> EngineStats:
        """Parse AFL++ fuzzer_stats file."""
        stats_file = os.path.join(self.config.output_dir, "default", "fuzzer_stats")

        try:
            if not os.path.exists(stats_file):
                return self._stats

            with open(stats_file, "r") as f:
                stats_data = {}
                for line in f:
                    if ":" in line:
                        key, value = line.strip().split(":", 1)
                        stats_data[key.strip()] = value.strip()

            self._stats.executions = int(stats_data.get("execs_done", 0))
            self._stats.executions_per_sec = float(stats_data.get("execs_per_sec", 0))
            self._stats.edges_found = int(stats_data.get("edges_found", 0))
            self._stats.corpus_size = int(stats_data.get("corpus_count", 0))
            self._stats.crashes_found = int(stats_data.get("saved_crashes", 0))
            self._stats.unique_crashes = int(stats_data.get("saved_crashes", 0))
            self._stats.hangs_found = int(stats_data.get("saved_hangs", 0))

            # Calculate coverage percentage
            map_size = int(stats_data.get("map_size", 65536))
            if map_size > 0:
                self._stats.coverage_pct = (self._stats.edges_found / map_size) * 100

            self._stats.is_healthy = True

        except Exception as e:
            logger.warning(f"Failed to parse AFL++ stats: {e}")
            self._stats.last_error = str(e)

        return self._stats

    async def _do_get_crashes(self) -> List[CrashInfo]:
        """Get crashes from AFL++ output directory."""
        crashes = []
        crash_dir = os.path.join(self.config.output_dir, "default", "crashes")

        if not os.path.exists(crash_dir):
            return crashes

        try:
            for filename in os.listdir(crash_dir):
                if filename.startswith("id:") or filename.startswith("crash_"):
                    crash_path = os.path.join(crash_dir, filename)
                    try:
                        with open(crash_path, "rb") as f:
                            data = f.read()

                        crash_hash = hashlib.sha256(data).hexdigest()

                        crashes.append(CrashInfo(
                            crash_id=filename,
                            crash_hash=crash_hash[:16],
                            input_data=data,
                            input_size=len(data),
                            discovered_at=datetime.fromtimestamp(os.path.getmtime(crash_path)),
                        ))
                    except Exception as e:
                        logger.warning(f"Failed to read crash {filename}: {e}")
        except Exception as e:
            logger.warning(f"Failed to list crashes: {e}")

        return crashes


# =============================================================================
# Engine Factory
# =============================================================================

def check_fuzzer_availability() -> Dict[str, bool]:
    """Check which fuzzers are available on the system."""
    fuzzers = {
        "afl-fuzz": shutil.which("afl-fuzz") is not None,
        "afl++": shutil.which("afl-fuzz") is not None,  # AFL++ uses same binary
        "honggfuzz": shutil.which("honggfuzz") is not None,
        "libfuzzer": False,  # Requires compilation, not a standalone binary
    }
    return fuzzers


def create_engine(
    engine_id: str,
    config: EngineConfig,
    prefer_mock: bool = False,
) -> FuzzingEngine:
    """
    Factory function to create appropriate fuzzing engine.

    Args:
        engine_id: Unique identifier for the engine
        config: Engine configuration
        prefer_mock: If True, always use mock engine

    Returns:
        FuzzingEngine instance
    """
    # Force mock mode if requested
    if prefer_mock or config.mock_mode:
        logger.info(f"Creating mock engine for {engine_id}")
        return MockFuzzingEngine(engine_id, config)

    # Try to use real fuzzer
    if config.engine_type in [EngineType.AFL, EngineType.AFLPP]:
        if shutil.which("afl-fuzz"):
            logger.info(f"Creating AFL++ engine for {engine_id}")
            return AFLPlusPlusEngine(engine_id, config)
        else:
            logger.warning(f"AFL++ not available, falling back to mock for {engine_id}")
            return MockFuzzingEngine(engine_id, config)

    # Default to mock
    logger.info(f"Using mock engine for {engine_id}")
    return MockFuzzingEngine(engine_id, config)


# =============================================================================
# Engine Pool
# =============================================================================

class EnginePool:
    """
    Manages a pool of fuzzing engines with automatic failover.
    """

    def __init__(self, max_engines: int = 4):
        self.max_engines = max_engines
        self._engines: Dict[str, FuzzingEngine] = {}
        self._lock = asyncio.Lock()

    async def add_engine(
        self,
        engine_id: str,
        config: EngineConfig,
        prefer_mock: bool = False,
    ) -> Optional[FuzzingEngine]:
        """Add and start a new engine."""
        async with self._lock:
            if len(self._engines) >= self.max_engines:
                logger.warning(f"Engine pool full ({self.max_engines})")
                return None

            if engine_id in self._engines:
                logger.warning(f"Engine {engine_id} already exists")
                return self._engines[engine_id]

            engine = create_engine(engine_id, config, prefer_mock)

            if await engine.start():
                self._engines[engine_id] = engine
                return engine
            else:
                return None

    async def remove_engine(self, engine_id: str) -> bool:
        """Stop and remove an engine."""
        async with self._lock:
            if engine_id not in self._engines:
                return False

            engine = self._engines.pop(engine_id)
            await engine.stop()
            return True

    async def stop_all(self) -> None:
        """Stop all engines."""
        async with self._lock:
            for engine in self._engines.values():
                await engine.stop()
            self._engines.clear()

    async def get_all_stats(self) -> Dict[str, EngineStats]:
        """Get stats from all engines."""
        stats = {}
        for engine_id, engine in self._engines.items():
            stats[engine_id] = await engine.get_stats()
        return stats

    async def get_all_crashes(self) -> List[CrashInfo]:
        """Get crashes from all engines, deduplicated."""
        all_crashes = []
        seen_hashes = set()

        for engine in self._engines.values():
            crashes = await engine.get_crashes()
            for crash in crashes:
                if crash.crash_hash not in seen_hashes:
                    all_crashes.append(crash)
                    seen_hashes.add(crash.crash_hash)

        return all_crashes

    def get_running_count(self) -> int:
        """Get count of running engines."""
        return sum(1 for e in self._engines.values() if e.is_running)

    def get_healthy_count(self) -> int:
        """Get count of healthy engines."""
        return sum(1 for e in self._engines.values() if e._stats.is_healthy)
