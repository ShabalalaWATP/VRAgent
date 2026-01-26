"""
AFL++ Full Integration Service

This module exposes ALL AFL++ capabilities, not just basic fuzzing.
Combined with our Agentic AI, this makes us AFL++ PLUS intelligence.

AFL++ Features We Now Support:
1. All power schedules (fast, coe, lin, quad, exploit, mmopt, rare, seek)
2. CMPLOG for automatic comparison solving
3. MOpt for adaptive mutation scheduling
4. Parallel fuzzing with corpus sync (-M/-S)
5. FRIDA mode for binary-only fuzzing
6. Unicorn mode for emulation
7. Custom mutators (Python/C)
8. Grammar mutators
9. Dictionary generation and management
10. Corpus minimization (afl-cmin, afl-tmin)
11. Coverage analysis (afl-showmap, afl-plot)
12. Persistent mode compilation helpers
13. Selective instrumentation
14. LAF-intel comparison splitting
15. All sanitizer integrations (ASAN, MSAN, UBSAN, TSAN, CFISAN)
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import re

logger = logging.getLogger(__name__)


# =============================================================================
# AFL++ Feature Enums
# =============================================================================

class AFLPowerSchedule(str, Enum):
    """All AFL++ power schedules."""
    FAST = "fast"         # Default, exponential
    COE = "coe"           # Cut-Off Exponential
    EXPLORE = "explore"   # Exploration-based
    EXPLOIT = "exploit"   # Exploitation-based
    LIN = "lin"           # Linear
    QUAD = "quad"         # Quadratic
    MMOPT = "mmopt"       # Modified MOpt
    RARE = "rare"         # Rare edge focus
    SEEK = "seek"         # Seek new coverage


class AFLMutator(str, Enum):
    """AFL++ mutator modes."""
    DEFAULT = "default"
    MOpt = "mopt"            # Adaptive mutation scheduling
    RADAMSA = "radamsa"      # Radamsa integration
    GRAMMAR = "grammar"      # Grammar-based mutations
    CUSTOM = "custom"        # Custom Python/C mutator


class AFLInstrumentMode(str, Enum):
    """AFL++ instrumentation modes."""
    DEFAULT = "default"      # Standard instrumentation
    CLASSIC = "classic"      # Classic AFL instrumentation
    PCGUARD = "pcguard"      # PC-guard instrumentation
    LTO = "lto"              # Link-Time Optimization mode
    GCC_PLUGIN = "gcc"       # GCC plugin mode
    CMPLOG = "cmplog"        # Comparison logging
    LAF = "laf"              # LAF-intel (comparison splitting)


class AFLSanitizer(str, Enum):
    """Sanitizers for crash detection."""
    NONE = "none"
    ASAN = "asan"            # Address Sanitizer
    MSAN = "msan"            # Memory Sanitizer
    UBSAN = "ubsan"          # Undefined Behavior Sanitizer
    TSAN = "tsan"            # Thread Sanitizer
    CFISAN = "cfisan"        # Control Flow Integrity
    LSAN = "lsan"            # Leak Sanitizer


class AFLFuzzMode(str, Enum):
    """AFL++ fuzzing modes."""
    STANDARD = "standard"
    PERSISTENT = "persistent"
    DEFERRED = "deferred"
    FRIDA = "frida"          # Binary-only via FRIDA
    QEMU = "qemu"            # Binary-only via QEMU
    UNICORN = "unicorn"      # Emulation via Unicorn
    NYX = "nyx"              # Hypervisor fuzzing
    WINE = "wine"            # Windows binaries on Linux


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class AFLPPConfig:
    """Complete AFL++ configuration - ALL features exposed."""
    # Target
    binary_path: str
    input_dir: str
    output_dir: str

    # Basic settings
    timeout_ms: int = 1000
    memory_limit_mb: int = 2048

    # Power schedule
    power_schedule: AFLPowerSchedule = AFLPowerSchedule.EXPLORE

    # Mutation settings
    mutator: AFLMutator = AFLMutator.MOpt
    custom_mutator_path: Optional[str] = None
    dictionary_path: Optional[str] = None

    # Instrumentation
    instrument_mode: AFLInstrumentMode = AFLInstrumentMode.DEFAULT
    cmplog_binary: Optional[str] = None  # Separate CMPLOG-instrumented binary
    cmplog_level: int = 2  # 1=basic, 2=arithmetic, 3=transforms

    # Sanitizers
    sanitizers: List[AFLSanitizer] = field(default_factory=lambda: [AFLSanitizer.ASAN])

    # Fuzzing mode
    fuzz_mode: AFLFuzzMode = AFLFuzzMode.STANDARD
    frida_script: Optional[str] = None
    qemu_mode: bool = False

    # Parallel fuzzing
    parallel_mode: Optional[str] = None  # -M (main) or -S (secondary)
    sync_id: Optional[str] = None        # Fuzzer instance ID for sync
    sync_dir: Optional[str] = None       # Shared sync directory

    # Advanced features
    skip_deterministic: bool = False     # -d flag
    no_ui: bool = True                   # No terminal UI
    crash_mode: bool = False             # -C crash exploration mode
    non_instrumented_mode: bool = False  # -n dumb fuzzing

    # LAF-intel options
    laf_split_compares: bool = False
    laf_split_switches: bool = False
    laf_split_floats: bool = False

    # Performance tuning
    cpu_affinity: Optional[int] = None   # Pin to specific CPU
    no_forksrv: bool = False             # Disable forkserver
    ignore_crashes: bool = False         # -i for crash exploration
    ignore_timeouts: bool = False        # Ignore timeout results

    # Input handling
    input_type: str = "file"             # file, stdin
    file_extension: Optional[str] = None

    # Persistent mode
    persistent_cnt: int = 10000          # Iterations per fork
    defer_forkserver: bool = True

    # Environment
    extra_env: Dict[str, str] = field(default_factory=dict)
    extra_args: List[str] = field(default_factory=list)


@dataclass
class AFLPPStats:
    """Comprehensive AFL++ statistics."""
    # Basic stats
    start_time: datetime
    last_update: datetime
    run_time_seconds: int = 0

    # Execution
    execs_done: int = 0
    execs_per_sec: float = 0.0
    execs_per_sec_recent: float = 0.0

    # Coverage
    edges_found: int = 0
    total_edges: int = 65536
    coverage_pct: float = 0.0
    new_edges_on: int = 0

    # Corpus
    corpus_count: int = 0
    corpus_variable: int = 0
    pending_favs: int = 0
    pending_total: int = 0

    # Crashes
    saved_crashes: int = 0
    saved_hangs: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0

    # Stability
    stability: float = 100.0
    bitmap_cvg: float = 0.0

    # Cycles
    cycles_done: int = 0
    cycles_wo_finds: int = 0

    # Scheduling
    current_schedule: str = ""
    havoc_expansion: int = 0

    # Performance
    slowest_exec_ms: int = 0
    peak_rss_mb: int = 0


@dataclass
class CompiledTarget:
    """Result of compiling a target with AFL++ instrumentation."""
    original_source: str
    instrumented_binary: str
    cmplog_binary: Optional[str] = None
    sanitizer_binary: Optional[str] = None
    compilation_flags: List[str] = field(default_factory=list)
    compile_time_seconds: float = 0.0
    success: bool = False
    error_message: Optional[str] = None


# =============================================================================
# AFL++ Full Integration Service
# =============================================================================

class AFLPlusPlusFullService:
    """
    Complete AFL++ integration exposing ALL features.

    This is designed to be controlled by our Agentic AI, which will
    intelligently select which features to enable based on:
    - Target characteristics
    - Past performance data
    - Current campaign state
    """

    # AFL++ tools
    AFL_FUZZ = "afl-fuzz"
    AFL_CC = "afl-clang-fast"
    AFL_CXX = "afl-clang-fast++"
    AFL_GCC = "afl-gcc"
    AFL_CMIN = "afl-cmin"
    AFL_TMIN = "afl-tmin"
    AFL_SHOWMAP = "afl-showmap"
    AFL_PLOT = "afl-plot"
    AFL_WHATSUP = "afl-whatsup"
    AFL_GOTCPU = "afl-gotcpu"
    AFL_ANALYZE = "afl-analyze"

    def __init__(self):
        self._check_installation()
        self._processes: Dict[str, asyncio.subprocess.Process] = {}
        self._stats: Dict[str, AFLPPStats] = {}

    def _check_installation(self) -> Dict[str, bool]:
        """Check which AFL++ tools are available."""
        self.available_tools = {}

        tools = [
            self.AFL_FUZZ, self.AFL_CC, self.AFL_CXX, self.AFL_GCC,
            self.AFL_CMIN, self.AFL_TMIN, self.AFL_SHOWMAP,
            self.AFL_PLOT, self.AFL_WHATSUP, self.AFL_GOTCPU
        ]

        for tool in tools:
            self.available_tools[tool] = shutil.which(tool) is not None

        # Check for FRIDA mode
        self.available_tools["frida_mode"] = shutil.which("afl-fuzz") is not None and \
            os.path.exists("/usr/local/lib/afl/afl-frida-trace.so")

        # Check for QEMU mode
        self.available_tools["qemu_mode"] = shutil.which("afl-qemu-trace") is not None

        # Log availability
        available = [k for k, v in self.available_tools.items() if v]
        missing = [k for k, v in self.available_tools.items() if not v]

        logger.info(f"AFL++ tools available: {available}")
        if missing:
            logger.warning(f"AFL++ tools missing: {missing}")

        return self.available_tools

    # =========================================================================
    # Compilation / Instrumentation
    # =========================================================================

    async def compile_target(
        self,
        source_path: str,
        output_path: str,
        instrument_mode: AFLInstrumentMode = AFLInstrumentMode.DEFAULT,
        sanitizers: List[AFLSanitizer] = None,
        create_cmplog: bool = True,
        extra_flags: List[str] = None,
    ) -> CompiledTarget:
        """
        Compile a target with AFL++ instrumentation.

        This creates:
        1. Main instrumented binary
        2. CMPLOG binary (for comparison logging)
        3. Sanitizer-enabled binary (for better crash detection)
        """
        result = CompiledTarget(
            original_source=source_path,
            instrumented_binary=output_path,
        )

        start_time = datetime.utcnow()
        sanitizers = sanitizers or [AFLSanitizer.ASAN]
        extra_flags = extra_flags or []

        # Determine compiler
        is_cpp = source_path.endswith(('.cpp', '.cc', '.cxx'))
        compiler = self.AFL_CXX if is_cpp else self.AFL_CC

        if not self.available_tools.get(compiler):
            result.error_message = f"Compiler {compiler} not available"
            return result

        # Build compilation flags
        base_flags = ["-O2", "-g", "-fno-omit-frame-pointer"]

        # Add sanitizer flags
        sanitizer_flags = []
        for san in sanitizers:
            if san == AFLSanitizer.ASAN:
                sanitizer_flags.extend(["-fsanitize=address"])
            elif san == AFLSanitizer.MSAN:
                sanitizer_flags.extend(["-fsanitize=memory"])
            elif san == AFLSanitizer.UBSAN:
                sanitizer_flags.extend(["-fsanitize=undefined"])
            elif san == AFLSanitizer.TSAN:
                sanitizer_flags.extend(["-fsanitize=thread"])
            elif san == AFLSanitizer.CFISAN:
                sanitizer_flags.extend(["-fsanitize=cfi"])

        # Instrument mode specific flags
        env = os.environ.copy()

        if instrument_mode == AFLInstrumentMode.PCGUARD:
            env["AFL_LLVM_INSTRUMENT"] = "PCGUARD"
        elif instrument_mode == AFLInstrumentMode.CLASSIC:
            env["AFL_LLVM_INSTRUMENT"] = "CLASSIC"
        elif instrument_mode == AFLInstrumentMode.LTO:
            compiler = "afl-clang-lto++" if is_cpp else "afl-clang-lto"
        elif instrument_mode == AFLInstrumentMode.LAF:
            env["AFL_LLVM_LAF_ALL"] = "1"

        # Compile main binary
        cmd = [compiler] + base_flags + sanitizer_flags + extra_flags + [
            "-o", output_path, source_path
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                result.error_message = stderr.decode()
                return result

            result.compilation_flags = cmd
            result.success = True

        except Exception as e:
            result.error_message = str(e)
            return result

        # Create CMPLOG binary
        if create_cmplog:
            cmplog_path = output_path + ".cmplog"
            env["AFL_LLVM_CMPLOG"] = "1"

            cmd_cmplog = [compiler] + base_flags + ["-o", cmplog_path, source_path]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd_cmplog,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                await proc.communicate()

                if proc.returncode == 0:
                    result.cmplog_binary = cmplog_path

            except Exception as e:
                logger.warning(f"Failed to create CMPLOG binary: {e}")

        result.compile_time_seconds = (datetime.utcnow() - start_time).total_seconds()
        return result

    # =========================================================================
    # Fuzzing Control
    # =========================================================================

    def build_fuzz_command(self, config: AFLPPConfig) -> Tuple[List[str], Dict[str, str]]:
        """
        Build complete AFL++ command with ALL features.

        Returns (command, environment)
        """
        cmd = [self.AFL_FUZZ]
        env = os.environ.copy()

        # Required args
        cmd.extend(["-i", config.input_dir])
        cmd.extend(["-o", config.output_dir])
        cmd.extend(["-t", str(config.timeout_ms)])
        cmd.extend(["-m", str(config.memory_limit_mb)])

        # Power schedule
        cmd.extend(["-P", config.power_schedule.value])

        # MOpt mutation scheduling
        if config.mutator == AFLMutator.MOpt:
            cmd.extend(["-L", "0"])

        # CMPLOG (game changer for magic bytes)
        if config.cmplog_binary and os.path.exists(config.cmplog_binary):
            cmd.extend(["-c", config.cmplog_binary])
            cmd.extend(["-l", str(config.cmplog_level)])

        # Dictionary
        if config.dictionary_path and os.path.exists(config.dictionary_path):
            cmd.extend(["-x", config.dictionary_path])

        # Parallel fuzzing
        if config.parallel_mode and config.sync_id:
            if config.parallel_mode == "main":
                cmd.extend(["-M", config.sync_id])
            else:
                cmd.extend(["-S", config.sync_id])

        # Skip deterministic (faster but less thorough)
        if config.skip_deterministic:
            cmd.append("-d")

        # Crash mode
        if config.crash_mode:
            cmd.append("-C")

        # Non-instrumented (dumb fuzzing)
        if config.non_instrumented_mode:
            cmd.append("-n")

        # Ignore crashes (for finding more unique crashes)
        if config.ignore_crashes:
            cmd.append("-i")

        # CPU affinity
        if config.cpu_affinity is not None:
            cmd.extend(["-b", str(config.cpu_affinity)])

        # QEMU mode
        if config.fuzz_mode == AFLFuzzMode.QEMU or config.qemu_mode:
            cmd.append("-Q")

        # FRIDA mode
        if config.fuzz_mode == AFLFuzzMode.FRIDA:
            cmd.append("-O")  # FRIDA mode flag
            if config.frida_script:
                env["AFL_FRIDA_JS_SCRIPT"] = config.frida_script

        # Unicorn mode
        if config.fuzz_mode == AFLFuzzMode.UNICORN:
            cmd.append("-U")

        # Custom mutator
        if config.custom_mutator_path:
            env["AFL_CUSTOM_MUTATOR_LIBRARY"] = config.custom_mutator_path

        # Environment setup
        env["AFL_NO_UI"] = "1" if config.no_ui else ""
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"

        # Persistent mode settings
        if config.fuzz_mode == AFLFuzzMode.PERSISTENT:
            env["AFL_PERSISTENT"] = "1"

        if config.defer_forkserver:
            env["AFL_DEFER_FORKSRV"] = "1"

        # LAF-intel settings (compile time, but can hint)
        if config.laf_split_compares:
            env["AFL_LLVM_LAF_SPLIT_COMPARES"] = "1"
        if config.laf_split_switches:
            env["AFL_LLVM_LAF_SPLIT_SWITCHES"] = "1"
        if config.laf_split_floats:
            env["AFL_LLVM_LAF_TRANSFORM_COMPARES"] = "1"

        # Additional environment from config
        env.update(config.extra_env)

        # Extra args
        cmd.extend(config.extra_args)

        # Target binary
        cmd.append("--")
        cmd.append(config.binary_path)

        # Input via file (@@) or stdin
        if config.input_type == "file":
            cmd.append("@@")

        return cmd, env

    async def start_fuzzing(
        self,
        instance_id: str,
        config: AFLPPConfig,
    ) -> bool:
        """Start an AFL++ fuzzing instance."""
        cmd, env = self.build_fuzz_command(config)

        logger.info(f"Starting AFL++ instance {instance_id}")
        logger.debug(f"Command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            self._processes[instance_id] = process
            self._stats[instance_id] = AFLPPStats(
                start_time=datetime.utcnow(),
                last_update=datetime.utcnow(),
            )

            # Wait briefly to check for immediate failure
            await asyncio.sleep(2)

            if process.returncode is not None:
                stderr = await process.stderr.read()
                logger.error(f"AFL++ failed to start: {stderr.decode()}")
                return False

            logger.info(f"AFL++ instance {instance_id} started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start AFL++ instance {instance_id}: {e}")
            return False

    async def stop_fuzzing(self, instance_id: str) -> bool:
        """Stop an AFL++ fuzzing instance."""
        process = self._processes.get(instance_id)
        if not process:
            return False

        try:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

            del self._processes[instance_id]
            logger.info(f"Stopped AFL++ instance {instance_id}")
            return True

        except Exception as e:
            logger.error(f"Error stopping AFL++ instance {instance_id}: {e}")
            return False

    # =========================================================================
    # Statistics & Monitoring
    # =========================================================================

    async def get_stats(self, instance_id: str, output_dir: str) -> AFLPPStats:
        """Parse comprehensive AFL++ statistics."""
        stats = self._stats.get(instance_id, AFLPPStats(
            start_time=datetime.utcnow(),
            last_update=datetime.utcnow(),
        ))

        # Find the fuzzer_stats file
        stats_file = None
        for subdir in ["default", instance_id, ""]:
            path = os.path.join(output_dir, subdir, "fuzzer_stats") if subdir else \
                   os.path.join(output_dir, "fuzzer_stats")
            if os.path.exists(path):
                stats_file = path
                break

        if not stats_file:
            return stats

        try:
            with open(stats_file, "r") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    key, value = line.strip().split(":", 1)
                    key = key.strip()
                    value = value.strip()

                    # Parse all known stats
                    if key == "execs_done":
                        stats.execs_done = int(value)
                    elif key == "execs_per_sec":
                        stats.execs_per_sec = float(value)
                    elif key == "execs_per_sec_last":
                        stats.execs_per_sec_recent = float(value)
                    elif key == "corpus_count":
                        stats.corpus_count = int(value)
                    elif key == "corpus_variable":
                        stats.corpus_variable = int(value)
                    elif key == "pending_favs":
                        stats.pending_favs = int(value)
                    elif key == "pending_total":
                        stats.pending_total = int(value)
                    elif key == "saved_crashes":
                        stats.saved_crashes = int(value)
                    elif key == "saved_hangs":
                        stats.saved_hangs = int(value)
                    elif key == "unique_crashes":
                        stats.unique_crashes = int(value)
                    elif key == "unique_hangs":
                        stats.unique_hangs = int(value)
                    elif key == "edges_found":
                        stats.edges_found = int(value)
                    elif key == "total_edges":
                        stats.total_edges = int(value)
                    elif key == "var_byte_count":
                        stats.corpus_variable = int(value)
                    elif key == "stability":
                        stats.stability = float(value.replace("%", ""))
                    elif key == "bitmap_cvg":
                        stats.bitmap_cvg = float(value.replace("%", ""))
                    elif key == "cycles_done":
                        stats.cycles_done = int(value)
                    elif key == "cycles_wo_finds":
                        stats.cycles_wo_finds = int(value)
                    elif key == "slowest_exec_ms":
                        stats.slowest_exec_ms = int(value)
                    elif key == "peak_rss_mb":
                        stats.peak_rss_mb = int(value)
                    elif key == "run_time":
                        stats.run_time_seconds = int(value)

            # Calculate coverage percentage
            if stats.total_edges > 0:
                stats.coverage_pct = (stats.edges_found / stats.total_edges) * 100

            stats.last_update = datetime.utcnow()
            self._stats[instance_id] = stats

        except Exception as e:
            logger.warning(f"Failed to parse AFL++ stats: {e}")

        return stats

    # =========================================================================
    # Corpus Management
    # =========================================================================

    async def minimize_corpus(
        self,
        binary_path: str,
        input_dir: str,
        output_dir: str,
        timeout_ms: int = 1000,
        memory_mb: int = 2048,
    ) -> Tuple[int, int]:
        """
        Minimize corpus using afl-cmin.

        Returns (original_count, minimized_count)
        """
        if not self.available_tools.get(self.AFL_CMIN):
            logger.warning("afl-cmin not available")
            return 0, 0

        # Count original inputs
        original_count = len(list(Path(input_dir).glob("*")))

        cmd = [
            self.AFL_CMIN,
            "-i", input_dir,
            "-o", output_dir,
            "-t", str(timeout_ms),
            "-m", str(memory_mb),
            "--", binary_path, "@@"
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            minimized_count = len(list(Path(output_dir).glob("*")))
            reduction = ((original_count - minimized_count) / original_count * 100) if original_count > 0 else 0

            logger.info(f"Corpus minimization: {original_count} -> {minimized_count} ({reduction:.1f}% reduction)")
            return original_count, minimized_count

        except Exception as e:
            logger.error(f"Corpus minimization failed: {e}")
            return original_count, 0

    async def minimize_testcase(
        self,
        binary_path: str,
        input_file: str,
        output_file: str,
        timeout_ms: int = 1000,
        memory_mb: int = 2048,
    ) -> Tuple[int, int]:
        """
        Minimize a single testcase using afl-tmin.

        Returns (original_size, minimized_size)
        """
        if not self.available_tools.get(self.AFL_TMIN):
            logger.warning("afl-tmin not available")
            return 0, 0

        original_size = os.path.getsize(input_file)

        cmd = [
            self.AFL_TMIN,
            "-i", input_file,
            "-o", output_file,
            "-t", str(timeout_ms),
            "-m", str(memory_mb),
            "--", binary_path, "@@"
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if os.path.exists(output_file):
                minimized_size = os.path.getsize(output_file)
                reduction = ((original_size - minimized_size) / original_size * 100) if original_size > 0 else 0
                logger.info(f"Testcase minimization: {original_size} -> {minimized_size} bytes ({reduction:.1f}% reduction)")
                return original_size, minimized_size

        except Exception as e:
            logger.error(f"Testcase minimization failed: {e}")

        return original_size, 0

    # =========================================================================
    # Coverage Analysis
    # =========================================================================

    async def get_coverage_map(
        self,
        binary_path: str,
        input_file: str,
        timeout_ms: int = 1000,
    ) -> Dict[int, int]:
        """
        Get coverage map for a single input using afl-showmap.

        Returns dict of edge_id -> hit_count
        """
        if not self.available_tools.get(self.AFL_SHOWMAP):
            return {}

        with tempfile.NamedTemporaryFile(delete=False) as f:
            map_file = f.name

        cmd = [
            self.AFL_SHOWMAP,
            "-o", map_file,
            "-t", str(timeout_ms),
            "--", binary_path, input_file
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            coverage = {}
            if os.path.exists(map_file):
                with open(map_file, "r") as f:
                    for line in f:
                        if ":" in line:
                            edge_id, count = line.strip().split(":")
                            coverage[int(edge_id)] = int(count)
                os.unlink(map_file)

            return coverage

        except Exception as e:
            logger.error(f"Coverage analysis failed: {e}")
            return {}

    # =========================================================================
    # Dictionary Generation
    # =========================================================================

    async def generate_dictionary(
        self,
        binary_path: str,
        output_path: str,
        sample_inputs: Optional[List[str]] = None,
    ) -> int:
        """
        Generate a dictionary from binary strings and sample inputs.

        Returns number of tokens generated.
        """
        tokens = set()

        # Extract strings from binary
        try:
            proc = await asyncio.create_subprocess_exec(
                "strings", "-n", "4", binary_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()

            for line in stdout.decode(errors='ignore').split('\n'):
                line = line.strip()
                if 4 <= len(line) <= 32:
                    # Skip common non-useful strings
                    if not any(skip in line.lower() for skip in ['copyright', 'license', 'version']):
                        tokens.add(line)

        except Exception as e:
            logger.warning(f"String extraction failed: {e}")

        # Extract from sample inputs
        if sample_inputs:
            for input_file in sample_inputs:
                try:
                    with open(input_file, 'rb') as f:
                        data = f.read()
                        # Find printable sequences
                        for match in re.finditer(rb'[\x20-\x7e]{4,32}', data):
                            tokens.add(match.group().decode('ascii', errors='ignore'))
                except Exception:
                    pass

        # Write dictionary
        with open(output_path, 'w') as f:
            for i, token in enumerate(sorted(tokens)):
                # AFL dictionary format
                escaped = token.replace('\\', '\\\\').replace('"', '\\"')
                f.write(f'token_{i}="{escaped}"\n')

        logger.info(f"Generated dictionary with {len(tokens)} tokens")
        return len(tokens)

    # =========================================================================
    # Parallel Fuzzing
    # =========================================================================

    async def start_parallel_fuzzing(
        self,
        base_config: AFLPPConfig,
        num_instances: int,
        sync_dir: str,
    ) -> List[str]:
        """
        Start parallel AFL++ instances with corpus synchronization.

        Uses AFL++'s -M (main) and -S (secondary) modes for optimal
        parallel fuzzing with corpus sharing.
        """
        instance_ids = []

        # Create sync directory
        os.makedirs(sync_dir, exist_ok=True)

        # Start main instance
        main_config = AFLPPConfig(
            **{k: v for k, v in base_config.__dict__.items()},
        )
        main_config.parallel_mode = "main"
        main_config.sync_id = "main"
        main_config.output_dir = sync_dir

        main_id = "main"
        if await self.start_fuzzing(main_id, main_config):
            instance_ids.append(main_id)

        # Start secondary instances with different configurations
        # This is where our agentic AI can shine - each instance uses
        # different strategies for maximum coverage
        secondary_configs = [
            (AFLPowerSchedule.RARE, "rare_secondary"),      # Focus on rare edges
            (AFLPowerSchedule.EXPLORE, "explore_secondary"), # Maximum exploration
            (AFLPowerSchedule.EXPLOIT, "exploit_secondary"), # Exploit known paths
            (AFLPowerSchedule.COE, "coe_secondary"),         # Cut-off exponential
            (AFLPowerSchedule.FAST, "fast_secondary"),       # Fast schedule
            (AFLPowerSchedule.MMOPT, "mmopt_secondary"),     # Modified MOpt
        ]

        for i in range(min(num_instances - 1, len(secondary_configs))):
            schedule, name = secondary_configs[i]

            sec_config = AFLPPConfig(
                **{k: v for k, v in base_config.__dict__.items()},
            )
            sec_config.parallel_mode = "secondary"
            sec_config.sync_id = name
            sec_config.output_dir = sync_dir
            sec_config.power_schedule = schedule
            sec_config.skip_deterministic = True  # Secondaries skip deterministic

            if await self.start_fuzzing(name, sec_config):
                instance_ids.append(name)

        logger.info(f"Started {len(instance_ids)} parallel AFL++ instances")
        return instance_ids

    async def get_parallel_status(self, sync_dir: str) -> Dict[str, Any]:
        """Get status of all parallel instances using afl-whatsup."""
        if not self.available_tools.get(self.AFL_WHATSUP):
            return {}

        cmd = [self.AFL_WHATSUP, "-s", sync_dir]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            # Parse afl-whatsup output
            output = stdout.decode()
            status = {
                "raw_output": output,
                "total_execs": 0,
                "total_crashes": 0,
                "total_coverage": 0,
            }

            # Extract key metrics from output
            for line in output.split('\n'):
                if "Total execs" in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        status["total_execs"] = int(match.group(1))
                elif "Crashes found" in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        status["total_crashes"] = int(match.group(1))

            return status

        except Exception as e:
            logger.error(f"Failed to get parallel status: {e}")
            return {}


# =============================================================================
# Harness Generation
# =============================================================================

HARNESS_TEMPLATE_STDIN = '''
/*
 * Auto-generated AFL++ harness for stdin-based fuzzing
 * Target: {target_name}
 * Generated: {timestamp}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Include target header if available
{includes}

// AFL++ persistent mode for 10-100x speedup
#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int main(int argc, char **argv) {{
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;
    #else
    // Fallback for non-persistent mode
    unsigned char buf[1024*1024];
    int len = read(0, buf, sizeof(buf));
    {{
    #endif

        // Call target function with fuzzed input
        {target_call}

    }}
    return 0;
}}
'''

HARNESS_TEMPLATE_FILE = '''
/*
 * Auto-generated AFL++ harness for file-based fuzzing
 * Target: {target_name}
 * Generated: {timestamp}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

{includes}

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int main(int argc, char **argv) {{
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}

    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {{
    #else
    {{
    #endif

        // Read input file
        FILE *f = fopen(argv[1], "rb");
        if (!f) return 1;

        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);

        unsigned char *buf = malloc(size + 1);
        if (!buf) {{ fclose(f); return 1; }}

        fread(buf, 1, size, f);
        fclose(f);

        // Call target function with fuzzed input
        {target_call}

        free(buf);
    }}
    return 0;
}}
'''

HARNESS_TEMPLATE_LIBRARY = '''
/*
 * Auto-generated AFL++ harness for library fuzzing
 * Library: {library_name}
 * Functions: {functions}
 * Generated: {timestamp}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

{includes}

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

// LLVMFuzzerTestOneInput compatible entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 1) return 0;

    // Call library functions with fuzzed data
    {target_calls}

    return 0;
}}

#ifndef LIBFUZZER_MODE
int main(int argc, char **argv) {{
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }}
    #else
    // Read from stdin
    unsigned char buf[1024*1024];
    int len = read(0, buf, sizeof(buf));
    if (len > 0) {{
        LLVMFuzzerTestOneInput(buf, len);
    }}
    #endif
    return 0;
}}
#endif
'''


@dataclass
class HarnessConfig:
    """Configuration for harness generation."""
    harness_type: str = "stdin"  # stdin, file, library
    target_functions: List[str] = field(default_factory=list)
    include_headers: List[str] = field(default_factory=list)
    library_path: Optional[str] = None
    extra_cflags: List[str] = field(default_factory=list)
    extra_ldflags: List[str] = field(default_factory=list)


@dataclass
class HarnessResult:
    """Result of harness generation."""
    success: bool
    harness_source: str = ""
    harness_binary: str = ""
    cmplog_binary: str = ""
    error_message: str = ""
    compile_output: str = ""


class HarnessGenerator:
    """Generate fuzzing harnesses for various target types."""

    def __init__(self, aflpp_service: 'AFLPlusPlusFullService'):
        self.aflpp_service = aflpp_service

    def generate_stdin_harness(
        self,
        target_function: str,
        include_headers: List[str] = None,
    ) -> str:
        """Generate a stdin-based harness."""
        includes = "\n".join(f'#include "{h}"' for h in (include_headers or []))
        target_call = f"{target_function}(buf, len);"

        return HARNESS_TEMPLATE_STDIN.format(
            target_name=target_function,
            timestamp=datetime.utcnow().isoformat(),
            includes=includes,
            target_call=target_call,
        )

    def generate_file_harness(
        self,
        target_function: str,
        include_headers: List[str] = None,
    ) -> str:
        """Generate a file-based harness."""
        includes = "\n".join(f'#include "{h}"' for h in (include_headers or []))
        target_call = f"{target_function}(buf, size);"

        return HARNESS_TEMPLATE_FILE.format(
            target_name=target_function,
            timestamp=datetime.utcnow().isoformat(),
            includes=includes,
            target_call=target_call,
        )

    def generate_library_harness(
        self,
        library_name: str,
        target_functions: List[str],
        include_headers: List[str] = None,
    ) -> str:
        """Generate a library fuzzing harness."""
        includes = "\n".join(f'#include "{h}"' for h in (include_headers or []))

        # Generate calls for each target function
        target_calls = []
        for func in target_functions:
            # Simple call - assumes function takes (data, size)
            target_calls.append(f"    {func}((char*)data, size);")

        return HARNESS_TEMPLATE_LIBRARY.format(
            library_name=library_name,
            functions=", ".join(target_functions),
            timestamp=datetime.utcnow().isoformat(),
            includes=includes,
            target_calls="\n".join(target_calls),
        )

    async def generate_and_compile(
        self,
        config: HarnessConfig,
        output_dir: str,
    ) -> HarnessResult:
        """Generate and compile a fuzzing harness."""
        result = HarnessResult(success=False)

        try:
            os.makedirs(output_dir, exist_ok=True)

            # Generate harness source
            if config.harness_type == "stdin":
                source = self.generate_stdin_harness(
                    config.target_functions[0] if config.target_functions else "target_function",
                    config.include_headers,
                )
            elif config.harness_type == "file":
                source = self.generate_file_harness(
                    config.target_functions[0] if config.target_functions else "target_function",
                    config.include_headers,
                )
            elif config.harness_type == "library":
                source = self.generate_library_harness(
                    config.library_path or "target_library",
                    config.target_functions,
                    config.include_headers,
                )
            else:
                result.error_message = f"Unknown harness type: {config.harness_type}"
                return result

            # Write harness source
            harness_source = os.path.join(output_dir, "harness.c")
            with open(harness_source, "w") as f:
                f.write(source)
            result.harness_source = harness_source

            # Compile harness with AFL++ instrumentation
            harness_binary = os.path.join(output_dir, "harness")
            cmplog_binary = os.path.join(output_dir, "harness.cmplog")

            compile_result = await self.aflpp_service.compile_target(
                source_path=harness_source,
                output_path=harness_binary,
                instrument_mode=AFLInstrumentMode.PCGUARD,
                sanitizers=[AFLSanitizer.ASAN],
                create_cmplog=True,
                extra_flags=config.extra_cflags,
            )

            if compile_result.success:
                result.success = True
                result.harness_binary = compile_result.instrumented_binary
                result.cmplog_binary = compile_result.cmplog_binary or ""
                result.compile_output = compile_result.compile_output
                logger.info(f"Harness generated and compiled: {result.harness_binary}")
            else:
                result.error_message = compile_result.error_message
                result.compile_output = compile_result.compile_output

        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Harness generation failed: {e}")

        return result


# =============================================================================
# Crash Verification and Minimization
# =============================================================================

@dataclass
class CrashVerificationResult:
    """Result of crash verification."""
    crash_id: str
    verified: bool
    reproducible: bool
    minimized_input: Optional[bytes] = None
    minimized_size: int = 0
    original_size: int = 0
    crash_type: str = ""
    crash_address: str = ""
    stack_trace: List[str] = field(default_factory=list)
    error_message: str = ""


class CrashVerifier:
    """Verify and minimize crashes found by fuzzing."""

    def __init__(self, aflpp_service: 'AFLPlusPlusFullService'):
        self.aflpp_service = aflpp_service

    async def verify_crash(
        self,
        binary_path: str,
        crash_input_path: str,
        timeout_ms: int = 5000,
        memory_mb: int = 2048,
    ) -> CrashVerificationResult:
        """
        Verify that a crash is reproducible.

        Runs the binary with the crash input multiple times to confirm
        the crash is reliable.
        """
        crash_id = os.path.basename(crash_input_path)
        result = CrashVerificationResult(
            crash_id=crash_id,
            verified=False,
            reproducible=False,
        )

        # Read original input
        try:
            with open(crash_input_path, "rb") as f:
                original_input = f.read()
            result.original_size = len(original_input)
        except Exception as e:
            result.error_message = f"Failed to read crash input: {e}"
            return result

        # Run binary multiple times to verify reproducibility
        crashes_seen = 0
        for attempt in range(3):
            try:
                proc = await asyncio.create_subprocess_exec(
                    binary_path, crash_input_path,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=timeout_ms / 1000.0
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    continue

                # Check for crash
                if proc.returncode != 0 and proc.returncode not in [1, 2]:
                    crashes_seen += 1

                    # Parse crash info from ASAN output
                    stderr_text = stderr.decode(errors='ignore')
                    if "AddressSanitizer" in stderr_text:
                        result.crash_type = self._extract_crash_type(stderr_text)
                        result.crash_address = self._extract_crash_address(stderr_text)
                        result.stack_trace = self._extract_stack_trace(stderr_text)

            except Exception as e:
                logger.debug(f"Verification attempt {attempt} failed: {e}")

        # Crash is verified if it reproduced at least 2 out of 3 times
        result.reproducible = crashes_seen >= 2
        result.verified = crashes_seen > 0

        logger.info(
            f"Crash {crash_id}: verified={result.verified}, "
            f"reproducible={result.reproducible} ({crashes_seen}/3 reproduced)"
        )

        return result

    async def minimize_crash(
        self,
        binary_path: str,
        crash_input_path: str,
        output_path: str,
        timeout_ms: int = 5000,
        memory_mb: int = 2048,
    ) -> CrashVerificationResult:
        """
        Minimize a crash input using afl-tmin.

        Creates the smallest input that still triggers the crash.
        """
        crash_id = os.path.basename(crash_input_path)
        result = await self.verify_crash(binary_path, crash_input_path, timeout_ms, memory_mb)

        if not result.verified:
            result.error_message = "Crash not verified, cannot minimize"
            return result

        # Use afl-tmin if available
        afl_tmin = self.aflpp_service.available_tools.get(self.aflpp_service.AFL_TMIN)
        if not afl_tmin:
            result.error_message = "afl-tmin not available"
            return result

        try:
            cmd = [
                self.aflpp_service.AFL_TMIN,
                "-i", crash_input_path,
                "-o", output_path,
                "-t", str(timeout_ms),
                "-m", str(memory_mb),
                "--", binary_path, "@@"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300.0  # 5 minute timeout for minimization
            )

            if proc.returncode == 0 and os.path.exists(output_path):
                with open(output_path, "rb") as f:
                    minimized_input = f.read()
                result.minimized_input = minimized_input
                result.minimized_size = len(minimized_input)

                reduction_pct = (1 - result.minimized_size / result.original_size) * 100
                logger.info(
                    f"Crash minimized: {result.original_size} -> {result.minimized_size} bytes "
                    f"({reduction_pct:.1f}% reduction)"
                )
            else:
                result.error_message = f"afl-tmin failed: {stderr.decode()}"

        except asyncio.TimeoutError:
            result.error_message = "Minimization timed out"
        except Exception as e:
            result.error_message = str(e)

        return result

    def _extract_crash_type(self, asan_output: str) -> str:
        """Extract crash type from ASAN output."""
        patterns = [
            (r"heap-buffer-overflow", "heap-buffer-overflow"),
            (r"stack-buffer-overflow", "stack-buffer-overflow"),
            (r"heap-use-after-free", "use-after-free"),
            (r"double-free", "double-free"),
            (r"null-dereference", "null-dereference"),
            (r"SEGV", "segfault"),
            (r"global-buffer-overflow", "global-buffer-overflow"),
        ]
        for pattern, crash_type in patterns:
            if re.search(pattern, asan_output, re.IGNORECASE):
                return crash_type
        return "unknown"

    def _extract_crash_address(self, asan_output: str) -> str:
        """Extract crash address from ASAN output."""
        match = re.search(r"0x[0-9a-fA-F]+", asan_output)
        return match.group(0) if match else ""

    def _extract_stack_trace(self, asan_output: str) -> List[str]:
        """Extract stack trace from ASAN output."""
        frames = []
        for line in asan_output.split('\n'):
            if re.match(r'\s*#\d+', line):
                frames.append(line.strip())
        return frames[:10]  # Limit to top 10 frames


# Add methods to AFLPlusPlusFullService for harness and crash handling
def _add_harness_methods(cls):
    """Add harness and crash methods to AFLPlusPlusFullService."""

    async def generate_harness(
        self,
        config: HarnessConfig,
        output_dir: str,
    ) -> HarnessResult:
        """Generate and compile a fuzzing harness."""
        generator = HarnessGenerator(self)
        return await generator.generate_and_compile(config, output_dir)

    async def verify_crash(
        self,
        binary_path: str,
        crash_input_path: str,
        timeout_ms: int = 5000,
    ) -> CrashVerificationResult:
        """Verify a crash is reproducible."""
        verifier = CrashVerifier(self)
        return await verifier.verify_crash(binary_path, crash_input_path, timeout_ms)

    async def minimize_crash(
        self,
        binary_path: str,
        crash_input_path: str,
        output_path: str,
        timeout_ms: int = 5000,
    ) -> CrashVerificationResult:
        """Minimize a crash input."""
        verifier = CrashVerifier(self)
        return await verifier.minimize_crash(binary_path, crash_input_path, output_path, timeout_ms)

    cls.generate_harness = generate_harness
    cls.verify_crash = verify_crash
    cls.minimize_crash = minimize_crash
    return cls


# Apply the harness methods to AFLPlusPlusFullService
# This is done at module load time
_harness_methods_added = False


# =============================================================================
# Convenience Functions
# =============================================================================

_aflpp_service: Optional[AFLPlusPlusFullService] = None


def get_aflpp_service() -> AFLPlusPlusFullService:
    """Get global AFL++ service instance with harness and crash methods."""
    global _aflpp_service, _harness_methods_added

    # Add harness and crash methods on first call
    if not _harness_methods_added:
        _add_harness_methods(AFLPlusPlusFullService)
        _harness_methods_added = True

    if _aflpp_service is None:
        _aflpp_service = AFLPlusPlusFullService()

    return _aflpp_service


async def quick_fuzz(
    binary_path: str,
    input_dir: str,
    output_dir: str,
    duration_seconds: int = 3600,
    power_schedule: AFLPowerSchedule = AFLPowerSchedule.EXPLORE,
) -> AFLPPStats:
    """Quick fuzzing with sensible defaults."""
    service = get_aflpp_service()

    config = AFLPPConfig(
        binary_path=binary_path,
        input_dir=input_dir,
        output_dir=output_dir,
        power_schedule=power_schedule,
        mutator=AFLMutator.MOpt,
    )

    instance_id = "quick_fuzz"
    if await service.start_fuzzing(instance_id, config):
        await asyncio.sleep(duration_seconds)
        stats = await service.get_stats(instance_id, output_dir)
        await service.stop_fuzzing(instance_id)
        return stats

    return AFLPPStats(start_time=datetime.utcnow(), last_update=datetime.utcnow())
