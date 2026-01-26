"""
LAF-Intel Integration Service for AFL++ Enhanced Fuzzing.

LAF-Intel (LLVM-based Automatic Fuzzing Intel) provides compile-time
instrumentation that splits complex comparisons into simpler ones,
making it easier for fuzzers to solve them incrementally.

Key transformations:
- Split multi-byte comparisons (strcmp, memcmp) into byte-by-byte checks
- Transform switch statements into if-else chains
- Split integer comparisons into bit-level checks
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import asyncio
import os
import shutil
import tempfile
import logging

logger = logging.getLogger(__name__)


class LafIntelMode(str, Enum):
    """LAF-Intel instrumentation modes."""
    SPLIT_SWITCHES = "split_switches"
    TRANSFORM_COMPARES = "transform_compares"
    SPLIT_COMPARES = "split_compares"
    SPLIT_FLOATS = "split_floats"
    ALL = "all"


@dataclass
class LafIntelConfig:
    """Configuration for LAF-Intel instrumentation."""
    modes: List[LafIntelMode] = field(default_factory=lambda: [LafIntelMode.ALL])
    # Compilation settings
    llvm_path: Optional[str] = None
    afl_clang_path: Optional[str] = None
    # Options
    split_compares_bitw: int = 8  # AFL_LLVM_LAF_SPLIT_COMPARES_BITW
    all_switches: bool = True  # AFL_LLVM_LAF_ALL_SWITCHES
    transform_compares: bool = True
    # Target
    source_dir: Optional[str] = None
    build_dir: Optional[str] = None
    output_binary: Optional[str] = None
    # Additional compiler flags
    extra_cflags: List[str] = field(default_factory=list)
    extra_ldflags: List[str] = field(default_factory=list)


@dataclass
class LafIntelEnvVars:
    """
    Environment variables for AFL++ with LAF-Intel instrumentation.

    These variables control the LAF-Intel passes during compilation
    with afl-clang-fast or afl-clang-lto.
    """
    AFL_LLVM_LAF_SPLIT_SWITCHES: str = "1"
    AFL_LLVM_LAF_TRANSFORM_COMPARES: str = "1"
    AFL_LLVM_LAF_SPLIT_COMPARES: str = "1"
    AFL_LLVM_LAF_SPLIT_COMPARES_BITW: str = "8"
    AFL_LLVM_LAF_SPLIT_FLOATS: str = "1"
    AFL_LLVM_LAF_ALL: str = "1"

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for subprocess environment."""
        return {
            k: v for k, v in vars(self).items()
            if not k.startswith('_') and isinstance(v, str)
        }

    @classmethod
    def from_modes(cls, modes: List[LafIntelMode], bitw: int = 8) -> "LafIntelEnvVars":
        """Create env vars from specific modes."""
        env = cls(
            AFL_LLVM_LAF_SPLIT_SWITCHES="0",
            AFL_LLVM_LAF_TRANSFORM_COMPARES="0",
            AFL_LLVM_LAF_SPLIT_COMPARES="0",
            AFL_LLVM_LAF_SPLIT_FLOATS="0",
            AFL_LLVM_LAF_ALL="0",
            AFL_LLVM_LAF_SPLIT_COMPARES_BITW=str(bitw),
        )

        for mode in modes:
            if mode == LafIntelMode.ALL:
                env.AFL_LLVM_LAF_ALL = "1"
                env.AFL_LLVM_LAF_SPLIT_SWITCHES = "1"
                env.AFL_LLVM_LAF_TRANSFORM_COMPARES = "1"
                env.AFL_LLVM_LAF_SPLIT_COMPARES = "1"
                env.AFL_LLVM_LAF_SPLIT_FLOATS = "1"
            elif mode == LafIntelMode.SPLIT_SWITCHES:
                env.AFL_LLVM_LAF_SPLIT_SWITCHES = "1"
            elif mode == LafIntelMode.TRANSFORM_COMPARES:
                env.AFL_LLVM_LAF_TRANSFORM_COMPARES = "1"
            elif mode == LafIntelMode.SPLIT_COMPARES:
                env.AFL_LLVM_LAF_SPLIT_COMPARES = "1"
            elif mode == LafIntelMode.SPLIT_FLOATS:
                env.AFL_LLVM_LAF_SPLIT_FLOATS = "1"

        return env


@dataclass
class LafIntelBuildResult:
    """Result of LAF-Intel compilation."""
    success: bool
    output_path: Optional[str] = None
    original_compares: int = 0
    split_compares: int = 0
    transformed_switches: int = 0
    build_time_seconds: float = 0.0
    compile_command: str = ""
    stdout: str = ""
    stderr: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "output_path": self.output_path,
            "original_compares": self.original_compares,
            "split_compares": self.split_compares,
            "transformed_switches": self.transformed_switches,
            "build_time_seconds": self.build_time_seconds,
            "compile_command": self.compile_command,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class LafIntelAvailability:
    """LAF-Intel availability information."""
    available: bool
    afl_clang_fast_path: Optional[str] = None
    afl_clang_lto_path: Optional[str] = None
    afl_gcc_path: Optional[str] = None
    llvm_version: Optional[str] = None
    supported_modes: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "available": self.available,
            "afl_clang_fast_path": self.afl_clang_fast_path,
            "afl_clang_lto_path": self.afl_clang_lto_path,
            "afl_gcc_path": self.afl_gcc_path,
            "llvm_version": self.llvm_version,
            "supported_modes": self.supported_modes,
            "recommendations": self.recommendations,
            "errors": self.errors,
        }


def _find_afl_compiler(name: str) -> Optional[str]:
    """Find AFL++ compiler wrapper in common locations."""
    # Common installation paths
    search_paths = [
        "/usr/local/bin",
        "/usr/bin",
        "/opt/AFLplusplus",
        "/opt/afl",
        os.path.expanduser("~/AFLplusplus"),
        os.path.expanduser("~/.local/bin"),
    ]

    # Add AFL_PATH environment variable if set
    afl_path = os.environ.get("AFL_PATH")
    if afl_path:
        search_paths.insert(0, afl_path)

    # Windows-specific paths
    if os.name == "nt":
        search_paths.extend([
            r"C:\AFLplusplus",
            r"C:\tools\AFLplusplus",
            os.path.expanduser(r"~\AFLplusplus"),
        ])

    # Try each path
    for base_path in search_paths:
        full_path = os.path.join(base_path, name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path
        # Windows: try with .exe extension
        if os.name == "nt":
            exe_path = full_path + ".exe"
            if os.path.isfile(exe_path):
                return exe_path

    # Fall back to PATH search
    return shutil.which(name)


async def _run_command(
    cmd: List[str],
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    timeout: float = 300.0,
) -> Tuple[int, str, str]:
    """Run a command asynchronously and return exit code, stdout, stderr."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=full_env,
            cwd=cwd,
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )

        return (
            proc.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        if proc:
            proc.kill()
            await proc.wait()
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


async def _get_llvm_version(clang_path: str) -> Optional[str]:
    """Get LLVM version from clang."""
    try:
        code, stdout, _ = await _run_command([clang_path, "--version"], timeout=10.0)
        if code == 0 and stdout:
            # Parse version from output like "clang version 15.0.0"
            for line in stdout.split("\n"):
                if "version" in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.lower() == "version" and i + 1 < len(parts):
                            return parts[i + 1]
        return None
    except Exception:
        return None


def _parse_laf_stats_from_output(stderr: str) -> Dict[str, int]:
    """Parse LAF-Intel instrumentation stats from compiler output."""
    stats = {
        "original_compares": 0,
        "split_compares": 0,
        "transformed_switches": 0,
    }

    # AFL++ LAF-Intel outputs stats like:
    # "[+] Instrumented X locations with LAF-intel"
    # "Splitting X comparisons"
    for line in stderr.split("\n"):
        line_lower = line.lower()
        if "splitting" in line_lower and "comparison" in line_lower:
            try:
                # Extract number
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.isdigit():
                        stats["split_compares"] = int(part)
                        break
            except (ValueError, IndexError):
                pass
        elif "switch" in line_lower and ("transform" in line_lower or "split" in line_lower):
            try:
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        stats["transformed_switches"] = int(part)
                        break
            except (ValueError, IndexError):
                pass

    return stats


class LafIntelService:
    """
    LAF-Intel integration service for compile-time comparison splitting.

    Provides:
    1. Environment variable configuration for AFL++ LAF mode
    2. Build helpers for instrumenting targets with LAF
    3. Integration with preflight checks
    4. Runtime detection and recommendations

    Example usage:
        service = LafIntelService()

        # Check availability
        avail = service.check_laf_availability()
        if avail.available:
            # Get env vars for fuzzing
            env = service.get_env_vars([LafIntelMode.ALL])
            # Use env when starting AFL++

            # Or build an instrumented binary
            result = await service.build_laf_target(
                source_path="target.c",
                output_path="target_laf",
            )
    """

    def __init__(self, config: Optional[LafIntelConfig] = None):
        self.config = config or LafIntelConfig()
        self.stats: Dict[str, Any] = {
            "builds_attempted": 0,
            "builds_succeeded": 0,
            "total_compares_split": 0,
            "total_switches_transformed": 0,
        }
        self._availability_cache: Optional[LafIntelAvailability] = None

    def get_env_vars(
        self,
        modes: Optional[List[LafIntelMode]] = None,
        bitw: int = 8,
    ) -> Dict[str, str]:
        """
        Get environment variables for LAF-Intel enabled fuzzing.

        These should be set when compiling with afl-clang-fast or afl-clang-lto.

        Args:
            modes: Specific LAF modes to enable (default: all from config)
            bitw: Bit width for comparison splitting (default: 8)

        Returns:
            Dictionary of environment variables

        Example:
            env = service.get_env_vars([LafIntelMode.SPLIT_COMPARES])
            # env = {"AFL_LLVM_LAF_SPLIT_COMPARES": "1", ...}
        """
        if modes is None:
            modes = self.config.modes

        env_obj = LafIntelEnvVars.from_modes(modes, bitw)
        return env_obj.to_dict()

    def get_runtime_env_vars(self) -> Dict[str, str]:
        """
        Get environment variables for runtime (fuzzing phase).

        LAF-Intel is primarily a compile-time feature, but some
        runtime options can enhance its effectiveness.

        Returns:
            Dictionary of runtime environment variables
        """
        return {
            # Enable comparison logging for better crash reproduction
            "AFL_CMPLOG_ONLY_NEW": "1",
            # Don't skip deterministic stages (helps with LAF)
            "AFL_SKIP_CPUFREQ": "1",
        }

    def check_laf_availability(self) -> LafIntelAvailability:
        """
        Check if LAF-Intel is available in the AFL++ installation.

        Returns:
            LafIntelAvailability with paths, versions, and recommendations
        """
        if self._availability_cache is not None:
            return self._availability_cache

        result = LafIntelAvailability(
            available=False,
            supported_modes=[],
            recommendations=[],
            errors=[],
        )

        # Find AFL++ compilers
        result.afl_clang_fast_path = (
            self.config.afl_clang_path or _find_afl_compiler("afl-clang-fast")
        )
        result.afl_clang_lto_path = _find_afl_compiler("afl-clang-lto")
        result.afl_gcc_path = _find_afl_compiler("afl-gcc")

        # Check if any compiler is available
        if result.afl_clang_fast_path:
            result.available = True
            result.supported_modes = [
                LafIntelMode.SPLIT_SWITCHES.value,
                LafIntelMode.TRANSFORM_COMPARES.value,
                LafIntelMode.SPLIT_COMPARES.value,
                LafIntelMode.SPLIT_FLOATS.value,
                LafIntelMode.ALL.value,
            ]
        elif result.afl_clang_lto_path:
            result.available = True
            result.supported_modes = [
                LafIntelMode.SPLIT_SWITCHES.value,
                LafIntelMode.TRANSFORM_COMPARES.value,
                LafIntelMode.SPLIT_COMPARES.value,
                LafIntelMode.ALL.value,
            ]
            result.recommendations.append(
                "Using afl-clang-lto provides better instrumentation than afl-clang-fast"
            )
        elif result.afl_gcc_path:
            result.available = True
            result.supported_modes = [
                LafIntelMode.SPLIT_SWITCHES.value,
            ]
            result.recommendations.append(
                "afl-gcc has limited LAF-Intel support. Install LLVM and use afl-clang-fast for full LAF-Intel"
            )
        else:
            result.errors.append(
                "No AFL++ compiler found. Install AFL++ with LLVM support for LAF-Intel"
            )
            result.recommendations.append(
                "Install AFL++ from https://github.com/AFLplusplus/AFLplusplus"
            )

        # Add mode recommendations
        if result.available:
            result.recommendations.append(
                "For maximum coverage, use LafIntelMode.ALL which enables all transformations"
            )
            result.recommendations.append(
                "Consider using CMPLOG alongside LAF-Intel for even better results"
            )

        self._availability_cache = result
        return result

    async def build_laf_target(
        self,
        source_path: str,
        output_path: str,
        compile_command: Optional[str] = None,
        extra_flags: Optional[List[str]] = None,
        modes: Optional[List[LafIntelMode]] = None,
        timeout_seconds: float = 300.0,
    ) -> LafIntelBuildResult:
        """
        Build target with LAF-Intel instrumentation.

        Args:
            source_path: Path to source file(s) or directory
            output_path: Output binary path
            compile_command: Custom compile command (uses afl-clang-fast by default)
            extra_flags: Additional compiler flags
            modes: LAF modes to enable (default: from config)
            timeout_seconds: Build timeout

        Returns:
            LafIntelBuildResult with compilation details

        Example:
            result = await service.build_laf_target(
                source_path="vuln.c",
                output_path="vuln_laf",
                extra_flags=["-g", "-O2"],
            )
            if result.success:
                print(f"Built: {result.output_path}")
                print(f"Split {result.split_compares} comparisons")
        """
        import time
        start_time = time.time()

        self.stats["builds_attempted"] += 1

        result = LafIntelBuildResult(
            success=False,
            output_path=output_path,
        )

        # Check availability
        avail = self.check_laf_availability()
        if not avail.available:
            result.errors = avail.errors
            return result

        # Validate source exists
        if not os.path.exists(source_path):
            result.errors.append(f"Source not found: {source_path}")
            return result

        # Determine compiler to use
        compiler = compile_command
        if not compiler:
            if avail.afl_clang_lto_path:
                compiler = avail.afl_clang_lto_path
            elif avail.afl_clang_fast_path:
                compiler = avail.afl_clang_fast_path
            elif avail.afl_gcc_path:
                compiler = avail.afl_gcc_path
            else:
                result.errors.append("No suitable AFL++ compiler found")
                return result

        # Build command
        cmd = [compiler]

        # Add LAF-Intel flags (through environment, not command line)
        env = self.get_env_vars(modes or self.config.modes)

        # Add extra flags
        if extra_flags:
            cmd.extend(extra_flags)
        if self.config.extra_cflags:
            cmd.extend(self.config.extra_cflags)

        # Add source and output
        cmd.extend(["-o", output_path, source_path])

        # Add linker flags
        if self.config.extra_ldflags:
            cmd.extend(self.config.extra_ldflags)

        result.compile_command = " ".join(cmd)

        logger.info(f"Building LAF-Intel target: {result.compile_command}")
        logger.debug(f"LAF-Intel env vars: {env}")

        # Run compilation
        exit_code, stdout, stderr = await _run_command(
            cmd,
            env=env,
            timeout=timeout_seconds,
        )

        result.stdout = stdout
        result.stderr = stderr
        result.build_time_seconds = time.time() - start_time

        if exit_code == 0 and os.path.isfile(output_path):
            result.success = True

            # Parse instrumentation stats from output
            stats = _parse_laf_stats_from_output(stderr)
            result.split_compares = stats["split_compares"]
            result.transformed_switches = stats["transformed_switches"]

            # Update global stats
            self.stats["builds_succeeded"] += 1
            self.stats["total_compares_split"] += result.split_compares
            self.stats["total_switches_transformed"] += result.transformed_switches

            logger.info(
                f"LAF-Intel build succeeded: {result.split_compares} compares split, "
                f"{result.transformed_switches} switches transformed"
            )
        else:
            result.errors.append(f"Compilation failed with exit code {exit_code}")
            if stderr:
                # Extract error lines
                for line in stderr.split("\n"):
                    if "error:" in line.lower():
                        result.errors.append(line.strip())

            logger.error(f"LAF-Intel build failed: {result.errors}")

        # Extract warnings
        if stderr:
            for line in stderr.split("\n"):
                if "warning:" in line.lower():
                    result.warnings.append(line.strip())

        return result

    def get_recommended_config(
        self,
        target_info: Dict[str, Any],
    ) -> LafIntelConfig:
        """
        Get recommended LAF-Intel configuration for target.

        Analyzes target binary information to recommend optimal LAF settings.

        Args:
            target_info: Binary analysis info (from analyze_binary or similar)

        Returns:
            Recommended LafIntelConfig
        """
        config = LafIntelConfig()

        # Default: enable all modes
        config.modes = [LafIntelMode.ALL]

        # Check if target uses strcmp/memcmp heavily
        functions = target_info.get("functions", [])
        string_funcs = ["strcmp", "strncmp", "memcmp", "strcasecmp"]
        has_string_compares = any(
            f in str(functions).lower() for f in string_funcs
        )

        if has_string_compares:
            # Ensure TRANSFORM_COMPARES is enabled
            if LafIntelMode.ALL not in config.modes:
                config.modes.append(LafIntelMode.TRANSFORM_COMPARES)

        # Check for switch statements (from binary analysis if available)
        has_switches = target_info.get("has_switch_statements", True)
        if has_switches and LafIntelMode.ALL not in config.modes:
            config.modes.append(LafIntelMode.SPLIT_SWITCHES)

        # Adjust bit width based on architecture
        arch = target_info.get("architecture", "x64")
        if arch in ["x86", "arm32"]:
            config.split_compares_bitw = 4  # Smaller for 32-bit
        else:
            config.split_compares_bitw = 8  # Default for 64-bit

        return config

    def integrate_with_preflight(
        self,
        preflight_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Add LAF-Intel recommendations to preflight check results.

        Call this from the AFL++ preflight check to add LAF-Intel
        availability and recommendations.

        Args:
            preflight_result: Existing preflight result dict

        Returns:
            Enhanced preflight result with LAF recommendations
        """
        avail = self.check_laf_availability()

        # Add LAF-Intel section
        preflight_result["laf_intel"] = {
            "available": avail.available,
            "compiler_path": avail.afl_clang_fast_path or avail.afl_clang_lto_path,
            "supported_modes": avail.supported_modes,
        }

        # Add recommendations
        if avail.available:
            if "recommendations" not in preflight_result:
                preflight_result["recommendations"] = []

            preflight_result["recommendations"].append({
                "category": "laf_intel",
                "priority": "medium",
                "message": "LAF-Intel is available and recommended for better coverage",
                "action": "Enable LAF-Intel modes during compilation",
            })

            # If target isn't LAF-instrumented, suggest rebuilding
            target_laf_instrumented = preflight_result.get("laf_instrumented", False)
            if not target_laf_instrumented:
                preflight_result["recommendations"].append({
                    "category": "laf_intel",
                    "priority": "high",
                    "message": "Target is not LAF-Intel instrumented",
                    "action": "Rebuild target with LAF-Intel for improved fuzzing",
                })
        else:
            if "warnings" not in preflight_result:
                preflight_result["warnings"] = []

            preflight_result["warnings"].append({
                "category": "laf_intel",
                "message": "LAF-Intel not available",
                "details": avail.errors,
            })

        return preflight_result

    def get_status(self) -> Dict[str, Any]:
        """Get service status and statistics."""
        avail = self.check_laf_availability()
        return {
            "available": avail.available,
            "compiler_path": avail.afl_clang_fast_path or avail.afl_clang_lto_path,
            "supported_modes": avail.supported_modes,
            "stats": self.stats.copy(),
        }


# Convenience functions for direct use

def get_laf_intel_env_vars(
    modes: Optional[List[LafIntelMode]] = None,
) -> Dict[str, str]:
    """
    Get LAF-Intel environment variables.

    Convenience function for quick access to env vars.

    Args:
        modes: LAF modes to enable (default: ALL)

    Returns:
        Dictionary of environment variables
    """
    service = LafIntelService()
    return service.get_env_vars(modes)


def check_laf_intel_available() -> bool:
    """
    Quick check if LAF-Intel is available.

    Returns:
        True if any LAF-Intel compiler is available
    """
    service = LafIntelService()
    return service.check_laf_availability().available


async def build_with_laf_intel(
    source_path: str,
    output_path: str,
    modes: Optional[List[LafIntelMode]] = None,
) -> LafIntelBuildResult:
    """
    Build a target with LAF-Intel instrumentation.

    Convenience function for quick builds.

    Args:
        source_path: Path to source file
        output_path: Output binary path
        modes: LAF modes to enable

    Returns:
        LafIntelBuildResult
    """
    service = LafIntelService()
    return await service.build_laf_target(
        source_path=source_path,
        output_path=output_path,
        modes=modes,
    )


def detect_laf_instrumented(binary_path: str) -> bool:
    """
    Detect if binary was compiled with LAF-Intel instrumentation.

    Checks for LAF-Intel markers in the binary.

    Args:
        binary_path: Path to binary file

    Returns:
        True if LAF-Intel instrumented
    """
    if not os.path.isfile(binary_path):
        return False

    try:
        with open(binary_path, "rb") as f:
            # Read first 1MB
            data = f.read(1024 * 1024)

            # Look for LAF-Intel markers
            # AFL++ LAF leaves distinctive patterns
            markers = [
                b"__afl_laf",
                b"__laf_cmp",
                b"afl_maybe_log",
            ]

            for marker in markers:
                if marker in data:
                    return True

            return False
    except Exception:
        return False
