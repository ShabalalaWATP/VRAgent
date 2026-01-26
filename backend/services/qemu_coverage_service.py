"""
QEMU Coverage Service - Extract coverage from binary-only targets via QEMU TCG.

This service provides coverage extraction capabilities for binaries that cannot
be instrumented at compile-time. It uses QEMU's Tiny Code Generator (TCG) to
track executed basic blocks during emulation.

Features:
- QEMU-based coverage extraction for binary-only targets
- Per-module coverage breakdown
- Comparison coverage (compcov) support
- Integration with AFL++ QEMU mode
- Coverage bitmap compatible with AFL format
"""

import asyncio
import ctypes
import ctypes.util
import hashlib
import mmap
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .binary_fuzzer_service import (
    CoverageProvider,
    QemuArchitecture,
    QemuCapabilities,
    QemuModeType,
)


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class QemuCoverageConfig:
    """Configuration for QEMU coverage extraction."""
    target_path: str
    architecture: Optional[QemuArchitecture] = None
    map_size: int = 65536
    compcov_level: int = 0  # 0=disabled, 1=cmp only, 2=all comparisons
    instrim_enabled: bool = False
    filter_libs: bool = True  # Filter out library code from coverage
    trace_child: bool = True
    persist_coverage: bool = True
    timeout_ms: int = 5000
    qemu_args: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "architecture": self.architecture.value if self.architecture else None,
            "map_size": self.map_size,
            "compcov_level": self.compcov_level,
            "instrim_enabled": self.instrim_enabled,
            "filter_libs": self.filter_libs,
            "trace_child": self.trace_child,
            "persist_coverage": self.persist_coverage,
            "timeout_ms": self.timeout_ms,
        }


@dataclass
class ModuleCoverage:
    """Coverage breakdown for a single module/library."""
    name: str
    base_address: int
    size: int
    blocks_total: int
    blocks_covered: int
    coverage_percentage: float
    hotspots: List[Tuple[int, int]] = field(default_factory=list)  # (address, hit_count)
    is_main_binary: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "base_address": hex(self.base_address),
            "size": self.size,
            "blocks_total": self.blocks_total,
            "blocks_covered": self.blocks_covered,
            "coverage_percentage": round(self.coverage_percentage, 2),
            "hotspots": [(hex(addr), count) for addr, count in self.hotspots[:20]],
            "is_main_binary": self.is_main_binary,
        }


@dataclass
class QemuCoverageResult:
    """Result from QEMU coverage extraction."""
    bitmap: bytes
    edge_count: int
    unique_blocks: int
    modules_covered: Dict[str, int]  # module_name -> blocks covered
    execution_time_ms: float
    trace_log: Optional[str] = None
    module_breakdown: List[ModuleCoverage] = field(default_factory=list)
    exit_code: int = 0
    error: Optional[str] = None
    input_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_count": self.edge_count,
            "unique_blocks": self.unique_blocks,
            "modules_covered": self.modules_covered,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "exit_code": self.exit_code,
            "error": self.error,
            "input_hash": self.input_hash,
            "module_breakdown": [m.to_dict() for m in self.module_breakdown],
        }


@dataclass
class QemuTraceEntry:
    """Single entry from QEMU trace log."""
    address: int
    module: str
    hit_count: int = 1


# ============================================================================
# QEMU Coverage Provider
# ============================================================================


class QemuCoverageProvider(CoverageProvider):
    """
    Coverage provider using QEMU TCG instrumentation.

    Extracts coverage from binary-only targets by using AFL++'s QEMU mode.
    This allows fuzzing closed-source binaries, firmware, and malware samples.

    Coverage is tracked via:
    1. AFL shared memory bitmap (when available)
    2. QEMU trace logs (fallback)
    3. Basic block address tracking

    Environment variables used:
    - AFL_QEMU_INST_RANGES: Limit instrumentation to specific address ranges
    - AFL_COMPCOV_LEVEL: Enable comparison coverage (1=strcmp, 2=all)
    - AFL_INST_RATIO: Instrumentation ratio for large binaries
    - QEMU_LD_PREFIX: Library search path for target binaries
    """

    # Known QEMU tool paths
    QEMU_PATHS = [
        "/usr/local/bin",
        "/opt/AFLplusplus",
        "/usr/bin",
    ]

    AFL_QEMU_TRACE_PATHS = [
        "/usr/local/bin/afl-qemu-trace",
        "/opt/AFLplusplus/afl-qemu-trace",
        "/usr/bin/afl-qemu-trace",
    ]

    ARCH_TO_QEMU_BINARY = {
        QemuArchitecture.X86: "qemu-i386",
        QemuArchitecture.X86_64: "qemu-x86_64",
        QemuArchitecture.ARM: "qemu-arm",
        QemuArchitecture.ARM64: "qemu-aarch64",
        QemuArchitecture.MIPS: "qemu-mips",
        QemuArchitecture.MIPS64: "qemu-mips64",
        QemuArchitecture.MIPSEL: "qemu-mipsel",
        QemuArchitecture.PPC: "qemu-ppc",
        QemuArchitecture.PPC64: "qemu-ppc64",
        QemuArchitecture.RISCV32: "qemu-riscv32",
        QemuArchitecture.RISCV64: "qemu-riscv64",
    }

    def __init__(
        self,
        config: QemuCoverageConfig,
    ):
        self.config = config
        self.map_size = config.map_size
        self._available = False
        self._qemu_trace_path: Optional[str] = None
        self._qemu_binary_path: Optional[str] = None
        self._shm_id: Optional[int] = None
        self._shm_addr: Optional[int] = None
        self._shm_map = None
        self._shmdt = None
        self._libc = None
        self._temp_dir: Optional[str] = None
        self._trace_log_path: Optional[str] = None
        self._capabilities: Optional[QemuCapabilities] = None
        self._block_hits: Dict[int, int] = {}
        self._module_map: Dict[str, Tuple[int, int]] = {}  # name -> (base, size)

        self._init_qemu()
        self._init_shared_memory()

    def _init_qemu(self):
        """Initialize QEMU paths and check availability."""
        # Find afl-qemu-trace
        for path in self.AFL_QEMU_TRACE_PATHS:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                self._qemu_trace_path = path
                break

        # Detect or use provided architecture
        arch = self.config.architecture
        if not arch:
            arch = self._detect_architecture(self.config.target_path)
            self.config.architecture = arch

        if arch:
            qemu_binary = self.ARCH_TO_QEMU_BINARY.get(arch)
            if qemu_binary:
                for base in self.QEMU_PATHS:
                    path = os.path.join(base, qemu_binary)
                    if os.path.isfile(path) and os.access(path, os.X_OK):
                        self._qemu_binary_path = path
                        break

        self._available = bool(self._qemu_trace_path or self._qemu_binary_path)

        # Create temp directory for trace logs
        if self._available:
            self._temp_dir = tempfile.mkdtemp(prefix="qemu_cov_")
            self._trace_log_path = os.path.join(self._temp_dir, "trace.log")

    def _detect_architecture(self, binary_path: str) -> Optional[QemuArchitecture]:
        """Detect binary architecture from ELF header."""
        ELF_MACHINE_MAP = {
            0x03: QemuArchitecture.X86,        # EM_386
            0x3E: QemuArchitecture.X86_64,     # EM_X86_64
            0x28: QemuArchitecture.ARM,        # EM_ARM
            0xB7: QemuArchitecture.ARM64,      # EM_AARCH64
            0x08: QemuArchitecture.MIPS,       # EM_MIPS
            0x14: QemuArchitecture.PPC,        # EM_PPC
            0x15: QemuArchitecture.PPC64,      # EM_PPC64
            0xF3: QemuArchitecture.RISCV64,    # EM_RISCV
        }

        try:
            with open(binary_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return None

                f.seek(18)
                machine = struct.unpack("<H", f.read(2))[0]

                return ELF_MACHINE_MAP.get(machine)
        except Exception:
            return None

    def _init_shared_memory(self):
        """Initialize POSIX shared memory for coverage bitmap."""
        if os.name == "nt":
            return

        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            return

        try:
            self._libc = ctypes.CDLL(libc_path, use_errno=True)
        except OSError:
            return

        IPC_PRIVATE = 0
        IPC_CREAT = 0o1000
        IPC_RMID = 0

        shmget = self._libc.shmget
        shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
        shmget.restype = ctypes.c_int

        shmat = self._libc.shmat
        shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        shmat.restype = ctypes.c_void_p

        shmctl = self._libc.shmctl
        shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        shmctl.restype = ctypes.c_int

        shmdt = self._libc.shmdt
        shmdt.argtypes = [ctypes.c_void_p]
        shmdt.restype = ctypes.c_int

        shm_id = shmget(IPC_PRIVATE, self.map_size, IPC_CREAT | 0o600)
        if shm_id < 0:
            return

        shm_addr = shmat(shm_id, None, 0)
        if shm_addr in (ctypes.c_void_p(-1).value, None):
            return

        shmctl(shm_id, IPC_RMID, None)

        self._shm_id = shm_id
        self._shm_addr = shm_addr
        self._shmdt = shmdt
        self._shm_map = (ctypes.c_ubyte * self.map_size).from_address(shm_addr)
        ctypes.memset(shm_addr, 0, self.map_size)

    def is_available(self) -> bool:
        """Check if QEMU coverage is available."""
        return self._available

    def prepare_environment(self, env: Dict[str, str]) -> Dict[str, str]:
        """Set up environment variables for QEMU coverage."""
        if not self._available:
            return env

        # Set shared memory ID for AFL
        if self._shm_id is not None:
            env["__AFL_SHM_ID"] = str(self._shm_id)
            env["AFL_MAP_SIZE"] = str(self.map_size)

        # Enable QEMU mode
        env["AFL_QEMU_MODE"] = "1"

        # Comparison coverage
        if self.config.compcov_level > 0:
            env["AFL_COMPCOV_LEVEL"] = str(self.config.compcov_level)

        # Instruction ratio for large binaries
        if self.config.instrim_enabled:
            env["AFL_INST_RATIO"] = "50"

        # Enable tracing if we have a trace log path
        if self._trace_log_path:
            env["QEMU_LOG"] = "exec"
            env["QEMU_LOG_FILENAME"] = self._trace_log_path

        # Filter library coverage if requested
        if self.config.filter_libs and os.path.isfile(self.config.target_path):
            # Instrument only the main binary address range
            try:
                base, size = self._get_binary_address_range(self.config.target_path)
                if base and size:
                    env["AFL_QEMU_INST_RANGES"] = f"{hex(base)}-{hex(base + size)}"
            except Exception:
                pass

        return env

    def _get_binary_address_range(self, binary_path: str) -> Tuple[Optional[int], Optional[int]]:
        """Get the address range of the main binary text section."""
        try:
            result = subprocess.run(
                ["readelf", "-S", binary_path],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.split("\n"):
                if ".text" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if ".text" in part and i + 3 < len(parts):
                            try:
                                addr = int(parts[i + 2], 16)
                                size = int(parts[i + 4], 16)
                                return addr, size
                            except (ValueError, IndexError):
                                pass
        except Exception:
            pass
        return None, None

    def reset(self):
        """Reset coverage bitmap for new execution."""
        if self._shm_addr and self.map_size:
            ctypes.memset(self._shm_addr, 0, self.map_size)
        self._block_hits.clear()

    def read_coverage(self) -> Optional[bytes]:
        """Read coverage bitmap from shared memory."""
        if not self._shm_map:
            return None
        return bytes(self._shm_map)

    async def run_traced_execution(
        self,
        input_data: bytes,
        timeout_ms: Optional[int] = None,
    ) -> QemuCoverageResult:
        """
        Run target with QEMU tracing and extract detailed coverage.

        Args:
            input_data: Input to feed to the target
            timeout_ms: Execution timeout in milliseconds

        Returns:
            QemuCoverageResult with coverage data and analysis
        """
        if not self._available:
            return QemuCoverageResult(
                bitmap=bytes(self.map_size),
                edge_count=0,
                unique_blocks=0,
                modules_covered={},
                execution_time_ms=0,
                error="QEMU coverage not available",
            )

        timeout = (timeout_ms or self.config.timeout_ms) / 1000.0

        # Reset coverage
        self.reset()

        # Write input to temp file
        input_path = os.path.join(self._temp_dir, "input")
        with open(input_path, "wb") as f:
            f.write(input_data)

        # Prepare environment
        env = os.environ.copy()
        env = self.prepare_environment(env)

        # Build command
        qemu_path = self._qemu_trace_path or self._qemu_binary_path
        cmd = [qemu_path]

        # Add QEMU args
        if self.config.qemu_args:
            cmd.extend(self.config.qemu_args)

        # Add target and input
        cmd.append(self.config.target_path)
        cmd.append(input_path)

        # Execute
        start_time = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
                exit_code = proc.returncode
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                exit_code = -9
                stdout, stderr = b"", b"Timeout"

        except Exception as e:
            return QemuCoverageResult(
                bitmap=bytes(self.map_size),
                edge_count=0,
                unique_blocks=0,
                modules_covered={},
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )

        execution_time = (time.time() - start_time) * 1000

        # Read coverage bitmap
        bitmap = self.read_coverage() or bytes(self.map_size)

        # Parse trace log if available
        trace_log = None
        if self._trace_log_path and os.path.isfile(self._trace_log_path):
            try:
                with open(self._trace_log_path, "r") as f:
                    trace_log = f.read()
                self._parse_trace_log(trace_log)
            except Exception:
                pass

        # Calculate coverage metrics
        edge_count = sum(1 for b in bitmap if b > 0)
        unique_blocks = len(self._block_hits)

        # Extract module coverage
        module_breakdown = self._extract_module_coverage()
        modules_covered = {m.name: m.blocks_covered for m in module_breakdown}

        # Compute input hash
        input_hash = hashlib.sha256(input_data).hexdigest()[:16]

        return QemuCoverageResult(
            bitmap=bitmap,
            edge_count=edge_count,
            unique_blocks=unique_blocks,
            modules_covered=modules_covered,
            execution_time_ms=execution_time,
            trace_log=trace_log[:10000] if trace_log else None,
            module_breakdown=module_breakdown,
            exit_code=exit_code,
            input_hash=input_hash,
        )

    def _parse_trace_log(self, trace_log: str):
        """Parse QEMU trace log to extract block addresses."""
        # QEMU exec log format: "Trace 0x<addr> [<module>+0x<offset>]"
        # or simply "0x<addr>:"

        addr_pattern = re.compile(r'(?:Trace\s+)?0x([0-9a-fA-F]+)')
        module_pattern = re.compile(r'\[([^\]]+)\+0x([0-9a-fA-F]+)\]')

        for line in trace_log.split('\n'):
            addr_match = addr_pattern.search(line)
            if addr_match:
                try:
                    addr = int(addr_match.group(1), 16)
                    self._block_hits[addr] = self._block_hits.get(addr, 0) + 1

                    # Try to extract module info
                    module_match = module_pattern.search(line)
                    if module_match:
                        module_name = module_match.group(1)
                        if module_name not in self._module_map:
                            self._module_map[module_name] = (addr, 0)
                except ValueError:
                    pass

    def _extract_module_coverage(self) -> List[ModuleCoverage]:
        """Extract per-module coverage from block hits."""
        if not self._block_hits:
            return []

        # Group blocks by module (if available) or by address range
        module_blocks: Dict[str, List[Tuple[int, int]]] = {}

        # Get main binary name
        main_binary = os.path.basename(self.config.target_path)

        for addr, count in self._block_hits.items():
            # Try to assign to known module
            assigned = False
            for module_name, (base, size) in self._module_map.items():
                if base <= addr < base + size:
                    if module_name not in module_blocks:
                        module_blocks[module_name] = []
                    module_blocks[module_name].append((addr, count))
                    assigned = True
                    break

            if not assigned:
                # Assign to main binary by default
                if main_binary not in module_blocks:
                    module_blocks[main_binary] = []
                module_blocks[main_binary].append((addr, count))

        # Build module coverage list
        results = []
        for module_name, blocks in module_blocks.items():
            base_addr = min(addr for addr, _ in blocks) if blocks else 0
            max_addr = max(addr for addr, _ in blocks) if blocks else 0

            # Sort hotspots by hit count
            hotspots = sorted(blocks, key=lambda x: x[1], reverse=True)

            results.append(ModuleCoverage(
                name=module_name,
                base_address=base_addr,
                size=max_addr - base_addr + 1 if blocks else 0,
                blocks_total=0,  # Unknown without static analysis
                blocks_covered=len(blocks),
                coverage_percentage=0.0,  # Cannot calculate without total
                hotspots=hotspots[:20],
                is_main_binary=(module_name == main_binary),
            ))

        # Sort with main binary first
        results.sort(key=lambda m: (not m.is_main_binary, m.name))

        return results

    def extract_module_coverage(self) -> List[ModuleCoverage]:
        """Public method to get current module coverage."""
        return self._extract_module_coverage()

    def get_block_hits(self) -> Dict[int, int]:
        """Get raw block hit counts."""
        return dict(self._block_hits)

    def close(self):
        """Clean up resources."""
        # Detach shared memory
        if self._shmdt and self._shm_addr:
            try:
                self._shmdt(self._shm_addr)
            except Exception:
                pass

        # Clean up temp directory
        if self._temp_dir and os.path.isdir(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir)
            except Exception:
                pass

        self._shm_id = None
        self._shm_addr = None
        self._shm_map = None
        self._temp_dir = None


# ============================================================================
# Factory Functions
# ============================================================================


async def create_qemu_coverage_provider(
    target_path: str,
    architecture: Optional[QemuArchitecture] = None,
    map_size: int = 65536,
    compcov_level: int = 0,
) -> Optional[QemuCoverageProvider]:
    """
    Factory function to create a QEMU coverage provider with auto-detection.

    Args:
        target_path: Path to target binary
        architecture: Target architecture (auto-detected if not provided)
        map_size: Coverage bitmap size
        compcov_level: Comparison coverage level (0-2)

    Returns:
        QemuCoverageProvider if available, None otherwise
    """
    config = QemuCoverageConfig(
        target_path=target_path,
        architecture=architecture,
        map_size=map_size,
        compcov_level=compcov_level,
    )

    provider = QemuCoverageProvider(config)

    if not provider.is_available():
        provider.close()
        return None

    return provider


def check_qemu_coverage_availability() -> Dict[str, Any]:
    """
    Check QEMU coverage capabilities on this system.

    Returns:
        Dictionary with availability info and supported features
    """
    result = {
        "available": False,
        "qemu_trace_found": False,
        "qemu_binaries": [],
        "features": {},
        "architectures": [],
        "error": None,
    }

    # Check for afl-qemu-trace
    for path in QemuCoverageProvider.AFL_QEMU_TRACE_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            result["qemu_trace_found"] = True
            result["qemu_trace_path"] = path
            break

    # Check for architecture-specific QEMU binaries
    for arch, binary in QemuCoverageProvider.ARCH_TO_QEMU_BINARY.items():
        for base in QemuCoverageProvider.QEMU_PATHS:
            path = os.path.join(base, binary)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                result["qemu_binaries"].append(binary)
                result["architectures"].append(arch.value)
                break

    # Check AFL++ QEMU support
    try:
        proc = subprocess.run(
            ["afl-fuzz", "-h"],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = proc.stdout + proc.stderr

        if "-Q" in output:
            result["features"]["standard_qemu"] = True
            result["available"] = True
        if "-QQ" in output or "QEMU persistent" in output.lower():
            result["features"]["persistent_qemu"] = True
        if "COMPCOV" in output or "AFL_COMPCOV" in output:
            result["features"]["compcov"] = True
        if "INSTRIM" in output:
            result["features"]["instrim"] = True

    except FileNotFoundError:
        result["error"] = "AFL++ not found"
    except subprocess.TimeoutExpired:
        result["error"] = "AFL++ check timed out"
    except Exception as e:
        result["error"] = str(e)

    if not result["available"] and not result["error"]:
        result["error"] = "QEMU mode not available. Ensure AFL++ was built with QEMU support."

    return result


def parse_qemu_trace_log(trace_path: str) -> Dict[int, int]:
    """
    Parse a QEMU trace log file and extract block hit counts.

    Args:
        trace_path: Path to QEMU trace log file

    Returns:
        Dictionary mapping block addresses to hit counts
    """
    block_hits: Dict[int, int] = {}

    if not os.path.isfile(trace_path):
        return block_hits

    addr_pattern = re.compile(r'(?:Trace\s+)?0x([0-9a-fA-F]+)')

    try:
        with open(trace_path, "r") as f:
            for line in f:
                match = addr_pattern.search(line)
                if match:
                    try:
                        addr = int(match.group(1), 16)
                        block_hits[addr] = block_hits.get(addr, 0) + 1
                    except ValueError:
                        pass
    except Exception:
        pass

    return block_hits


def map_addresses_to_modules(
    addresses: Set[int],
    binary_path: str,
) -> Dict[str, List[int]]:
    """
    Map coverage addresses back to modules/functions using readelf/nm.

    Args:
        addresses: Set of covered addresses
        binary_path: Path to binary file

    Returns:
        Dictionary mapping module/function names to covered addresses
    """
    result: Dict[str, List[int]] = {}

    if not addresses or not os.path.isfile(binary_path):
        return result

    # Try to get symbol table
    try:
        proc = subprocess.run(
            ["nm", "-C", binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Parse symbols
        symbols: List[Tuple[int, int, str]] = []  # (start, end, name)
        lines = proc.stdout.strip().split('\n')

        for i, line in enumerate(lines):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    addr = int(parts[0], 16)
                    name = " ".join(parts[2:])

                    # Estimate function size from next symbol
                    next_addr = None
                    if i + 1 < len(lines):
                        next_parts = lines[i + 1].split()
                        if len(next_parts) >= 1:
                            try:
                                next_addr = int(next_parts[0], 16)
                            except ValueError:
                                pass

                    end_addr = next_addr if next_addr and next_addr > addr else addr + 0x100
                    symbols.append((addr, end_addr, name))
                except ValueError:
                    pass

        # Map addresses to symbols
        for addr in addresses:
            for start, end, name in symbols:
                if start <= addr < end:
                    if name not in result:
                        result[name] = []
                    result[name].append(addr)
                    break
            else:
                # No symbol found
                if "unknown" not in result:
                    result["unknown"] = []
                result["unknown"].append(addr)

    except Exception:
        # Fallback: group by address range
        for addr in sorted(addresses):
            key = f"block_{hex(addr)}"
            result[key] = [addr]

    return result
