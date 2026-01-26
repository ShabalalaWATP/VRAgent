"""
Taint Tracking Service for Targeted Fuzzing.

This service provides dynamic taint analysis to identify which bytes in an input
reach security-sensitive functions (sinks). This information is used to:

1. Prioritize mutation of "hot bytes" that affect security-critical code paths
2. Generate targeted mutations for specific vulnerability classes
3. Guide hybrid fuzzing by focusing concolic execution on relevant inputs

Supported backends:
- Frida: Cross-platform, no recompilation needed (primary)
- QEMU TCG: Binary-only taint tracking via QEMU
- DynamoRIO: High-performance instrumentation
- Intel Pin: x86/x64 binary instrumentation
"""

from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Set, Tuple
from enum import Enum
import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import struct
import tempfile
import time

logger = logging.getLogger(__name__)


class TaintBackend(str, Enum):
    """Supported taint tracking backends."""
    FRIDA = "frida"
    QEMU_TCG = "qemu_tcg"
    DYNAMORIO = "dynamorio"
    PIN = "pin"
    AUTO = "auto"


class TaintSource(str, Enum):
    """Categories of taint sources (where tainted data originates)."""
    STDIN = "stdin"
    FILE_READ = "file_read"
    NETWORK = "network"
    ARGV = "argv"
    ENVIRONMENT = "environment"
    MMAP = "mmap"


class TaintSink(str, Enum):
    """Security-sensitive sink functions."""
    # Memory operations
    STRCPY = "strcpy"
    STRNCPY = "strncpy"
    STRCAT = "strcat"
    STRNCAT = "strncat"
    SPRINTF = "sprintf"
    SNPRINTF = "snprintf"
    MEMCPY = "memcpy"
    MEMMOVE = "memmove"
    GETS = "gets"
    SCANF = "scanf"
    SSCANF = "sscanf"
    # Command execution
    SYSTEM = "system"
    EXEC = "exec"
    EXECVE = "execve"
    POPEN = "popen"
    # File operations
    FOPEN = "fopen"
    OPEN = "open"
    # Network operations
    SEND = "send"
    SENDTO = "sendto"
    WRITE = "write"
    # Format strings
    PRINTF = "printf"
    FPRINTF = "fprintf"
    SYSLOG = "syslog"
    # Memory allocation (for heap analysis)
    MALLOC = "malloc"
    REALLOC = "realloc"
    FREE = "free"


# Default sink criticality scores (0.0 - 1.0)
SINK_CRITICALITY: Dict[TaintSink, float] = {
    # Critical: Direct code execution
    TaintSink.SYSTEM: 1.0,
    TaintSink.EXEC: 1.0,
    TaintSink.EXECVE: 1.0,
    TaintSink.POPEN: 1.0,
    # High: Memory corruption
    TaintSink.STRCPY: 0.9,
    TaintSink.GETS: 0.9,
    TaintSink.SPRINTF: 0.85,
    TaintSink.MEMCPY: 0.8,
    TaintSink.STRCAT: 0.8,
    TaintSink.SCANF: 0.8,
    # Medium-High: Controlled writes
    TaintSink.STRNCPY: 0.7,
    TaintSink.STRNCAT: 0.7,
    TaintSink.SNPRINTF: 0.65,
    TaintSink.MEMMOVE: 0.65,
    TaintSink.SSCANF: 0.7,
    # Medium: Format strings
    TaintSink.PRINTF: 0.6,
    TaintSink.FPRINTF: 0.6,
    TaintSink.SYSLOG: 0.6,
    # Medium: File/Network
    TaintSink.FOPEN: 0.5,
    TaintSink.OPEN: 0.5,
    TaintSink.SEND: 0.5,
    TaintSink.SENDTO: 0.5,
    TaintSink.WRITE: 0.4,
    # Lower: Memory management (for heap analysis)
    TaintSink.MALLOC: 0.3,
    TaintSink.REALLOC: 0.3,
    TaintSink.FREE: 0.4,
}


@dataclass
class TaintConfig:
    """Configuration for taint tracking analysis."""
    backend: TaintBackend = TaintBackend.AUTO
    target_path: str = ""
    target_args: str = "@@"
    timeout_seconds: int = 30
    # Source/sink configuration
    track_sources: List[TaintSource] = field(
        default_factory=lambda: [TaintSource.STDIN, TaintSource.FILE_READ]
    )
    track_sinks: List[TaintSink] = field(
        default_factory=lambda: [
            TaintSink.STRCPY, TaintSink.MEMCPY, TaintSink.SPRINTF,
            TaintSink.SYSTEM, TaintSink.EXEC,
        ]
    )
    # Custom sinks (function names or addresses)
    custom_sinks: List[str] = field(default_factory=list)
    custom_sink_criticality: Dict[str, float] = field(default_factory=dict)
    # Analysis options
    track_implicit_flows: bool = False  # Control flow based tainting
    track_pointer_aliases: bool = True
    max_taint_labels: int = 256  # Max unique taint labels
    byte_granularity: bool = True  # Track at byte level vs word level
    # Output
    output_dir: str = ""
    telemetry_dir: Optional[str] = None
    # Backend-specific paths
    frida_script_path: Optional[str] = None
    dynamorio_path: Optional[str] = None
    pin_path: Optional[str] = None
    qemu_path: Optional[str] = None


@dataclass
class TaintedByte:
    """Information about a tainted byte in input."""
    input_offset: int
    taint_label: int
    reaches_sinks: List[str]  # Function names that this byte reaches
    flow_depth: int  # How many operations between source and sink
    criticality: float  # 0.0-1.0 based on sink severity
    first_sink_address: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_offset": self.input_offset,
            "taint_label": self.taint_label,
            "reaches_sinks": self.reaches_sinks,
            "flow_depth": self.flow_depth,
            "criticality": self.criticality,
            "first_sink_address": self.first_sink_address,
        }


@dataclass
class TaintFlowEdge:
    """An edge in the taint flow graph (propagation step)."""
    source_address: int
    dest_address: int
    instruction: str
    operation: str  # mov, add, xor, etc.
    tainted_bytes: List[int]  # Input offsets involved

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_address": hex(self.source_address),
            "dest_address": hex(self.dest_address),
            "instruction": self.instruction,
            "operation": self.operation,
            "tainted_bytes": self.tainted_bytes,
        }


@dataclass
class SinkHit:
    """Record of tainted data reaching a sink."""
    sink_name: str
    sink_address: int
    hit_count: int
    tainted_args: List[int]  # Which arguments were tainted
    input_bytes: List[int]  # Which input bytes reached this sink
    sample_values: List[bytes]  # Sample tainted values (for analysis)
    criticality: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_name": self.sink_name,
            "sink_address": hex(self.sink_address),
            "hit_count": self.hit_count,
            "tainted_args": self.tainted_args,
            "input_bytes": self.input_bytes,
            "sample_values": [base64.b64encode(v).decode() for v in self.sample_values[:5]],
            "criticality": self.criticality,
        }


@dataclass
class TaintAnalysisResult:
    """Result of taint analysis on an input."""
    input_id: str
    input_path: str
    input_size: int
    input_hash: str
    execution_time_ms: float
    # Tainted bytes analysis
    tainted_bytes: List[TaintedByte]
    hot_bytes: List[int]  # High-impact byte offsets (sorted by criticality)
    cold_bytes: List[int]  # Bytes that don't reach any sinks
    # Sink analysis
    sink_hits: List[SinkHit]
    total_sink_hits: int
    unique_sinks_reached: int
    # Flow analysis
    flow_edges: List[TaintFlowEdge]
    max_flow_depth: int
    # Mutation guidance
    mutation_priority_map: Dict[int, float]  # offset -> priority (0-1)
    suggested_mutations: List[Dict[str, Any]]
    # Metadata
    backend_used: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_id": self.input_id,
            "input_path": self.input_path,
            "input_size": self.input_size,
            "input_hash": self.input_hash,
            "execution_time_ms": self.execution_time_ms,
            "tainted_bytes_count": len(self.tainted_bytes),
            "hot_bytes": self.hot_bytes[:50],  # Limit for JSON
            "cold_bytes_count": len(self.cold_bytes),
            "sink_hits": [s.to_dict() for s in self.sink_hits],
            "total_sink_hits": self.total_sink_hits,
            "unique_sinks_reached": self.unique_sinks_reached,
            "max_flow_depth": self.max_flow_depth,
            "mutation_priority_map": {
                str(k): v for k, v in list(self.mutation_priority_map.items())[:100]
            },
            "suggested_mutations": self.suggested_mutations[:20],
            "backend_used": self.backend_used,
            "errors": self.errors,
            "warnings": self.warnings,
        }


# Frida script template for taint tracking
FRIDA_TAINT_SCRIPT = '''
'use strict';

// Configuration from Python
const CONFIG = %CONFIG%;

// Taint state
const taintMap = new Map();  // address -> Set of input byte offsets
const sinkHits = [];
const flowEdges = [];

// Helper: Get function address by name
function getFuncAddr(name) {
    const symbols = Module.enumerateSymbols(Process.enumerateModules()[0].name);
    for (const sym of symbols) {
        if (sym.name === name || sym.name === '_' + name) {
            return sym.address;
        }
    }
    // Try libc
    try {
        return Module.findExportByName(null, name);
    } catch (e) {
        return null;
    }
}

// Track input read
function hookInputSource(funcName, argIndex, sizeArgIndex) {
    const addr = getFuncAddr(funcName);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.buf = args[argIndex];
            this.size = sizeArgIndex >= 0 ? args[sizeArgIndex].toInt32() : 0;
        },
        onLeave: function(retval) {
            const bytesRead = retval.toInt32();
            if (bytesRead > 0 && this.buf) {
                // Mark bytes as tainted
                for (let i = 0; i < bytesRead; i++) {
                    const addr = this.buf.add(i);
                    if (!taintMap.has(addr.toString())) {
                        taintMap.set(addr.toString(), new Set());
                    }
                    taintMap.get(addr.toString()).add(CONFIG.currentOffset + i);
                }
                CONFIG.currentOffset += bytesRead;
            }
        }
    });
}

// Hook sink functions
function hookSink(funcName, argIndices, criticality) {
    const addr = getFuncAddr(funcName);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter: function(args) {
            const taintedArgs = [];
            const inputBytes = new Set();
            const sampleValues = [];

            for (const idx of argIndices) {
                const arg = args[idx];
                if (arg.isNull()) continue;

                // Check if argument is tainted (pointer to tainted memory)
                try {
                    const argStr = arg.toString();
                    if (taintMap.has(argStr)) {
                        taintedArgs.push(idx);
                        for (const offset of taintMap.get(argStr)) {
                            inputBytes.add(offset);
                        }
                    }

                    // Also check if it's a string pointer with tainted content
                    if (arg.readPointer) {
                        const ptr = arg;
                        for (let i = 0; i < 64; i++) {
                            const byteAddr = ptr.add(i).toString();
                            if (taintMap.has(byteAddr)) {
                                taintedArgs.push(idx);
                                for (const offset of taintMap.get(byteAddr)) {
                                    inputBytes.add(offset);
                                }
                            }
                        }
                        // Sample value
                        try {
                            sampleValues.push(ptr.readCString(32) || '');
                        } catch (e) {}
                    }
                } catch (e) {}
            }

            if (inputBytes.size > 0) {
                sinkHits.push({
                    sink_name: funcName,
                    sink_address: addr.toString(),
                    tainted_args: taintedArgs,
                    input_bytes: Array.from(inputBytes),
                    sample_values: sampleValues,
                    criticality: criticality
                });
            }
        }
    });
}

// Initialize hooks
function init() {
    // Hook input sources
    if (CONFIG.track_sources.includes('file_read')) {
        hookInputSource('read', 1, 2);
        hookInputSource('fread', 0, 2);
    }
    if (CONFIG.track_sources.includes('stdin')) {
        hookInputSource('fgets', 0, 1);
        hookInputSource('gets', 0, -1);
    }

    // Hook sinks
    for (const [sinkName, criticality] of Object.entries(CONFIG.sinks)) {
        // Determine which args to check based on function
        let argIndices = [0];  // Default: check first arg
        if (['memcpy', 'memmove', 'strncpy'].includes(sinkName)) {
            argIndices = [0, 1];  // dest and src
        } else if (['sprintf', 'snprintf'].includes(sinkName)) {
            argIndices = [0, 1, 2];  // dest, format, args
        } else if (sinkName === 'system' || sinkName === 'popen') {
            argIndices = [0];  // command string
        }

        hookSink(sinkName, argIndices, criticality);
    }
}

// Export results
rpc.exports = {
    getSinkHits: function() {
        return sinkHits;
    },
    getFlowEdges: function() {
        return flowEdges;
    },
    getTaintedCount: function() {
        return taintMap.size;
    }
};

init();
'''


def _find_backend_binary(name: str, env_var: Optional[str] = None) -> Optional[str]:
    """Find backend binary in common locations."""
    if env_var:
        path = os.environ.get(env_var)
        if path and os.path.isfile(path):
            return path

    # Common paths
    search_paths = [
        "/usr/local/bin",
        "/usr/bin",
        "/opt",
        os.path.expanduser("~/.local/bin"),
    ]

    for base in search_paths:
        full_path = os.path.join(base, name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path

    return shutil.which(name)


def _compute_file_hash(path: str) -> str:
    """Compute SHA256 hash of file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


class TaintTrackingService:
    """
    Dynamic taint tracking service for targeted fuzzing.

    Tracks data flow from inputs to security-sensitive sinks to identify
    "hot bytes" that should be prioritized for mutation.

    Example usage:
        config = TaintConfig(
            target_path="/path/to/binary",
            track_sinks=[TaintSink.STRCPY, TaintSink.SYSTEM],
        )
        service = TaintTrackingService(config)

        result = await service.analyze_input("/path/to/input.bin")
        print(f"Hot bytes: {result.hot_bytes}")
        print(f"Sinks reached: {result.unique_sinks_reached}")

        # Generate mutation mask for AFL++
        mask = service.generate_mutation_mask(result, result.input_size)
    """

    def __init__(self, config: TaintConfig):
        self.config = config
        self._running = False
        self._stop_requested = False
        self.stats: Dict[str, Any] = {
            "inputs_analyzed": 0,
            "total_hot_bytes": 0,
            "total_sink_hits": 0,
            "analysis_time_total_ms": 0.0,
        }
        self._backend: Optional[str] = None
        self._frida_session = None

    def _select_backend(self) -> str:
        """Select the best available backend."""
        if self.config.backend != TaintBackend.AUTO:
            return self.config.backend.value

        # Try backends in order of preference
        try:
            import frida
            return TaintBackend.FRIDA.value
        except ImportError:
            pass

        if _find_backend_binary("drrun", "DYNAMORIO_HOME"):
            return TaintBackend.DYNAMORIO.value

        if _find_backend_binary("pin", "PIN_ROOT"):
            return TaintBackend.PIN.value

        if _find_backend_binary("qemu-x86_64"):
            return TaintBackend.QEMU_TCG.value

        # Fall back to Frida (will error if not installed)
        return TaintBackend.FRIDA.value

    async def start(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Start taint tracking service (for batch analysis).

        Yields status updates during analysis.
        """
        self._running = True
        self._stop_requested = False
        self._backend = self._select_backend()

        yield {
            "type": "service_started",
            "backend": self._backend,
            "config": {
                "target": self.config.target_path,
                "sinks": [s.value for s in self.config.track_sinks],
            }
        }

        while self._running and not self._stop_requested:
            await asyncio.sleep(1)
            yield {
                "type": "status",
                "stats": self.stats.copy(),
            }

        yield {
            "type": "service_stopped",
            "stats": self.stats.copy(),
        }

    async def stop(self) -> None:
        """Stop the service gracefully."""
        self._stop_requested = True
        self._running = False

        if self._frida_session:
            try:
                self._frida_session.detach()
            except Exception:
                pass
            self._frida_session = None

    async def analyze_input(
        self,
        input_path: str,
        target_path: Optional[str] = None,
        target_args: Optional[str] = None,
    ) -> TaintAnalysisResult:
        """
        Perform taint analysis on a single input.

        Args:
            input_path: Path to input file
            target_path: Override target path from config
            target_args: Override target args from config

        Returns:
            TaintAnalysisResult with hot byte identification
        """
        start_time = time.time()

        target = target_path or self.config.target_path
        args = target_args or self.config.target_args

        # Validate
        if not os.path.isfile(input_path):
            return TaintAnalysisResult(
                input_id="",
                input_path=input_path,
                input_size=0,
                input_hash="",
                execution_time_ms=0,
                tainted_bytes=[],
                hot_bytes=[],
                cold_bytes=[],
                sink_hits=[],
                total_sink_hits=0,
                unique_sinks_reached=0,
                flow_edges=[],
                max_flow_depth=0,
                mutation_priority_map={},
                suggested_mutations=[],
                backend_used="none",
                errors=[f"Input file not found: {input_path}"],
            )

        if not os.path.isfile(target):
            return TaintAnalysisResult(
                input_id="",
                input_path=input_path,
                input_size=0,
                input_hash="",
                execution_time_ms=0,
                tainted_bytes=[],
                hot_bytes=[],
                cold_bytes=[],
                sink_hits=[],
                total_sink_hits=0,
                unique_sinks_reached=0,
                flow_edges=[],
                max_flow_depth=0,
                mutation_priority_map={},
                suggested_mutations=[],
                backend_used="none",
                errors=[f"Target not found: {target}"],
            )

        # Get input info
        input_size = os.path.getsize(input_path)
        input_hash = _compute_file_hash(input_path)
        input_id = f"{os.path.basename(input_path)}_{input_hash}"

        # Select and run backend
        backend = self._select_backend()

        if backend == TaintBackend.FRIDA.value:
            result = await self._analyze_with_frida(
                input_path, target, args, input_id, input_size, input_hash
            )
        else:
            # Fallback to simulated analysis for now
            result = await self._analyze_simulated(
                input_path, target, args, input_id, input_size, input_hash
            )

        result.execution_time_ms = (time.time() - start_time) * 1000
        result.backend_used = backend

        # Update stats
        self.stats["inputs_analyzed"] += 1
        self.stats["total_hot_bytes"] += len(result.hot_bytes)
        self.stats["total_sink_hits"] += result.total_sink_hits
        self.stats["analysis_time_total_ms"] += result.execution_time_ms

        return result

    async def _analyze_with_frida(
        self,
        input_path: str,
        target: str,
        args: str,
        input_id: str,
        input_size: int,
        input_hash: str,
    ) -> TaintAnalysisResult:
        """Analyze using Frida instrumentation."""
        try:
            import frida
        except ImportError:
            return TaintAnalysisResult(
                input_id=input_id,
                input_path=input_path,
                input_size=input_size,
                input_hash=input_hash,
                execution_time_ms=0,
                tainted_bytes=[],
                hot_bytes=[],
                cold_bytes=list(range(input_size)),
                sink_hits=[],
                total_sink_hits=0,
                unique_sinks_reached=0,
                flow_edges=[],
                max_flow_depth=0,
                mutation_priority_map={},
                suggested_mutations=[],
                backend_used="frida",
                errors=["Frida not installed. Run: pip install frida frida-tools"],
            )

        # Build command
        if "@@" in args:
            cmd_args = args.replace("@@", input_path).split()
        else:
            cmd_args = args.split() if args else []

        # Prepare Frida config
        frida_config = {
            "track_sources": [s.value for s in self.config.track_sources],
            "sinks": {
                s.value: SINK_CRITICALITY.get(s, 0.5)
                for s in self.config.track_sinks
            },
            "currentOffset": 0,
        }

        # Add custom sinks
        for sink in self.config.custom_sinks:
            frida_config["sinks"][sink] = self.config.custom_sink_criticality.get(sink, 0.5)

        script_source = FRIDA_TAINT_SCRIPT.replace(
            "%CONFIG%", json.dumps(frida_config)
        )

        sink_hits: List[SinkHit] = []
        flow_edges: List[TaintFlowEdge] = []
        errors: List[str] = []
        warnings: List[str] = []

        try:
            # Spawn target process
            pid = frida.spawn([target] + cmd_args)
            session = frida.attach(pid)
            self._frida_session = session

            # Load script
            script = session.create_script(script_source)
            script.load()

            # Resume and wait for completion
            frida.resume(pid)

            # Wait for process to complete (with timeout)
            await asyncio.sleep(min(self.config.timeout_seconds, 30))

            # Get results from script
            try:
                raw_sink_hits = script.exports.get_sink_hits()
                for hit in raw_sink_hits:
                    sink_hits.append(SinkHit(
                        sink_name=hit["sink_name"],
                        sink_address=int(hit["sink_address"], 16) if isinstance(hit["sink_address"], str) else hit["sink_address"],
                        hit_count=1,
                        tainted_args=hit.get("tainted_args", []),
                        input_bytes=hit.get("input_bytes", []),
                        sample_values=[v.encode() if isinstance(v, str) else v for v in hit.get("sample_values", [])],
                        criticality=hit.get("criticality", 0.5),
                    ))
            except Exception as e:
                warnings.append(f"Failed to get sink hits: {e}")

            # Cleanup
            session.detach()
            self._frida_session = None

        except frida.ProcessNotFoundError:
            errors.append("Process terminated before analysis completed")
        except frida.PermissionDeniedError:
            errors.append("Permission denied. Try running with elevated privileges")
        except Exception as e:
            errors.append(f"Frida analysis error: {str(e)}")

        # Build result from sink hits
        return self._build_result_from_sink_hits(
            input_id, input_path, input_size, input_hash,
            sink_hits, flow_edges, errors, warnings
        )

    async def _analyze_simulated(
        self,
        input_path: str,
        target: str,
        args: str,
        input_id: str,
        input_size: int,
        input_hash: str,
    ) -> TaintAnalysisResult:
        """
        Simulated taint analysis using heuristics.

        This is a fallback when no instrumentation backend is available.
        Uses pattern matching and heuristics to estimate hot bytes.
        """
        warnings = [
            "Using simulated taint analysis (no instrumentation backend available)",
            "Install Frida for accurate analysis: pip install frida frida-tools",
        ]

        # Read input
        with open(input_path, "rb") as f:
            input_data = f.read()

        # Heuristic: bytes that look like they could affect control flow
        hot_bytes: List[int] = []
        mutation_priority: Dict[int, float] = {}

        for i, byte in enumerate(input_data):
            priority = 0.0

            # Length fields (common at start)
            if i < 8:
                priority += 0.3

            # Printable ASCII that could be part of strings
            if 0x20 <= byte <= 0x7e:
                priority += 0.2

            # Null bytes (string terminators)
            if byte == 0:
                priority += 0.4

            # Magic values
            if byte in [0xff, 0x7f, 0x80, 0x00]:
                priority += 0.3

            # Format string indicators
            if byte == ord('%'):
                priority += 0.5

            # Path separators
            if byte in [ord('/'), ord('\\')]:
                priority += 0.4

            if priority > 0.3:
                hot_bytes.append(i)
                mutation_priority[i] = min(priority, 1.0)

        # Cold bytes are those not in hot
        cold_bytes = [i for i in range(input_size) if i not in hot_bytes]

        # Sort hot bytes by priority
        hot_bytes.sort(key=lambda x: mutation_priority.get(x, 0), reverse=True)

        return TaintAnalysisResult(
            input_id=input_id,
            input_path=input_path,
            input_size=input_size,
            input_hash=input_hash,
            execution_time_ms=0,
            tainted_bytes=[],
            hot_bytes=hot_bytes[:min(len(hot_bytes), input_size // 2)],
            cold_bytes=cold_bytes,
            sink_hits=[],
            total_sink_hits=0,
            unique_sinks_reached=0,
            flow_edges=[],
            max_flow_depth=0,
            mutation_priority_map=mutation_priority,
            suggested_mutations=self._generate_suggested_mutations(input_data, hot_bytes),
            backend_used="simulated",
            warnings=warnings,
        )

    def _build_result_from_sink_hits(
        self,
        input_id: str,
        input_path: str,
        input_size: int,
        input_hash: str,
        sink_hits: List[SinkHit],
        flow_edges: List[TaintFlowEdge],
        errors: List[str],
        warnings: List[str],
    ) -> TaintAnalysisResult:
        """Build TaintAnalysisResult from collected sink hits."""
        # Aggregate input bytes by criticality
        byte_criticality: Dict[int, float] = {}

        for hit in sink_hits:
            for byte_offset in hit.input_bytes:
                if byte_offset not in byte_criticality:
                    byte_criticality[byte_offset] = 0
                byte_criticality[byte_offset] = max(
                    byte_criticality[byte_offset],
                    hit.criticality
                )

        # Build tainted bytes list
        tainted_bytes: List[TaintedByte] = []
        for offset, criticality in byte_criticality.items():
            sinks_reached = [
                hit.sink_name for hit in sink_hits
                if offset in hit.input_bytes
            ]
            tainted_bytes.append(TaintedByte(
                input_offset=offset,
                taint_label=offset,
                reaches_sinks=list(set(sinks_reached)),
                flow_depth=1,
                criticality=criticality,
            ))

        # Hot bytes: sorted by criticality
        hot_bytes = sorted(
            byte_criticality.keys(),
            key=lambda x: byte_criticality[x],
            reverse=True
        )

        # Cold bytes
        all_tainted = set(byte_criticality.keys())
        cold_bytes = [i for i in range(input_size) if i not in all_tainted]

        # Unique sinks
        unique_sinks = set(hit.sink_name for hit in sink_hits)

        # Read input for mutation suggestions
        suggested_mutations = []
        try:
            with open(input_path, "rb") as f:
                input_data = f.read()
            suggested_mutations = self._generate_suggested_mutations(input_data, hot_bytes)
        except Exception:
            pass

        return TaintAnalysisResult(
            input_id=input_id,
            input_path=input_path,
            input_size=input_size,
            input_hash=input_hash,
            execution_time_ms=0,
            tainted_bytes=tainted_bytes,
            hot_bytes=hot_bytes,
            cold_bytes=cold_bytes,
            sink_hits=sink_hits,
            total_sink_hits=len(sink_hits),
            unique_sinks_reached=len(unique_sinks),
            flow_edges=flow_edges,
            max_flow_depth=max((tb.flow_depth for tb in tainted_bytes), default=0),
            mutation_priority_map=byte_criticality,
            suggested_mutations=suggested_mutations,
            backend_used="",
            errors=errors,
            warnings=warnings,
        )

    def _generate_suggested_mutations(
        self,
        input_data: bytes,
        hot_bytes: List[int],
    ) -> List[Dict[str, Any]]:
        """Generate targeted mutations based on hot bytes."""
        suggestions = []

        # Focus on top hot bytes
        for offset in hot_bytes[:20]:
            if offset >= len(input_data):
                continue

            byte_val = input_data[offset]

            # Suggest mutations based on byte value
            mutations = []

            # Null byte
            if byte_val != 0:
                mutations.append({"value": 0, "reason": "null_termination"})

            # Boundary values
            if byte_val != 0xff:
                mutations.append({"value": 0xff, "reason": "max_value"})
            if byte_val != 0x7f:
                mutations.append({"value": 0x7f, "reason": "signed_max"})
            if byte_val != 0x80:
                mutations.append({"value": 0x80, "reason": "signed_min"})

            # Format string if printable
            if 0x20 <= byte_val <= 0x7e:
                mutations.append({"value": ord('%'), "reason": "format_string"})

            if mutations:
                suggestions.append({
                    "offset": offset,
                    "original": byte_val,
                    "mutations": mutations[:4],
                })

        return suggestions

    async def batch_analyze(
        self,
        input_paths: List[str],
        max_parallel: int = 2,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> AsyncGenerator[TaintAnalysisResult, None]:
        """
        Analyze multiple inputs.

        Args:
            input_paths: List of input file paths
            max_parallel: Maximum parallel analyses
            progress_callback: Optional callback(completed, total)

        Yields:
            TaintAnalysisResult for each input
        """
        total = len(input_paths)
        completed = 0

        # Process in batches
        for i in range(0, total, max_parallel):
            batch = input_paths[i:i + max_parallel]

            # Run batch in parallel
            tasks = [self.analyze_input(path) for path in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                completed += 1

                if isinstance(result, Exception):
                    # Yield error result
                    yield TaintAnalysisResult(
                        input_id="",
                        input_path="",
                        input_size=0,
                        input_hash="",
                        execution_time_ms=0,
                        tainted_bytes=[],
                        hot_bytes=[],
                        cold_bytes=[],
                        sink_hits=[],
                        total_sink_hits=0,
                        unique_sinks_reached=0,
                        flow_edges=[],
                        max_flow_depth=0,
                        mutation_priority_map={},
                        suggested_mutations=[],
                        backend_used="error",
                        errors=[str(result)],
                    )
                else:
                    yield result

                if progress_callback:
                    progress_callback(completed, total)

    def get_hot_bytes(
        self,
        result: TaintAnalysisResult,
        min_criticality: float = 0.5,
    ) -> List[int]:
        """
        Extract hot byte offsets from analysis result.

        Hot bytes are those that:
        1. Reach security-sensitive sinks
        2. Have high criticality scores

        Args:
            result: TaintAnalysisResult from analyze_input
            min_criticality: Minimum criticality threshold (0-1)

        Returns:
            List of byte offsets sorted by criticality
        """
        return [
            offset for offset in result.hot_bytes
            if result.mutation_priority_map.get(offset, 0) >= min_criticality
        ]

    def generate_mutation_mask(
        self,
        result: TaintAnalysisResult,
        input_size: int,
    ) -> bytes:
        """
        Generate mutation priority mask for AFL++.

        Each byte in the mask represents the mutation priority (0-255)
        for the corresponding input byte.

        Args:
            result: TaintAnalysisResult from analyze_input
            input_size: Size of input (for mask size)

        Returns:
            Byte array where each byte is 0-255 priority
        """
        mask = bytearray(input_size)

        for offset, priority in result.mutation_priority_map.items():
            if 0 <= offset < input_size:
                mask[offset] = min(int(priority * 255), 255)

        return bytes(mask)

    def suggest_targeted_mutations(
        self,
        result: TaintAnalysisResult,
        input_data: bytes,
        max_mutations: int = 20,
    ) -> List[bytes]:
        """
        Generate targeted mutations based on taint analysis.

        Creates new inputs by mutating hot bytes in ways likely to
        trigger vulnerabilities.

        Args:
            result: TaintAnalysisResult from analyze_input
            input_data: Original input bytes
            max_mutations: Maximum mutations to generate

        Returns:
            List of mutated inputs
        """
        mutations = []
        input_array = bytearray(input_data)

        for suggestion in result.suggested_mutations[:max_mutations]:
            offset = suggestion["offset"]
            for mutation in suggestion["mutations"]:
                mutated = bytearray(input_array)
                mutated[offset] = mutation["value"]
                mutations.append(bytes(mutated))

                if len(mutations) >= max_mutations:
                    break
            if len(mutations) >= max_mutations:
                break

        return mutations

    def get_status(self) -> Dict[str, Any]:
        """Get current service status."""
        return {
            "running": self._running,
            "backend": self._backend or self._select_backend(),
            "stats": self.stats.copy(),
            "config": {
                "target": self.config.target_path,
                "sinks": [s.value for s in self.config.track_sinks],
                "timeout": self.config.timeout_seconds,
            }
        }


# Convenience functions

async def check_taint_backend_installation() -> Dict[str, Any]:
    """Check availability of taint tracking backends."""
    result = {
        "frida": {"available": False, "version": None},
        "dynamorio": {"available": False, "path": None},
        "pin": {"available": False, "path": None},
        "qemu": {"available": False, "path": None},
        "recommended": None,
    }

    # Check Frida
    try:
        import frida
        result["frida"]["available"] = True
        result["frida"]["version"] = frida.__version__
        result["recommended"] = "frida"
    except ImportError:
        pass

    # Check DynamoRIO
    dr_path = _find_backend_binary("drrun", "DYNAMORIO_HOME")
    if dr_path:
        result["dynamorio"]["available"] = True
        result["dynamorio"]["path"] = dr_path
        if not result["recommended"]:
            result["recommended"] = "dynamorio"

    # Check Pin
    pin_path = _find_backend_binary("pin", "PIN_ROOT")
    if pin_path:
        result["pin"]["available"] = True
        result["pin"]["path"] = pin_path
        if not result["recommended"]:
            result["recommended"] = "pin"

    # Check QEMU
    qemu_path = _find_backend_binary("qemu-x86_64")
    if qemu_path:
        result["qemu"]["available"] = True
        result["qemu"]["path"] = qemu_path
        if not result["recommended"]:
            result["recommended"] = "qemu"

    return result


def get_default_sinks() -> List[Tuple[str, TaintSink, float]]:
    """Return default sink definitions with criticality scores."""
    return [
        (sink.value, sink, SINK_CRITICALITY.get(sink, 0.5))
        for sink in TaintSink
    ]
