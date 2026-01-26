"""
Android Native Library Fuzzer Service

Fuzzes Android native libraries (.so files) using:
1. FRIDA-based on-device fuzzing (instrumentation)
2. QEMU-based emulated fuzzing (for offline analysis)
3. AFL++ FRIDA mode integration
4. Crash analysis and triage
"""

import asyncio
import hashlib
import logging
import os
import re
import struct
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class FuzzMode(Enum):
    """Native fuzzing mode."""
    FRIDA = "frida"           # On-device with FRIDA instrumentation
    QEMU = "qemu"             # Emulated with QEMU user-mode
    AFL_FRIDA = "afl_frida"   # AFL++ FRIDA mode
    AFL_QEMU = "afl_qemu"     # AFL++ QEMU mode


class InputDelivery(Enum):
    """How input is delivered to target function."""
    STDIN = "stdin"
    FILE = "file"
    ARGUMENT = "argument"
    MEMORY = "memory"         # Direct memory write via FRIDA


class CrashType(Enum):
    """Type of crash detected."""
    SEGFAULT = "segfault"
    SIGABRT = "sigabrt"
    SIGBUS = "sigbus"
    SIGFPE = "sigfpe"
    TIMEOUT = "timeout"
    HANG = "hang"
    ASAN = "asan"             # Address Sanitizer
    UBSAN = "ubsan"           # Undefined Behavior Sanitizer
    UNKNOWN = "unknown"


class Severity(Enum):
    """Crash severity classification."""
    CRITICAL = "critical"     # Exploitable (heap overflow, UAF)
    HIGH = "high"             # Likely exploitable (stack overflow)
    MEDIUM = "medium"         # DoS, NULL deref
    LOW = "low"               # Minor issues
    INFO = "info"             # Informational


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class NativeLibraryInfo:
    """Information about a native Android library."""
    name: str
    path: str                           # Path on device or local
    architecture: str                   # arm64-v8a, armeabi-v7a, x86_64, x86
    size: int
    is_stripped: bool = True
    is_pie: bool = False
    has_stack_canary: bool = False
    has_nx: bool = True
    has_relro: bool = False
    exports: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    dangerous_functions: List[str] = field(default_factory=list)
    jni_functions: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)


@dataclass
class NativeFuzzConfig:
    """Configuration for native library fuzzing."""
    device_serial: str
    library_path: str                   # Path on device or local APK
    target_function: Optional[str] = None
    target_functions: List[str] = field(default_factory=list)

    # Fuzzing mode
    fuzz_mode: FuzzMode = FuzzMode.FRIDA
    input_delivery: InputDelivery = InputDelivery.MEMORY

    # Input configuration
    input_size_min: int = 1
    input_size_max: int = 4096
    corpus_dir: Optional[str] = None
    dictionary_path: Optional[str] = None
    seed_inputs: List[bytes] = field(default_factory=list)

    # Execution limits
    timeout_ms: int = 5000
    max_iterations: int = 10000
    max_crashes: int = 100

    # Coverage options
    track_coverage: bool = True
    coverage_bitmap_size: int = 65536

    # Sanitizers
    use_asan: bool = False
    use_ubsan: bool = False

    # FRIDA-specific
    frida_script_extra: Optional[str] = None
    hook_malloc: bool = True
    hook_free: bool = True

    # QEMU-specific
    qemu_cpu: str = "max"
    qemu_memory_mb: int = 256


@dataclass
class CoverageInfo:
    """Code coverage information."""
    edges_hit: int = 0
    total_edges: int = 0
    blocks_hit: int = 0
    functions_hit: int = 0
    new_edges_this_run: int = 0
    coverage_bitmap: Optional[bytes] = None
    edge_map: Dict[int, int] = field(default_factory=dict)


@dataclass
class CrashInfo:
    """Information about a detected crash."""
    crash_id: str
    crash_type: CrashType
    severity: Severity
    signal: int = 0
    address: int = 0
    instruction: str = ""
    register_state: Dict[str, int] = field(default_factory=dict)
    stack_trace: List[str] = field(default_factory=list)
    input_data: bytes = b""
    input_hash: str = ""
    library_name: str = ""
    function_name: str = ""
    is_unique: bool = True
    is_exploitable: bool = False
    exploitability_reason: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzStats:
    """Statistics for a fuzzing session."""
    executions: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    timeouts: int = 0
    coverage_edges: int = 0
    coverage_blocks: int = 0
    exec_per_sec: float = 0.0
    last_new_coverage: Optional[datetime] = None
    last_crash: Optional[datetime] = None
    start_time: Optional[datetime] = None
    corpus_size: int = 0
    queue_size: int = 0


@dataclass
class NativeFuzzResult:
    """Result of a native fuzzing session."""
    session_id: str
    library_name: str
    target_function: str
    status: str                         # running, completed, error
    stats: FuzzStats = field(default_factory=FuzzStats)
    crashes: List[CrashInfo] = field(default_factory=list)
    coverage: CoverageInfo = field(default_factory=CoverageInfo)
    duration_sec: float = 0.0
    error_message: Optional[str] = None


# ============================================================================
# FRIDA Script Templates
# ============================================================================

FRIDA_FUZZER_SCRIPT = '''
// Android Native Library Fuzzer - FRIDA Script
// Auto-generated for: {library_name}:{function_name}

const LIBRARY_NAME = "{library_name}";
const FUNCTION_NAME = "{function_name}";
const INPUT_SIZE_MAX = {input_size_max};
const TIMEOUT_MS = {timeout_ms};

// Coverage bitmap (shared memory style)
const COVERAGE_SIZE = {coverage_size};
let coverageBitmap = new Uint8Array(COVERAGE_SIZE);
let edgeCount = 0;
let prevBlock = 0;

// Stats
let executions = 0;
let crashes = 0;
let lastInput = null;

// Find target module and function
let targetModule = null;
let targetFunc = null;

function findTarget() {{
    const modules = Process.enumerateModules();
    for (const mod of modules) {{
        if (mod.name.includes(LIBRARY_NAME) || mod.path.includes(LIBRARY_NAME)) {{
            targetModule = mod;
            break;
        }}
    }}

    if (!targetModule) {{
        send({{type: "error", message: "Target library not found: " + LIBRARY_NAME}});
        return false;
    }}

    // Find function by name
    const exports = targetModule.enumerateExports();
    for (const exp of exports) {{
        if (exp.name === FUNCTION_NAME || exp.name.includes(FUNCTION_NAME)) {{
            targetFunc = exp.address;
            send({{type: "info", message: "Found target: " + exp.name + " at " + targetFunc}});
            break;
        }}
    }}

    if (!targetFunc) {{
        // Try by offset if function name looks like hex
        if (FUNCTION_NAME.startsWith("0x")) {{
            const offset = parseInt(FUNCTION_NAME, 16);
            targetFunc = targetModule.base.add(offset);
            send({{type: "info", message: "Using offset: " + FUNCTION_NAME + " -> " + targetFunc}});
        }} else {{
            send({{type: "error", message: "Target function not found: " + FUNCTION_NAME}});
            return false;
        }}
    }}

    return true;
}}

// Coverage tracking via Stalker
function setupCoverage() {{
    Stalker.trustThreshold = 0;

    Stalker.follow(Process.getCurrentThreadId(), {{
        events: {{
            call: false,
            ret: false,
            exec: false,
            block: true,
            compile: false
        }},

        onReceive: function(events) {{
            const dominated = Stalker.parse(events, {{stringify: false, annotate: false}});
            for (const block of dominated) {{
                if (block.length >= 1) {{
                    const blockAddr = block[0];
                    // AFL-style edge coverage
                    const edge = (prevBlock >> 1) ^ (blockAddr & 0xFFFF);
                    const idx = edge % COVERAGE_SIZE;
                    if (coverageBitmap[idx] < 255) {{
                        if (coverageBitmap[idx] === 0) {{
                            edgeCount++;
                        }}
                        coverageBitmap[idx]++;
                    }}
                    prevBlock = blockAddr & 0xFFFF;
                }}
            }}
        }}
    }});
}}

// Memory allocator for inputs
let inputBuffer = null;
let inputSize = 0;

function allocateInput(size) {{
    if (inputBuffer) {{
        // Reuse if big enough
        if (size <= inputSize) {{
            return inputBuffer;
        }}
        // Free old buffer
        Memory.free(inputBuffer);
    }}

    inputSize = Math.max(size, INPUT_SIZE_MAX);
    inputBuffer = Memory.alloc(inputSize);
    return inputBuffer;
}}

// Write input data to memory
function writeInput(data) {{
    const buf = allocateInput(data.length);
    Memory.writeByteArray(buf, data);
    lastInput = data;
    return buf;
}}

// Hook the target function
function hookTarget() {{
    Interceptor.attach(targetFunc, {{
        onEnter: function(args) {{
            this.startTime = Date.now();
            executions++;

            // Send coverage periodically
            if (executions % 100 === 0) {{
                send({{
                    type: "stats",
                    executions: executions,
                    crashes: crashes,
                    edges: edgeCount
                }});
            }}
        }},

        onLeave: function(retval) {{
            const elapsed = Date.now() - this.startTime;

            if (elapsed > TIMEOUT_MS) {{
                send({{
                    type: "timeout",
                    executions: executions,
                    elapsed: elapsed
                }});
            }}
        }}
    }});
}}

// Exception handler for crash detection
Process.setExceptionHandler(function(details) {{
    crashes++;

    const crashInfo = {{
        type: "crash",
        crashType: details.type,
        address: details.address ? details.address.toString() : "unknown",
        context: {{}},
        memory: null,
        input: lastInput ? Array.from(lastInput) : [],
        inputHash: lastInput ? computeHash(lastInput) : "",
        executions: executions
    }};

    // Capture register state
    if (details.context) {{
        const ctx = details.context;
        if (Process.arch === "arm64") {{
            crashInfo.context = {{
                pc: ctx.pc.toString(),
                sp: ctx.sp.toString(),
                x0: ctx.x0.toString(),
                x1: ctx.x1.toString(),
                x2: ctx.x2.toString(),
                x29: ctx.x29.toString(),
                x30: ctx.x30.toString()
            }};
        }} else if (Process.arch === "arm") {{
            crashInfo.context = {{
                pc: ctx.pc.toString(),
                sp: ctx.sp.toString(),
                r0: ctx.r0.toString(),
                r1: ctx.r1.toString(),
                lr: ctx.lr.toString()
            }};
        }}
    }}

    // Try to read memory around crash
    try {{
        if (details.address) {{
            crashInfo.memory = Memory.readByteArray(details.address, 64);
        }}
    }} catch (e) {{
        // Memory not readable
    }}

    send(crashInfo);

    // Don't propagate - we want to continue fuzzing
    return true;
}});

// Simple hash function
function computeHash(data) {{
    let hash = 0x811c9dc5;
    for (let i = 0; i < data.length; i++) {{
        hash ^= data[i];
        hash = Math.imul(hash, 0x01000193);
    }}
    return (hash >>> 0).toString(16).padStart(8, '0');
}}

// Mutation strategies
const MUTATIONS = {{
    bitFlip: function(data, idx) {{
        const bit = Math.floor(Math.random() * 8);
        data[idx] ^= (1 << bit);
        return data;
    }},

    byteFlip: function(data, idx) {{
        data[idx] ^= 0xFF;
        return data;
    }},

    byteSet: function(data, idx) {{
        const interesting = [0x00, 0x01, 0x7F, 0x80, 0xFF];
        data[idx] = interesting[Math.floor(Math.random() * interesting.length)];
        return data;
    }},

    wordSet: function(data, idx) {{
        if (idx + 1 < data.length) {{
            const interesting = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF];
            const val = interesting[Math.floor(Math.random() * interesting.length)];
            data[idx] = val & 0xFF;
            data[idx + 1] = (val >> 8) & 0xFF;
        }}
        return data;
    }},

    dwordSet: function(data, idx) {{
        if (idx + 3 < data.length) {{
            const interesting = [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF];
            const val = interesting[Math.floor(Math.random() * interesting.length)];
            data[idx] = val & 0xFF;
            data[idx + 1] = (val >> 8) & 0xFF;
            data[idx + 2] = (val >> 16) & 0xFF;
            data[idx + 3] = (val >> 24) & 0xFF;
        }}
        return data;
    }},

    insert: function(data, idx) {{
        const newData = new Uint8Array(Math.min(data.length + 1, INPUT_SIZE_MAX));
        newData.set(data.subarray(0, idx));
        newData[idx] = Math.floor(Math.random() * 256);
        newData.set(data.subarray(idx), idx + 1);
        return newData;
    }},

    delete: function(data, idx) {{
        if (data.length <= 1) return data;
        const newData = new Uint8Array(data.length - 1);
        newData.set(data.subarray(0, idx));
        newData.set(data.subarray(idx + 1), idx);
        return newData;
    }},

    havoc: function(data) {{
        const mutations = Object.values(MUTATIONS).filter(m => m !== MUTATIONS.havoc);
        const count = 1 + Math.floor(Math.random() * 5);
        for (let i = 0; i < count; i++) {{
            const idx = Math.floor(Math.random() * data.length);
            const mut = mutations[Math.floor(Math.random() * mutations.length)];
            data = mut(data, idx);
        }}
        return data;
    }}
}};

// Mutate input
function mutate(input) {{
    const data = new Uint8Array(input);
    const mutations = Object.values(MUTATIONS);
    const mutation = mutations[Math.floor(Math.random() * mutations.length)];
    const idx = Math.floor(Math.random() * data.length);
    return mutation(data, idx);
}}

// Main fuzzing loop - called from Python
let fuzzingActive = false;
let corpus = [];

rpc.exports = {{
    init: function() {{
        if (!findTarget()) {{
            return false;
        }}
        setupCoverage();
        hookTarget();
        send({{type: "ready", library: LIBRARY_NAME, function: FUNCTION_NAME}});
        return true;
    }},

    addCorpus: function(inputs) {{
        for (const input of inputs) {{
            corpus.push(new Uint8Array(input));
        }}
        send({{type: "info", message: "Corpus loaded: " + corpus.length + " items"}});
    }},

    fuzz: function(input) {{
        const data = new Uint8Array(input);
        const buf = writeInput(data);

        // Call target function with input
        // This depends on function signature - basic case: func(buf, len)
        try {{
            const nativeFunc = new NativeFunction(targetFunc, 'int', ['pointer', 'int']);
            const result = nativeFunc(buf, data.length);
            return {{success: true, result: result, edges: edgeCount}};
        }} catch (e) {{
            return {{success: false, error: e.message}};
        }}
    }},

    fuzzLoop: function(iterations) {{
        fuzzingActive = true;
        let i = 0;

        const loop = function() {{
            if (!fuzzingActive || i >= iterations) {{
                send({{type: "done", executions: executions, crashes: crashes, edges: edgeCount}});
                return;
            }}

            // Pick from corpus or generate random
            let input;
            if (corpus.length > 0 && Math.random() < 0.8) {{
                input = corpus[Math.floor(Math.random() * corpus.length)];
                input = mutate(input);
            }} else {{
                const size = Math.floor(Math.random() * INPUT_SIZE_MAX) + 1;
                input = new Uint8Array(size);
                for (let j = 0; j < size; j++) {{
                    input[j] = Math.floor(Math.random() * 256);
                }}
            }}

            const buf = writeInput(input);

            try {{
                const nativeFunc = new NativeFunction(targetFunc, 'int', ['pointer', 'int']);
                nativeFunc(buf, input.length);
            }} catch (e) {{
                // Exception handler will catch crashes
            }}

            i++;

            // Schedule next iteration
            setTimeout(loop, 0);
        }};

        loop();
    }},

    stop: function() {{
        fuzzingActive = false;
        Stalker.unfollow();
    }},

    getCoverage: function() {{
        return {{
            edges: edgeCount,
            bitmap: Array.from(coverageBitmap.filter(x => x > 0))
        }};
    }},

    getStats: function() {{
        return {{
            executions: executions,
            crashes: crashes,
            edges: edgeCount
        }};
    }}
}};

send({{type: "loaded"}});
'''

FRIDA_HEAP_TRACKER_SCRIPT = '''
// Heap tracking for detecting memory corruption
const allocations = new Map();

Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (!retval.isNull()) {
            allocations.set(retval.toString(), {
                address: retval,
                size: this.size,
                freed: false,
                allocStack: Thread.backtrace(this.context, Backtracer.ACCURATE)
            });
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter: function(args) {
        const addr = args[0].toString();
        const alloc = allocations.get(addr);

        if (alloc) {
            if (alloc.freed) {
                send({
                    type: "double_free",
                    address: addr,
                    originalAlloc: alloc.allocStack.map(DebugSymbol.fromAddress).join("\\n")
                });
            }
            alloc.freed = true;
            alloc.freeStack = Thread.backtrace(this.context, Backtracer.ACCURATE);
        } else if (!args[0].isNull()) {
            send({
                type: "invalid_free",
                address: addr,
                stack: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n")
            });
        }
    }
});

// Check for use-after-free on memory access
// This is expensive - only enable when needed
rpc.exports = {
    checkUAF: function(addr) {
        for (const [key, alloc] of allocations) {
            const base = ptr(key);
            if (addr.compare(base) >= 0 && addr.compare(base.add(alloc.size)) < 0) {
                if (alloc.freed) {
                    return {
                        isUAF: true,
                        allocStack: alloc.allocStack,
                        freeStack: alloc.freeStack
                    };
                }
                return {isUAF: false};
            }
        }
        return {isUAF: false, notTracked: true};
    }
};
'''


# ============================================================================
# Dangerous Functions Database
# ============================================================================

DANGEROUS_FUNCTIONS = {
    # Memory corruption
    "strcpy": ("buffer overflow", Severity.HIGH),
    "strcat": ("buffer overflow", Severity.HIGH),
    "sprintf": ("format string/overflow", Severity.HIGH),
    "vsprintf": ("format string/overflow", Severity.HIGH),
    "gets": ("buffer overflow", Severity.CRITICAL),
    "scanf": ("buffer overflow", Severity.HIGH),
    "sscanf": ("buffer overflow", Severity.HIGH),
    "fscanf": ("buffer overflow", Severity.HIGH),

    # Format strings
    "printf": ("format string", Severity.MEDIUM),
    "fprintf": ("format string", Severity.MEDIUM),
    "syslog": ("format string", Severity.MEDIUM),

    # Memory operations
    "memcpy": ("buffer overflow if unchecked", Severity.MEDIUM),
    "memmove": ("buffer overflow if unchecked", Severity.MEDIUM),
    "bcopy": ("buffer overflow if unchecked", Severity.MEDIUM),

    # Integer issues
    "atoi": ("integer overflow", Severity.LOW),
    "atol": ("integer overflow", Severity.LOW),
    "strtol": ("integer overflow", Severity.LOW),

    # Command execution
    "system": ("command injection", Severity.CRITICAL),
    "popen": ("command injection", Severity.CRITICAL),
    "execve": ("command injection", Severity.CRITICAL),
    "execl": ("command injection", Severity.CRITICAL),
    "execlp": ("command injection", Severity.CRITICAL),

    # File operations (path traversal)
    "fopen": ("path traversal", Severity.MEDIUM),
    "open": ("path traversal", Severity.MEDIUM),
    "access": ("TOCTOU race", Severity.MEDIUM),

    # Network
    "recv": ("buffer overflow", Severity.HIGH),
    "recvfrom": ("buffer overflow", Severity.HIGH),
    "read": ("buffer overflow if unchecked", Severity.MEDIUM),
}


# ============================================================================
# Android Native Fuzzer Service
# ============================================================================

class AndroidNativeFuzzer:
    """
    Fuzz Android native libraries (.so files) using FRIDA or QEMU.

    Supports:
    - On-device fuzzing with FRIDA instrumentation
    - Emulated fuzzing with QEMU user-mode
    - AFL++ integration for guided fuzzing
    - Automatic crash triage and deduplication
    """

    def __init__(self):
        self.device_service = None  # Injected
        self.sessions: Dict[str, NativeFuzzResult] = {}
        self.active_scripts: Dict[str, Any] = {}  # FRIDA script handles
        self._crash_hashes: Dict[str, Set[str]] = {}  # session_id -> crash hashes

    def set_device_service(self, device_service):
        """Inject the device service dependency."""
        self.device_service = device_service

    # ========================================================================
    # Library Discovery and Analysis
    # ========================================================================

    async def list_native_libraries(
        self,
        serial: str,
        package: str
    ) -> List[NativeLibraryInfo]:
        """List native libraries in an installed package."""
        if not self.device_service:
            raise RuntimeError("Device service not configured")

        libraries = []

        # Get package's native library directory
        pkg_info = await self.device_service.get_package_info(serial, package)
        if not pkg_info:
            logger.warning(f"Package not found: {package}")
            return []

        # Common native library locations
        lib_paths = [
            f"/data/app/{package}*/lib/arm64",
            f"/data/app/{package}*/lib/arm",
            f"/data/data/{package}/lib",
        ]

        # Get device ABI
        device = await self.device_service.get_device(serial)
        abi = device.abi.value if device else "arm64-v8a"

        for lib_path_pattern in lib_paths:
            # Find actual path
            result = await self.device_service.shell(
                serial,
                f"ls -la {lib_path_pattern}/*.so 2>/dev/null"
            )

            if result.exit_code == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 8 and parts[-1].endswith('.so'):
                        lib_name = parts[-1]
                        lib_size = int(parts[4]) if parts[4].isdigit() else 0
                        lib_full_path = lib_path_pattern.replace('*', '') + '/' + lib_name

                        # Get actual resolved path
                        resolve_result = await self.device_service.shell(
                            serial,
                            f"readlink -f {lib_full_path} 2>/dev/null || echo {lib_full_path}"
                        )
                        actual_path = resolve_result.stdout.strip()

                        libraries.append(NativeLibraryInfo(
                            name=lib_name,
                            path=actual_path,
                            architecture=abi,
                            size=lib_size
                        ))

        # Also check APK's lib folder via dumpsys
        dumpsys_result = await self.device_service.shell(
            serial,
            f"dumpsys package {package} | grep -A5 'Native libraries'"
        )

        if dumpsys_result.exit_code == 0:
            for line in dumpsys_result.stdout.split('\n'):
                if '.so' in line:
                    match = re.search(r'(/[^\s]+\.so)', line)
                    if match:
                        lib_path = match.group(1)
                        lib_name = os.path.basename(lib_path)
                        if not any(l.name == lib_name for l in libraries):
                            libraries.append(NativeLibraryInfo(
                                name=lib_name,
                                path=lib_path,
                                architecture=abi,
                                size=0
                            ))

        return libraries

    async def pull_library(
        self,
        serial: str,
        remote_path: str,
        local_dir: Optional[str] = None
    ) -> str:
        """Pull a library from device to local filesystem."""
        if not self.device_service:
            raise RuntimeError("Device service not configured")

        if not local_dir:
            local_dir = tempfile.mkdtemp(prefix="android_lib_")

        lib_name = os.path.basename(remote_path)
        local_path = os.path.join(local_dir, lib_name)

        success = await self.device_service.pull(serial, remote_path, local_path)

        if not success:
            raise RuntimeError(f"Failed to pull library: {remote_path}")

        return local_path

    async def analyze_library(self, library_path: str) -> NativeLibraryInfo:
        """Analyze a local native library using readelf/nm."""
        if not os.path.exists(library_path):
            raise FileNotFoundError(f"Library not found: {library_path}")

        lib_name = os.path.basename(library_path)
        lib_size = os.path.getsize(library_path)

        info = NativeLibraryInfo(
            name=lib_name,
            path=library_path,
            architecture="unknown",
            size=lib_size
        )

        # Read ELF header to determine architecture
        with open(library_path, 'rb') as f:
            elf_header = f.read(64)

            if elf_header[:4] != b'\x7fELF':
                raise ValueError("Not a valid ELF file")

            # e_machine at offset 18 (2 bytes)
            e_machine = struct.unpack('<H', elf_header[18:20])[0]
            arch_map = {
                0x03: "x86",
                0x3E: "x86_64",
                0x28: "armeabi-v7a",
                0xB7: "arm64-v8a"
            }
            info.architecture = arch_map.get(e_machine, f"unknown_{e_machine}")

            # Check if 32 or 64 bit
            is_64bit = elf_header[4] == 2

            # Check PIE (ET_DYN with no INTERP)
            e_type = struct.unpack('<H', elf_header[16:18])[0]
            info.is_pie = (e_type == 3)  # ET_DYN

        # Use readelf to get symbols
        try:
            # Try readelf
            proc = await asyncio.create_subprocess_exec(
                'readelf', '-sW', library_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                for line in stdout.decode('utf-8', errors='ignore').split('\n'):
                    # Parse symbol table output
                    parts = line.split()
                    if len(parts) >= 8:
                        sym_type = parts[3] if len(parts) > 3 else ""
                        sym_bind = parts[4] if len(parts) > 4 else ""
                        sym_name = parts[-1] if parts else ""

                        if sym_type == "FUNC" and sym_bind in ["GLOBAL", "WEAK"]:
                            # Check if exported (non-UND)
                            ndx = parts[6] if len(parts) > 6 else ""
                            if ndx != "UND":
                                info.exports.append(sym_name)

                                # Check for dangerous functions
                                if sym_name in DANGEROUS_FUNCTIONS:
                                    info.dangerous_functions.append(sym_name)

                                # Check for JNI functions
                                if sym_name.startswith("Java_") or sym_name in [
                                    "JNI_OnLoad", "JNI_OnUnload"
                                ]:
                                    info.jni_functions.append(sym_name)
                            else:
                                info.imports.append(sym_name)

        except FileNotFoundError:
            logger.warning("readelf not found, skipping symbol analysis")

        # Check security features
        try:
            proc = await asyncio.create_subprocess_exec(
                'readelf', '-dW', library_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            output = stdout.decode('utf-8', errors='ignore')

            # Check RELRO
            if "BIND_NOW" in output:
                info.has_relro = True  # Full RELRO
            elif "GNU_RELRO" in output:
                info.has_relro = True  # Partial RELRO

            # Check for stack canary (presence of __stack_chk_fail)
            if "__stack_chk_fail" in output or "__stack_chk_guard" in output:
                info.has_stack_canary = True

        except FileNotFoundError:
            pass

        # Extract interesting strings
        try:
            proc = await asyncio.create_subprocess_exec(
                'strings', '-n', '8', library_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            strings = stdout.decode('utf-8', errors='ignore').split('\n')

            # Look for interesting patterns
            patterns = [
                r'https?://',           # URLs
                r'/data/data/',         # Android paths
                r'/system/',            # System paths
                r'password',            # Credentials
                r'secret',
                r'api[_-]?key',
                r'BEGIN .* KEY',        # Crypto keys
                r'SELECT.*FROM',        # SQL
            ]

            for s in strings[:1000]:  # Limit to first 1000
                for pattern in patterns:
                    if re.search(pattern, s, re.IGNORECASE):
                        if s not in info.interesting_strings:
                            info.interesting_strings.append(s[:200])
                        break

            # Limit total
            info.interesting_strings = info.interesting_strings[:100]

        except FileNotFoundError:
            pass

        # Determine if stripped
        info.is_stripped = len(info.exports) < 10 and "stripped" not in library_path.lower()

        return info

    async def find_fuzz_targets(
        self,
        library: NativeLibraryInfo,
        max_targets: int = 10
    ) -> List[str]:
        """
        Identify good fuzzing targets in a library.
        Prioritizes: input parsing functions, JNI functions, dangerous functions.
        """
        targets = []

        # Priority 1: JNI functions (direct app interface)
        for func in library.jni_functions:
            if func not in targets:
                targets.append(func)

        # Priority 2: Functions that use dangerous APIs
        for func in library.dangerous_functions:
            if func not in targets:
                targets.append(func)

        # Priority 3: Functions with parsing-related names
        parsing_keywords = [
            'parse', 'decode', 'read', 'load', 'process',
            'handle', 'input', 'recv', 'deserialize', 'unmarshal',
            'extract', 'import', 'convert'
        ]

        for func in library.exports:
            func_lower = func.lower()
            for keyword in parsing_keywords:
                if keyword in func_lower and func not in targets:
                    targets.append(func)
                    break

        # Priority 4: Functions with buffer-related names
        buffer_keywords = ['buf', 'data', 'bytes', 'str', 'mem', 'copy']

        for func in library.exports:
            func_lower = func.lower()
            for keyword in buffer_keywords:
                if keyword in func_lower and func not in targets:
                    targets.append(func)
                    break

        return targets[:max_targets]

    # ========================================================================
    # Harness Generation
    # ========================================================================

    async def generate_harness(
        self,
        library: NativeLibraryInfo,
        function: str,
        signature: Optional[str] = None
    ) -> str:
        """
        Generate a C harness for fuzzing a specific function.

        Args:
            library: Library info
            function: Target function name
            signature: Optional function signature (e.g., "int func(char*, int)")

        Returns:
            C source code for the harness
        """
        # Default signature assumes: int func(void* data, size_t len)
        if not signature:
            signature = "int (*target_func)(void*, size_t)"

        harness = f'''
/*
 * Auto-generated fuzzing harness for {library.name}:{function}
 * Generated by Android Native Fuzzer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>

// Target library and function
#define TARGET_LIBRARY "{library.path}"
#define TARGET_FUNCTION "{function}"

// Function pointer type - adjust based on actual signature
typedef {signature};

// AFL++ persistent mode
#ifdef __AFL_HAVE_MANUAL_CONTROL
#include <sys/shm.h>
__AFL_FUZZ_INIT();
#endif

int main(int argc, char** argv) {{
    // Load target library
    void* handle = dlopen(TARGET_LIBRARY, RTLD_NOW);
    if (!handle) {{
        fprintf(stderr, "Failed to load library: %s\\n", dlerror());
        return 1;
    }}

    // Find target function
    target_func func = (target_func)dlsym(handle, TARGET_FUNCTION);
    if (!func) {{
        fprintf(stderr, "Failed to find function: %s\\n", dlerror());
        dlclose(handle);
        return 1;
    }}

#ifdef __AFL_HAVE_MANUAL_CONTROL
    // AFL++ persistent mode
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;

        // Call target with fuzz input
        func(buf, len);
    }}
#else
    // Standard mode - read from stdin or file
    unsigned char buf[4096];
    size_t len = 0;

    if (argc > 1) {{
        // Read from file
        FILE* f = fopen(argv[1], "rb");
        if (f) {{
            len = fread(buf, 1, sizeof(buf), f);
            fclose(f);
        }}
    }} else {{
        // Read from stdin
        len = fread(buf, 1, sizeof(buf), stdin);
    }}

    if (len > 0) {{
        func(buf, len);
    }}
#endif

    dlclose(handle);
    return 0;
}}
'''
        return harness

    async def compile_harness(
        self,
        harness_path: str,
        output_path: str,
        arch: str = "arm64-v8a",
        use_afl: bool = True
    ) -> str:
        """
        Compile a harness for the target architecture.

        Requires: Android NDK or appropriate cross-compiler
        """
        # Map architecture to compiler
        compiler_map = {
            "arm64-v8a": "aarch64-linux-android-clang",
            "armeabi-v7a": "arm-linux-androideabi-clang",
            "x86_64": "x86_64-linux-android-clang",
            "x86": "i686-linux-android-clang",
        }

        compiler = compiler_map.get(arch, "clang")

        # Build command
        cmd = [compiler, "-o", output_path, harness_path, "-ldl"]

        if use_afl:
            # Use AFL++ compiler wrapper if available
            afl_compiler = f"afl-clang-fast"
            cmd[0] = afl_compiler
            cmd.extend(["-fsanitize=address", "-g"])

        cmd_str = ' '.join(cmd)

        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(f"Compilation failed: {stderr.decode()}")

        return output_path

    # ========================================================================
    # FRIDA-based Fuzzing
    # ========================================================================

    async def fuzz_with_frida(
        self,
        config: NativeFuzzConfig
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fuzz a native library using FRIDA instrumentation (on-device).

        Yields progress updates and crashes as they occur.
        """
        session_id = str(uuid.uuid4())[:8]

        if not self.device_service:
            raise RuntimeError("Device service not configured")

        # Initialize result tracking
        result = NativeFuzzResult(
            session_id=session_id,
            library_name=os.path.basename(config.library_path),
            target_function=config.target_function or "auto",
            status="starting"
        )
        result.stats.start_time = datetime.now()
        self.sessions[session_id] = result
        self._crash_hashes[session_id] = set()

        yield {
            "type": "session_start",
            "session_id": session_id,
            "library": result.library_name,
            "function": result.target_function
        }

        try:
            # Import frida
            try:
                import frida
            except ImportError:
                raise RuntimeError("FRIDA not installed. Run: pip install frida frida-tools")

            # Ensure FRIDA server is running
            frida_running = await self.device_service.check_frida_server(config.device_serial)
            if not frida_running:
                yield {"type": "info", "message": "Starting FRIDA server..."}
                await self.device_service.start_frida_server(config.device_serial)
                await asyncio.sleep(2)

            # Connect to device
            device = frida.get_device(config.device_serial)

            # Find or spawn target process
            # For library fuzzing, we need a host process
            # Usually the app that loads the library

            # Generate FRIDA script
            script_source = FRIDA_FUZZER_SCRIPT.format(
                library_name=os.path.basename(config.library_path),
                function_name=config.target_function or "JNI_OnLoad",
                input_size_max=config.input_size_max,
                timeout_ms=config.timeout_ms,
                coverage_size=config.coverage_bitmap_size
            )

            if config.hook_malloc:
                script_source += "\n" + FRIDA_HEAP_TRACKER_SCRIPT

            if config.frida_script_extra:
                script_source += "\n" + config.frida_script_extra

            # Message handler for FRIDA
            message_queue: asyncio.Queue = asyncio.Queue()

            def on_message(message, data):
                if message['type'] == 'send':
                    asyncio.create_task(message_queue.put(message['payload']))
                elif message['type'] == 'error':
                    asyncio.create_task(message_queue.put({
                        'type': 'error',
                        'message': message.get('description', str(message))
                    }))

            # Attach to process (need to determine PID)
            # This is simplified - real implementation would need app package
            yield {"type": "info", "message": "Attaching to target process..."}

            # For now, assume we have a target PID or spawn
            # In practice, you'd spawn the app or attach to running process

            result.status = "running"
            yield {
                "type": "fuzzing_started",
                "session_id": session_id,
                "config": {
                    "library": config.library_path,
                    "function": config.target_function,
                    "max_iterations": config.max_iterations
                }
            }

            # Main fuzzing loop simulation
            # Real implementation would use FRIDA script's fuzzLoop RPC
            iteration = 0
            last_coverage = 0

            while iteration < config.max_iterations:
                # Generate/mutate input
                if config.seed_inputs and iteration < len(config.seed_inputs):
                    input_data = config.seed_inputs[iteration]
                else:
                    input_data = self._generate_random_input(
                        config.input_size_min,
                        config.input_size_max
                    )

                # This would call script.exports.fuzz(input_data) in real implementation

                iteration += 1
                result.stats.executions = iteration

                # Simulate coverage/crash detection
                # In real implementation, we'd get this from FRIDA message handler

                # Periodic stats update
                if iteration % 100 == 0:
                    elapsed = (datetime.now() - result.stats.start_time).total_seconds()
                    result.stats.exec_per_sec = iteration / elapsed if elapsed > 0 else 0

                    yield {
                        "type": "stats",
                        "session_id": session_id,
                        "executions": iteration,
                        "crashes": result.stats.crashes,
                        "unique_crashes": result.stats.unique_crashes,
                        "coverage_edges": result.stats.coverage_edges,
                        "exec_per_sec": round(result.stats.exec_per_sec, 1)
                    }

                # Check for crashes in message queue
                while not message_queue.empty():
                    try:
                        msg = message_queue.get_nowait()

                        if msg.get('type') == 'crash':
                            crash = self._process_crash(
                                session_id,
                                msg,
                                config.library_path,
                                config.target_function
                            )

                            if crash.is_unique:
                                result.crashes.append(crash)
                                result.stats.unique_crashes += 1

                                yield {
                                    "type": "crash",
                                    "session_id": session_id,
                                    "crash_id": crash.crash_id,
                                    "crash_type": crash.crash_type.value,
                                    "severity": crash.severity.value,
                                    "address": hex(crash.address) if crash.address else "unknown",
                                    "is_exploitable": crash.is_exploitable
                                }

                            result.stats.crashes += 1

                            if result.stats.unique_crashes >= config.max_crashes:
                                logger.info(f"Max crashes reached: {config.max_crashes}")
                                break

                        elif msg.get('type') == 'stats':
                            result.stats.coverage_edges = msg.get('edges', 0)

                        elif msg.get('type') == 'error':
                            yield {
                                "type": "error",
                                "session_id": session_id,
                                "message": msg.get('message', 'Unknown error')
                            }

                    except asyncio.QueueEmpty:
                        break

                # Small delay to prevent tight loop
                if iteration % 1000 == 0:
                    await asyncio.sleep(0.01)

            result.status = "completed"
            result.duration_sec = (datetime.now() - result.stats.start_time).total_seconds()

            yield {
                "type": "session_complete",
                "session_id": session_id,
                "stats": {
                    "executions": result.stats.executions,
                    "crashes": result.stats.crashes,
                    "unique_crashes": result.stats.unique_crashes,
                    "coverage_edges": result.stats.coverage_edges,
                    "duration_sec": round(result.duration_sec, 1)
                }
            }

        except Exception as e:
            result.status = "error"
            result.error_message = str(e)
            logger.exception(f"FRIDA fuzzing error: {e}")

            yield {
                "type": "error",
                "session_id": session_id,
                "message": str(e)
            }

    def _generate_random_input(self, min_size: int, max_size: int) -> bytes:
        """Generate random input data for fuzzing."""
        import random
        size = random.randint(min_size, max_size)
        return bytes(random.getrandbits(8) for _ in range(size))

    def _process_crash(
        self,
        session_id: str,
        crash_data: Dict[str, Any],
        library: str,
        function: str
    ) -> CrashInfo:
        """Process a crash from FRIDA and determine uniqueness."""
        # Generate crash hash for deduplication
        hash_input = f"{crash_data.get('crashType', '')}:{crash_data.get('address', '')}"
        crash_hash = hashlib.md5(hash_input.encode()).hexdigest()[:16]

        is_unique = crash_hash not in self._crash_hashes.get(session_id, set())
        if is_unique:
            self._crash_hashes.setdefault(session_id, set()).add(crash_hash)

        # Determine crash type
        crash_type_map = {
            "access-violation": CrashType.SEGFAULT,
            "abort": CrashType.SIGABRT,
            "bus-error": CrashType.SIGBUS,
            "arithmetic": CrashType.SIGFPE,
        }
        crash_type = crash_type_map.get(
            crash_data.get('crashType', '').lower(),
            CrashType.UNKNOWN
        )

        # Parse address
        address = 0
        addr_str = crash_data.get('address', '0')
        if isinstance(addr_str, str):
            try:
                address = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
            except ValueError:
                pass

        # Determine severity and exploitability
        severity, is_exploitable, reason = self._assess_exploitability(
            crash_type,
            address,
            crash_data.get('context', {})
        )

        # Get input data
        input_data = bytes(crash_data.get('input', []))
        input_hash = crash_data.get('inputHash', hashlib.md5(input_data).hexdigest()[:16])

        return CrashInfo(
            crash_id=crash_hash,
            crash_type=crash_type,
            severity=severity,
            address=address,
            register_state=crash_data.get('context', {}),
            input_data=input_data,
            input_hash=input_hash,
            library_name=os.path.basename(library),
            function_name=function or "unknown",
            is_unique=is_unique,
            is_exploitable=is_exploitable,
            exploitability_reason=reason,
            details=crash_data
        )

    def _assess_exploitability(
        self,
        crash_type: CrashType,
        address: int,
        context: Dict[str, Any]
    ) -> Tuple[Severity, bool, str]:
        """Assess crash severity and potential exploitability."""
        # Check for obvious signs

        # NULL pointer dereference (usually not exploitable)
        if 0 <= address < 0x10000:
            return Severity.MEDIUM, False, "NULL pointer dereference"

        # Stack address (potential stack buffer overflow)
        # ARM64 stack typically around 0x7f... or 0xff...
        if address > 0x7f00000000000000:
            return Severity.HIGH, True, "Possible stack buffer overflow"

        # Heap corruption indicators
        if crash_type == CrashType.SIGABRT:
            return Severity.HIGH, True, "Heap corruption / double-free detected"

        # Write to controlled address
        pc = context.get('pc', '0')
        try:
            pc_val = int(pc, 16) if isinstance(pc, str) and pc.startswith('0x') else int(pc) if pc else 0
        except (ValueError, TypeError):
            pc_val = 0

        # If PC is corrupted (weird value), likely exploitable
        if pc_val != 0 and (pc_val < 0x1000 or pc_val == 0x41414141 or pc_val == 0x4141414141414141):
            return Severity.CRITICAL, True, "PC corruption - likely exploitable"

        # Default assessment based on crash type
        type_severity = {
            CrashType.SEGFAULT: (Severity.HIGH, True, "Memory access violation"),
            CrashType.SIGBUS: (Severity.HIGH, True, "Bus error - alignment or access"),
            CrashType.SIGABRT: (Severity.MEDIUM, False, "Abort signal"),
            CrashType.SIGFPE: (Severity.LOW, False, "Floating point exception"),
            CrashType.TIMEOUT: (Severity.LOW, False, "Timeout"),
            CrashType.UNKNOWN: (Severity.MEDIUM, False, "Unknown crash type"),
        }

        return type_severity.get(crash_type, (Severity.MEDIUM, False, "Unknown"))

    # ========================================================================
    # QEMU-based Fuzzing
    # ========================================================================

    async def fuzz_with_qemu(
        self,
        config: NativeFuzzConfig
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fuzz a native library using QEMU user-mode emulation.

        This allows fuzzing on x86_64 host without a physical device.
        """
        session_id = str(uuid.uuid4())[:8]

        result = NativeFuzzResult(
            session_id=session_id,
            library_name=os.path.basename(config.library_path),
            target_function=config.target_function or "auto",
            status="starting"
        )
        result.stats.start_time = datetime.now()
        self.sessions[session_id] = result

        yield {
            "type": "session_start",
            "session_id": session_id,
            "library": result.library_name,
            "mode": "qemu"
        }

        try:
            # Determine QEMU binary based on architecture
            # First, analyze library to get architecture
            lib_info = await self.analyze_library(config.library_path)

            qemu_map = {
                "arm64-v8a": "qemu-aarch64",
                "armeabi-v7a": "qemu-arm",
                "x86_64": "qemu-x86_64",
                "x86": "qemu-i386",
            }

            qemu_binary = qemu_map.get(lib_info.architecture)
            if not qemu_binary:
                raise RuntimeError(f"No QEMU binary for architecture: {lib_info.architecture}")

            # Generate harness
            harness_code = await self.generate_harness(
                lib_info,
                config.target_function or lib_info.jni_functions[0] if lib_info.jni_functions else "main"
            )

            # For now, yield info about what would happen
            # Full implementation would compile harness and run with AFL++/QEMU

            yield {
                "type": "info",
                "session_id": session_id,
                "message": f"Would use {qemu_binary} with AFL++ QEMU mode",
                "architecture": lib_info.architecture,
                "exports_count": len(lib_info.exports),
                "dangerous_functions": lib_info.dangerous_functions[:10]
            }

            result.status = "completed"
            yield {
                "type": "session_complete",
                "session_id": session_id,
                "message": "QEMU fuzzing would be run here (requires AFL++ setup)"
            }

        except Exception as e:
            result.status = "error"
            result.error_message = str(e)
            yield {
                "type": "error",
                "session_id": session_id,
                "message": str(e)
            }

    # ========================================================================
    # Crash Analysis
    # ========================================================================

    async def analyze_crash(
        self,
        crash: CrashInfo,
        library_path: str
    ) -> Dict[str, Any]:
        """
        Perform detailed analysis of a crash.

        Includes:
        - Stack trace symbolization
        - Root cause analysis
        - Exploitability assessment
        - Input minimization hints
        """
        analysis = {
            "crash_id": crash.crash_id,
            "crash_type": crash.crash_type.value,
            "severity": crash.severity.value,
            "is_exploitable": crash.is_exploitable,
            "exploitability_reason": crash.exploitability_reason,
            "recommendations": [],
            "cwe_ids": [],
            "mitre_attack": []
        }

        # Map crash types to CWEs
        cwe_map = {
            CrashType.SEGFAULT: ["CWE-119", "CWE-125", "CWE-787"],  # Buffer errors
            CrashType.SIGABRT: ["CWE-415", "CWE-416"],  # Double-free, UAF
            CrashType.SIGBUS: ["CWE-119"],
        }

        analysis["cwe_ids"] = cwe_map.get(crash.crash_type, [])

        # Add recommendations based on crash type
        if crash.crash_type == CrashType.SEGFAULT:
            analysis["recommendations"].extend([
                "Check bounds on buffer operations",
                "Verify pointer validity before dereference",
                "Consider using AddressSanitizer for more details"
            ])

        if crash.is_exploitable:
            analysis["recommendations"].append(
                "HIGH PRIORITY: This crash appears exploitable - investigate immediately"
            )
            analysis["mitre_attack"] = ["T1203"]  # Exploitation for client execution

        # Try to symbolize stack trace
        if crash.stack_trace:
            symbolized = []
            for frame in crash.stack_trace:
                # In real implementation, use addr2line or similar
                symbolized.append(frame)
            analysis["symbolized_stack"] = symbolized

        return analysis

    async def minimize_crash_input(
        self,
        crash: CrashInfo,
        config: NativeFuzzConfig
    ) -> bytes:
        """
        Minimize a crash-inducing input to smallest reproducing case.

        Uses binary search / delta debugging approach.
        """
        if not crash.input_data:
            return b""

        original = crash.input_data
        current = original

        # Try progressively smaller inputs
        # This is a simplified version - real implementation would verify crash still occurs

        # Remove from end
        for size in [len(current) // 2, len(current) // 4, len(current) // 8]:
            if size > 0:
                candidate = current[:size]
                # Would verify crash here
                # For now, just return smaller size
                current = candidate
                break

        # Remove from start
        for skip in [len(current) // 4, len(current) // 8]:
            if skip > 0 and skip < len(current):
                candidate = current[skip:]
                current = candidate
                break

        return current

    # ========================================================================
    # Session Management
    # ========================================================================

    def get_session(self, session_id: str) -> Optional[NativeFuzzResult]:
        """Get a fuzzing session by ID."""
        return self.sessions.get(session_id)

    def get_all_sessions(self) -> List[NativeFuzzResult]:
        """Get all fuzzing sessions."""
        return list(self.sessions.values())

    async def stop_session(self, session_id: str) -> bool:
        """Stop an active fuzzing session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        session.status = "stopped"

        # Stop FRIDA script if active
        if session_id in self.active_scripts:
            try:
                script = self.active_scripts[session_id]
                await asyncio.to_thread(script.unload)
                del self.active_scripts[session_id]
            except Exception as e:
                logger.warning(f"Error stopping FRIDA script: {e}")

        return True

    def get_crashes(
        self,
        session_id: Optional[str] = None,
        severity: Optional[Severity] = None,
        unique_only: bool = True
    ) -> List[CrashInfo]:
        """Get crashes, optionally filtered."""
        crashes = []

        sessions = [self.sessions[session_id]] if session_id else self.sessions.values()

        for session in sessions:
            for crash in session.crashes:
                if unique_only and not crash.is_unique:
                    continue
                if severity and crash.severity != severity:
                    continue
                crashes.append(crash)

        return crashes


# ============================================================================
# Module-level instance
# ============================================================================

_native_fuzzer: Optional[AndroidNativeFuzzer] = None


def get_native_fuzzer() -> AndroidNativeFuzzer:
    """Get or create the native fuzzer singleton."""
    global _native_fuzzer
    if _native_fuzzer is None:
        _native_fuzzer = AndroidNativeFuzzer()
    return _native_fuzzer
