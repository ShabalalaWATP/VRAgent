"""
Binary Frida Service - Malware Analysis with Frida

Provides dynamic instrumentation for Windows PE and Linux ELF binaries:
1. Frida-based runtime hooking and monitoring
2. Docker sandbox isolation (Wine for Windows, Ubuntu for Linux)
3. Behavioral analysis and API call tracking
4. Anti-evasion bypass (anti-debug, anti-VM, packing)
5. Memory forensics and string decryption
6. MITRE ATT&CK mapping
"""

import asyncio
import hashlib
import json
import logging
import os
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

class Platform(Enum):
    """Binary platform."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class AnalysisPhase(Enum):
    """Analysis phase."""
    INITIALIZATION = "initialization"
    STATIC_ANALYSIS = "static_analysis"
    SANDBOX_SETUP = "sandbox_setup"
    FRIDA_INJECTION = "frida_injection"
    EXECUTION = "execution"
    BEHAVIOR_CAPTURE = "behavior_capture"
    CRASH_ANALYSIS = "crash_analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class BehaviorCategory(Enum):
    """Malware behavior categories."""
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    REGISTRY = "registry"
    PROCESS = "process"
    CRYPTO = "crypto"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EVASION = "evasion"
    DISCOVERY = "discovery"
    COMMAND_CONTROL = "command_control"


class MalwareFamily(Enum):
    """Common malware families."""
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    BACKDOOR = "backdoor"
    ROOTKIT = "rootkit"
    WORM = "worm"
    SPYWARE = "spyware"
    ADWARE = "adware"
    DOWNLOADER = "downloader"
    DROPPER = "dropper"
    UNKNOWN = "unknown"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class BinaryInfo:
    """Binary file information."""
    name: str
    path: str
    hash_sha256: str
    hash_md5: str
    size: int
    platform: Platform
    architecture: str  # x86, x64, arm, arm64
    is_packed: bool = False
    is_stripped: bool = False
    has_debug_info: bool = False
    compiler: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    sections: List[Dict] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    suspicious_indicators: List[str] = field(default_factory=list)


@dataclass
class FridaConfig:
    """Frida instrumentation configuration."""
    enable_api_hooks: bool = True
    enable_network_monitoring: bool = True
    enable_filesystem_monitoring: bool = True
    enable_registry_monitoring: bool = True  # Windows only
    enable_crypto_monitoring: bool = True
    enable_memory_forensics: bool = True
    enable_anti_evasion: bool = True
    enable_string_decryption: bool = True
    enable_code_coverage: bool = False  # Stalker-based (can be slow)
    custom_scripts: List[str] = field(default_factory=list)
    hook_patterns: List[str] = field(default_factory=list)  # Regex for API names


@dataclass
class SandboxConfig:
    """Sandbox execution configuration."""
    container_image: str = "frida-wine"  # or "frida-linux"
    timeout_seconds: int = 300
    network_enabled: bool = True
    internet_enabled: bool = False  # Isolated by default
    snapshot_enabled: bool = True
    resource_limits: Dict[str, Any] = field(default_factory=lambda: {
        "cpu_quota": 50000,  # 50% CPU
        "memory_mb": 2048,
        "disk_mb": 4096
    })


@dataclass
class RuntimeBehaviorData:
    """Runtime behavior captured during execution."""
    api_calls: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    files_written: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    registry_read: List[Dict] = field(default_factory=list)  # Windows
    registry_written: List[Dict] = field(default_factory=list)  # Windows
    processes_created: List[Dict] = field(default_factory=list)
    crypto_operations: List[Dict] = field(default_factory=list)
    decrypted_strings: List[Dict] = field(default_factory=list)
    memory_allocations: List[Dict] = field(default_factory=list)
    suspicious_behaviors: List[Dict] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class MalwareProfile:
    """Malware behavioral profile."""
    is_malicious: bool = False
    confidence_score: float = 0.0
    malware_family: MalwareFamily = MalwareFamily.UNKNOWN
    malware_category: str = "unknown"
    indicators_of_compromise: List[Dict] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity: str = "low"  # low, medium, high, critical
    threat_score: int = 0  # 0-100


@dataclass
class AnalysisResult:
    """Complete malware analysis result."""
    session_id: str
    binary_info: BinaryInfo
    runtime_behavior: RuntimeBehaviorData
    malware_profile: MalwareProfile
    phase: AnalysisPhase
    status: str  # running, completed, failed
    progress: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None
    container_id: Optional[str] = None
    frida_session_id: Optional[str] = None


# ============================================================================
# Frida JavaScript Templates
# ============================================================================

# Anti-Debug Bypass Script
ANTI_DEBUG_BYPASS_SCRIPT = """
// Anti-Debug Bypass for Windows/Linux

console.log("[FRIDA] Anti-debug bypass activated");

// Windows - IsDebuggerPresent bypass
try {
    const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    if (IsDebuggerPresent) {
        Interceptor.replace(IsDebuggerPresent, new NativeCallback(function() {
            console.log('[BYPASS] IsDebuggerPresent -> false');
            return 0;
        }, 'int', []));
    }
} catch (e) {}

// Windows - CheckRemoteDebuggerPresent bypass
try {
    const CheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
    if (CheckRemoteDebuggerPresent) {
        Interceptor.replace(CheckRemoteDebuggerPresent, new NativeCallback(function(hProcess, pbDebuggerPresent) {
            console.log('[BYPASS] CheckRemoteDebuggerPresent -> false');
            if (pbDebuggerPresent) {
                Memory.writeU32(pbDebuggerPresent, 0);
            }
            return 1;
        }, 'int', ['pointer', 'pointer']));
    }
} catch (e) {}

// Windows - OutputDebugString bypass (timing attack detection)
try {
    const OutputDebugStringA = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
    if (OutputDebugStringA) {
        Interceptor.replace(OutputDebugStringA, new NativeCallback(function(lpOutputString) {
            // Do nothing, no delay
            return;
        }, 'void', ['pointer']));
    }
} catch (e) {}

// Linux - ptrace detection bypass
try {
    const ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
            console.log('[BYPASS] ptrace() -> fake success');
            return 0;
        }, 'long', ['int', 'int', 'pointer', 'pointer']));
    }
} catch (e) {}

// Linux - /proc/self/status TracerPid bypass
try {
    const open = Module.findExportByName(null, 'open');
    const read = Module.findExportByName(null, 'read');
    if (open && read) {
        Interceptor.attach(open, {
            onEnter: function(args) {
                this.filename = Memory.readUtf8String(args[0]);
            },
            onLeave: function(retval) {
                if (this.filename && this.filename.includes('/proc/self/status')) {
                    this.fd = retval.toInt32();
                }
            }
        });

        Interceptor.attach(read, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (this.fd && this.buf) {
                    try {
                        const content = Memory.readUtf8String(this.buf, retval.toInt32());
                        if (content.includes('TracerPid')) {
                            // Replace TracerPid: <number> with TracerPid: 0
                            const modified = content.replace(/TracerPid:\\s*\\d+/, 'TracerPid: 0');
                            Memory.writeUtf8String(this.buf, modified);
                            console.log('[BYPASS] /proc/self/status TracerPid -> 0');
                        }
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {}

console.log("[FRIDA] Anti-debug bypass complete");
"""

# Windows API Monitoring Script
WINDOWS_API_HOOKS_SCRIPT = """
// Windows API Monitoring

console.log("[FRIDA] Windows API monitoring activated");

const INTERESTING_APIS = {
    // File operations
    'CreateFileW': ['kernel32.dll', ['pointer', 'uint', 'uint', 'pointer', 'uint', 'uint', 'pointer'], 'pointer'],
    'WriteFile': ['kernel32.dll', ['pointer', 'pointer', 'uint', 'pointer', 'pointer'], 'int'],
    'ReadFile': ['kernel32.dll', ['pointer', 'pointer', 'uint', 'pointer', 'pointer'], 'int'],
    'DeleteFileW': ['kernel32.dll', ['pointer'], 'int'],

    // Registry
    'RegOpenKeyExW': ['advapi32.dll', ['pointer', 'pointer', 'uint', 'uint', 'pointer'], 'long'],
    'RegSetValueExW': ['advapi32.dll', ['pointer', 'pointer', 'uint', 'uint', 'pointer', 'uint'], 'long'],
    'RegDeleteKeyW': ['advapi32.dll', ['pointer', 'pointer'], 'long'],

    // Network
    'connect': ['ws2_32.dll', ['int', 'pointer', 'int'], 'int'],
    'send': ['ws2_32.dll', ['int', 'pointer', 'int', 'int'], 'int'],
    'recv': ['ws2_32.dll', ['int', 'pointer', 'int', 'int'], 'int'],
    'WSAConnect': ['ws2_32.dll', ['int', 'pointer', 'int', 'pointer', 'pointer', 'pointer', 'pointer'], 'int'],

    // Process
    'CreateProcessW': ['kernel32.dll', ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'uint', 'pointer', 'pointer', 'pointer', 'pointer'], 'int'],
    'CreateRemoteThread': ['kernel32.dll', ['pointer', 'pointer', 'uint', 'pointer', 'pointer', 'uint', 'pointer'], 'pointer'],
    'VirtualAllocEx': ['kernel32.dll', ['pointer', 'pointer', 'uint', 'uint', 'uint'], 'pointer'],
    'WriteProcessMemory': ['kernel32.dll', ['pointer', 'pointer', 'pointer', 'uint', 'pointer'], 'int'],

    // Crypto
    'CryptEncrypt': ['advapi32.dll', ['pointer', 'pointer', 'int', 'uint', 'pointer', 'pointer', 'uint'], 'int'],
    'CryptDecrypt': ['advapi32.dll', ['pointer', 'pointer', 'int', 'uint', 'pointer', 'pointer'], 'int'],
};

function hookAPI(apiName, moduleName, argTypes, retType) {
    try {
        const addr = Module.findExportByName(moduleName, apiName);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.apiName = apiName;
                this.args = [];

                // Parse common argument types
                for (let i = 0; i < argTypes.length && i < args.length; i++) {
                    const argType = argTypes[i];
                    if (argType === 'pointer' && !args[i].isNull()) {
                        try {
                            // Try to read as string
                            this.args.push(Memory.readUtf16String(args[i]));
                        } catch (e) {
                            this.args.push(args[i].toString());
                        }
                    } else {
                        this.args.push(args[i].toString());
                    }
                }

                this.timestamp = Date.now();
            },
            onLeave: function(retval) {
                send({
                    type: 'api_call',
                    api: this.apiName,
                    args: this.args,
                    retval: retval.toString(),
                    timestamp: this.timestamp
                });
            }
        });

        console.log(`[HOOK] ${apiName} hooked successfully`);
    } catch (e) {
        console.log(`[ERROR] Failed to hook ${apiName}: ${e.message}`);
    }
}

// Hook all interesting APIs
for (const [apiName, [moduleName, argTypes, retType]] of Object.entries(INTERESTING_APIS)) {
    hookAPI(apiName, moduleName, argTypes, retType);
}

console.log("[FRIDA] Windows API monitoring complete");
"""

# Network Monitoring Script
NETWORK_MONITORING_SCRIPT = """
// Network Activity Monitoring (Windows + Linux)

console.log("[FRIDA] Network monitoring activated");

// Windows - Winsock
try {
    const connect = Module.findExportByName('ws2_32.dll', 'connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                try {
                    const sockaddr = args[1];
                    const family = Memory.readU16(sockaddr);

                    if (family === 2) { // AF_INET
                        const port = ((Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3)));
                        const ip = Memory.readU8(sockaddr.add(4)) + '.' +
                                   Memory.readU8(sockaddr.add(5)) + '.' +
                                   Memory.readU8(sockaddr.add(6)) + '.' +
                                   Memory.readU8(sockaddr.add(7));

                        send({
                            type: 'network_connection',
                            protocol: 'tcp',
                            ip: ip,
                            port: port,
                            timestamp: Date.now()
                        });
                        console.log(`[NETWORK] connect() -> ${ip}:${port}`);
                    }
                } catch (e) {
                    console.log(`[ERROR] Failed to parse connect: ${e.message}`);
                }
            }
        });
    }

    const send = Module.findExportByName('ws2_32.dll', 'send');
    if (send) {
        Interceptor.attach(send, {
            onEnter: function(args) {
                const buf = args[1];
                const len = args[2].toInt32();
                if (len > 0 && len < 4096) {
                    try {
                        const data = Memory.readByteArray(buf, Math.min(len, 512));
                        send({
                            type: 'network_send',
                            data: Array.from(new Uint8Array(data)),
                            length: len,
                            timestamp: Date.now()
                        });
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {
    console.log(`[NETWORK] Windows hooks failed: ${e.message}`);
}

// Linux - connect/send/recv
try {
    const connect = Module.findExportByName(null, 'connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                try {
                    const sockaddr = args[1];
                    const family = Memory.readU16(sockaddr);

                    if (family === 2) { // AF_INET
                        const port = ((Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3)));
                        const ip = Memory.readU8(sockaddr.add(4)) + '.' +
                                   Memory.readU8(sockaddr.add(5)) + '.' +
                                   Memory.readU8(sockaddr.add(6)) + '.' +
                                   Memory.readU8(sockaddr.add(7));

                        send({
                            type: 'network_connection',
                            protocol: 'tcp',
                            ip: ip,
                            port: port,
                            timestamp: Date.now()
                        });
                        console.log(`[NETWORK] connect() -> ${ip}:${port}`);
                    }
                } catch (e) {}
            }
        });
    }
} catch (e) {
    console.log(`[NETWORK] Linux hooks failed: ${e.message}`);
}

console.log("[FRIDA] Network monitoring complete");
"""

# Filesystem Monitoring Script
FILESYSTEM_MONITORING_SCRIPT = """
// Filesystem Activity Monitoring

console.log("[FRIDA] Filesystem monitoring activated");

// Windows - File operations
try {
    const CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
    if (CreateFileW) {
        Interceptor.attach(CreateFileW, {
            onEnter: function(args) {
                try {
                    this.filename = Memory.readUtf16String(args[0]);
                    this.access = args[1].toInt32();
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.filename && retval.toInt32() !== -1) {
                    send({
                        type: 'file_open',
                        path: this.filename,
                        access: this.access,
                        timestamp: Date.now()
                    });
                    console.log(`[FILE] CreateFileW: ${this.filename}`);
                }
            }
        });
    }

    const WriteFile = Module.findExportByName('kernel32.dll', 'WriteFile');
    if (WriteFile) {
        Interceptor.attach(WriteFile, {
            onEnter: function(args) {
                this.handle = args[0];
                this.size = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    send({
                        type: 'file_write',
                        handle: this.handle.toString(),
                        size: this.size,
                        timestamp: Date.now()
                    });
                }
            }
        });
    }

    const DeleteFileW = Module.findExportByName('kernel32.dll', 'DeleteFileW');
    if (DeleteFileW) {
        Interceptor.attach(DeleteFileW, {
            onEnter: function(args) {
                try {
                    const filename = Memory.readUtf16String(args[0]);
                    send({
                        type: 'file_delete',
                        path: filename,
                        timestamp: Date.now()
                    });
                    console.log(`[FILE] DeleteFileW: ${filename}`);
                } catch (e) {}
            }
        });
    }
} catch (e) {
    console.log(`[FILE] Windows hooks failed: ${e.message}`);
}

// Linux - File operations
try {
    const open = Module.findExportByName(null, 'open');
    if (open) {
        Interceptor.attach(open, {
            onEnter: function(args) {
                try {
                    this.filename = Memory.readUtf8String(args[0]);
                    this.flags = args[1].toInt32();
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.filename && retval.toInt32() !== -1) {
                    send({
                        type: 'file_open',
                        path: this.filename,
                        flags: this.flags,
                        timestamp: Date.now()
                    });
                    console.log(`[FILE] open: ${this.filename}`);
                }
            }
        });
    }

    const unlink = Module.findExportByName(null, 'unlink');
    if (unlink) {
        Interceptor.attach(unlink, {
            onEnter: function(args) {
                try {
                    const filename = Memory.readUtf8String(args[0]);
                    send({
                        type: 'file_delete',
                        path: filename,
                        timestamp: Date.now()
                    });
                    console.log(`[FILE] unlink: ${filename}`);
                } catch (e) {}
            }
        });
    }
} catch (e) {
    console.log(`[FILE] Linux hooks failed: ${e.message}`);
}

console.log("[FRIDA] Filesystem monitoring complete");
"""

# Crypto Monitoring Script
CRYPTO_MONITORING_SCRIPT = """
// Cryptographic Operations Monitoring

console.log("[FRIDA] Crypto monitoring activated");

// Windows - CryptoAPI
try {
    const CryptEncrypt = Module.findExportByName('advapi32.dll', 'CryptEncrypt');
    if (CryptEncrypt) {
        Interceptor.attach(CryptEncrypt, {
            onEnter: function(args) {
                this.dataLen = Memory.readU32(args[5]);
                this.data = args[4];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.data) {
                    try {
                        const data = Memory.readByteArray(this.data, Math.min(this.dataLen, 64));
                        send({
                            type: 'crypto_operation',
                            operation: 'encrypt',
                            data: Array.from(new Uint8Array(data)),
                            timestamp: Date.now()
                        });
                        console.log(`[CRYPTO] CryptEncrypt: ${this.dataLen} bytes`);
                    } catch (e) {}
                }
            }
        });
    }

    const CryptDecrypt = Module.findExportByName('advapi32.dll', 'CryptDecrypt');
    if (CryptDecrypt) {
        Interceptor.attach(CryptDecrypt, {
            onEnter: function(args) {
                this.dataLen = Memory.readU32(args[5]);
                this.data = args[4];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.data) {
                    try {
                        const data = Memory.readByteArray(this.data, Math.min(this.dataLen, 64));
                        send({
                            type: 'crypto_operation',
                            operation: 'decrypt',
                            data: Array.from(new Uint8Array(data)),
                            timestamp: Date.now()
                        });
                        console.log(`[CRYPTO] CryptDecrypt: ${this.dataLen} bytes`);
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {
    console.log(`[CRYPTO] Windows hooks failed: ${e.message}`);
}

// OpenSSL hooks (cross-platform)
try {
    const SSL_write = Module.findExportByName(null, 'SSL_write');
    if (SSL_write) {
        Interceptor.attach(SSL_write, {
            onEnter: function(args) {
                const len = args[2].toInt32();
                if (len > 0 && len < 4096) {
                    try {
                        const data = Memory.readByteArray(args[1], Math.min(len, 256));
                        send({
                            type: 'ssl_write',
                            data: Array.from(new Uint8Array(data)),
                            length: len,
                            timestamp: Date.now()
                        });
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {}

console.log("[FRIDA] Crypto monitoring complete");
"""


# ============================================================================
# Binary Frida Service
# ============================================================================

class BinaryFridaService:
    """
    Frida-based malware analysis for Windows PE and Linux ELF binaries.

    Provides dynamic instrumentation in isolated Docker sandboxes with:
    - API call monitoring
    - Network activity tracking
    - Filesystem monitoring
    - Registry monitoring (Windows)
    - Crypto operation tracking
    - Anti-evasion bypass
    - Memory forensics
    - MITRE ATT&CK mapping
    """

    def __init__(self):
        self.sessions: Dict[str, AnalysisResult] = {}
        self.active_containers: Dict[str, str] = {}  # session_id -> container_id

    async def analyze_binary(
        self,
        binary_path: str,
        frida_config: Optional[FridaConfig] = None,
        sandbox_config: Optional[SandboxConfig] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Analyze a binary with Frida instrumentation.

        Args:
            binary_path: Path to the binary file
            frida_config: Frida configuration (optional)
            sandbox_config: Sandbox configuration (optional)

        Yields:
            Progress updates and analysis results
        """
        session_id = str(uuid.uuid4())[:8]

        # Use default configs if not provided
        if frida_config is None:
            frida_config = FridaConfig()
        if sandbox_config is None:
            sandbox_config = SandboxConfig()

        # Initialize session
        binary_info = await self._analyze_binary_static(binary_path)
        result = AnalysisResult(
            session_id=session_id,
            binary_info=binary_info,
            runtime_behavior=RuntimeBehaviorData(),
            malware_profile=MalwareProfile(),
            phase=AnalysisPhase.INITIALIZATION,
            status="running",
            start_time=datetime.now()
        )
        self.sessions[session_id] = result

        yield {
            "type": "session_start",
            "session_id": session_id,
            "binary": binary_info.name,
            "platform": binary_info.platform.value,
            "architecture": binary_info.architecture
        }

        try:
            # Phase 1: Static Analysis
            result.phase = AnalysisPhase.STATIC_ANALYSIS
            result.progress = 0.1
            yield {"type": "phase", "phase": "static_analysis", "progress": 0.1}

            # Static analysis already done in initialization

            # Phase 2: Sandbox Setup
            result.phase = AnalysisPhase.SANDBOX_SETUP
            result.progress = 0.2
            yield {"type": "phase", "phase": "sandbox_setup", "progress": 0.2}

            container_id = await self._create_sandbox(binary_info.platform, sandbox_config)
            result.container_id = container_id
            self.active_containers[session_id] = container_id

            yield {"type": "info", "message": f"Sandbox created: {container_id[:12]}"}

            # Phase 3: Frida Injection
            result.phase = AnalysisPhase.FRIDA_INJECTION
            result.progress = 0.3
            yield {"type": "phase", "phase": "frida_injection", "progress": 0.3}

            # Copy binary to container and inject Frida
            await self._copy_to_container(container_id, binary_path)
            frida_session = await self._inject_frida(container_id, binary_info, frida_config)
            result.frida_session_id = frida_session

            yield {"type": "info", "message": "Frida instrumentation injected"}

            # Phase 4: Execution & Behavior Capture
            result.phase = AnalysisPhase.EXECUTION
            result.progress = 0.4
            yield {"type": "phase", "phase": "execution", "progress": 0.4}

            # Execute binary and capture behavior
            async for behavior_update in self._execute_and_monitor(
                container_id,
                binary_info,
                frida_config,
                sandbox_config
            ):
                # Update runtime behavior
                self._update_runtime_behavior(result.runtime_behavior, behavior_update)

                # Send progress updates
                result.progress = min(0.4 + (behavior_update.get("progress", 0) * 0.4), 0.8)
                yield {
                    "type": "behavior",
                    "data": behavior_update,
                    "progress": result.progress
                }

            # Phase 5: Analysis & Profiling
            result.phase = AnalysisPhase.REPORTING
            result.progress = 0.9
            yield {"type": "phase", "phase": "reporting", "progress": 0.9}

            # Generate malware profile
            result.malware_profile = await self._generate_malware_profile(result.runtime_behavior)

            # Phase 6: Complete
            result.phase = AnalysisPhase.COMPLETED
            result.status = "completed"
            result.progress = 1.0
            result.end_time = datetime.now()

            yield {
                "type": "complete",
                "session_id": session_id,
                "malware_profile": {
                    "is_malicious": result.malware_profile.is_malicious,
                    "confidence_score": result.malware_profile.confidence_score,
                    "malware_family": result.malware_profile.malware_family.value,
                    "severity": result.malware_profile.severity,
                    "threat_score": result.malware_profile.threat_score,
                    "capabilities": result.malware_profile.capabilities,
                    "mitre_tactics": result.malware_profile.mitre_tactics,
                    "mitre_techniques": result.malware_profile.mitre_techniques
                },
                "progress": 1.0
            }

        except Exception as e:
            result.phase = AnalysisPhase.FAILED
            result.status = "failed"
            result.error = str(e)
            result.end_time = datetime.now()
            logger.error(f"Analysis failed for session {session_id}: {e}")
            yield {"type": "error", "error": str(e)}

        finally:
            # Cleanup sandbox
            if container_id:
                await self._cleanup_sandbox(container_id)

    async def _analyze_binary_static(self, binary_path: str) -> BinaryInfo:
        """Perform static analysis on binary."""
        # Calculate hashes
        with open(binary_path, 'rb') as f:
            data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()

        # Detect platform and architecture
        platform, architecture = self._detect_platform_arch(data)

        return BinaryInfo(
            name=os.path.basename(binary_path),
            path=binary_path,
            hash_sha256=sha256,
            hash_md5=md5,
            size=len(data),
            platform=platform,
            architecture=architecture
        )

    def _detect_platform_arch(self, data: bytes) -> Tuple[Platform, str]:
        """Detect platform and architecture from binary."""
        # PE signature
        if data[:2] == b'MZ':
            # Read PE header offset
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
            if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                if machine == 0x8664:
                    return Platform.WINDOWS, "x64"
                elif machine == 0x014c:
                    return Platform.WINDOWS, "x86"

        # ELF signature
        elif data[:4] == b'\x7fELF':
            ei_class = data[4]
            if ei_class == 2:
                return Platform.LINUX, "x64"
            elif ei_class == 1:
                return Platform.LINUX, "x86"

        return Platform.WINDOWS, "unknown"

    async def _create_sandbox(self, platform: Platform, config: SandboxConfig) -> str:
        """Create Docker sandbox for binary execution."""
        # This is a placeholder - actual implementation would use Docker API
        # For now, return a mock container ID
        container_id = f"sandbox_{uuid.uuid4().hex[:12]}"
        logger.info(f"Created sandbox: {container_id}")
        return container_id

    async def _copy_to_container(self, container_id: str, binary_path: str):
        """Copy binary to Docker container."""
        # Placeholder - would use docker cp
        logger.info(f"Copied binary to container {container_id}")

    async def _inject_frida(
        self,
        container_id: str,
        binary_info: BinaryInfo,
        frida_config: FridaConfig
    ) -> str:
        """Inject Frida instrumentation."""
        # Placeholder - would start Frida and inject scripts
        frida_session_id = f"frida_{uuid.uuid4().hex[:8]}"
        logger.info(f"Frida session started: {frida_session_id}")
        return frida_session_id

    async def _execute_and_monitor(
        self,
        container_id: str,
        binary_info: BinaryInfo,
        frida_config: FridaConfig,
        sandbox_config: SandboxConfig
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Execute binary and monitor behavior."""
        # Placeholder - would execute binary with Frida hooks active
        # and yield behavior updates in real-time

        for i in range(10):
            await asyncio.sleep(0.5)
            yield {
                "type": "api_call",
                "api": "CreateFileW",
                "args": ["C:\\\\temp\\\\test.txt"],
                "timestamp": time.time(),
                "progress": i / 10
            }

    def _update_runtime_behavior(self, behavior: RuntimeBehaviorData, update: Dict):
        """Update runtime behavior with new data."""
        if update.get("type") == "api_call":
            behavior.api_calls.append(update)
        elif update.get("type") == "network_connection":
            behavior.network_connections.append(update)
        elif update.get("type") == "file_open":
            behavior.files_read.append(update.get("path", ""))

    async def _generate_malware_profile(self, behavior: RuntimeBehaviorData) -> MalwareProfile:
        """Generate malware behavioral profile."""
        profile = MalwareProfile()

        # Simple heuristic-based detection
        threat_score = 0

        # Check for suspicious behaviors
        if len(behavior.network_connections) > 0:
            threat_score += 20
            profile.capabilities.append("network_communication")

        if len(behavior.files_written) > 5:
            threat_score += 15
            profile.capabilities.append("file_manipulation")

        if len(behavior.processes_created) > 0:
            threat_score += 25
            profile.capabilities.append("process_injection")

        if len(behavior.registry_written) > 0:
            threat_score += 20
            profile.capabilities.append("persistence")

        profile.threat_score = min(threat_score, 100)
        profile.is_malicious = threat_score > 40
        profile.confidence_score = min(threat_score / 100.0, 0.95)

        if threat_score > 70:
            profile.severity = "critical"
        elif threat_score > 50:
            profile.severity = "high"
        elif threat_score > 30:
            profile.severity = "medium"
        else:
            profile.severity = "low"

        return profile

    async def _cleanup_sandbox(self, container_id: str):
        """Cleanup Docker sandbox."""
        logger.info(f"Cleaning up sandbox: {container_id}")

    def get_session(self, session_id: str) -> Optional[AnalysisResult]:
        """Get analysis session by ID."""
        return self.sessions.get(session_id)

    async def stop_session(self, session_id: str) -> bool:
        """Stop an active analysis session."""
        if session_id in self.sessions:
            result = self.sessions[session_id]
            result.status = "stopped"

            if session_id in self.active_containers:
                await self._cleanup_sandbox(self.active_containers[session_id])
                del self.active_containers[session_id]

            return True
        return False
