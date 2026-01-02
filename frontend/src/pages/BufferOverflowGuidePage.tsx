import {
  Box,
  Typography,
  Paper,
  alpha,
  useTheme,
  Tabs,
  Tab,
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
} from "@mui/material";
import { useState } from "react";
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
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import QuizIcon from "@mui/icons-material/Quiz";

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

// ========== DATA ARRAYS (Expandable Structure) ==========

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

export default function BufferOverflowGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

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

  return (
    <LearnPageLayout pageTitle="Buffer Overflow Attacks" pageContext={pageContext}>
    <Box>
      <Box sx={{ mb: 3 }}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2 }}
        />
      </Box>
      {/* Header */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#dc2626", 0.1)}, ${alpha("#f59e0b", 0.05)})`,
          border: `1px solid ${alpha("#dc2626", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              bgcolor: alpha("#dc2626", 0.15),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <MemoryIcon sx={{ fontSize: 32, color: "#dc2626" }} />
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 800 }}>
              Buffer Overflow Vulnerabilities
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Memory corruption fundamentals • Exploitation • Mitigations
            </Typography>
          </Box>
        </Box>

        {/* Beginner-Friendly Introduction */}
        <Box sx={{ mt: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#dc2626" }} />
            What is a Buffer Overflow?
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Imagine you have a row of 10 mailboxes, and you're only allowed to put letters in boxes 1-10. 
            A <strong>buffer overflow</strong> happens when someone tries to stuff letters into box 11, 12, and beyond – 
            except those boxes belong to someone else! In computer memory, this "someone else" might be critical 
            program data like return addresses, function pointers, or security tokens.
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            In programming terms, a <strong>buffer</strong> is just a chunk of memory set aside to hold data – 
            like a character array to store a username. When a program writes more data into this buffer than 
            it can hold, the extra data "overflows" into adjacent memory locations. This overflow can corrupt 
            other variables, crash the program, or – in the worst case – allow an attacker to execute their 
            own malicious code.
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
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
            mt: 2 
          }}>
            <Typography variant="body2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon sx={{ fontSize: 18, color: "#dc2626" }} />
              Why This Matters
            </Typography>
            <Typography variant="body2" sx={{ mt: 1, lineHeight: 1.7 }}>
              Buffer overflows can lead to: <strong>Remote Code Execution (RCE)</strong> – attackers run their code on your system; 
              <strong> Privilege Escalation</strong> – gaining admin/root access; <strong>Denial of Service</strong> – crashing 
              services; and <strong>Information Disclosure</strong> – leaking sensitive memory contents. Understanding these 
              vulnerabilities is essential for both defenders building secure systems and security researchers finding bugs.
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* Navigation Tabs */}
      <Paper sx={{ mb: 4, borderRadius: 2 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none" },
          }}
        >
          <Tab icon={<BugReportIcon />} iconPosition="start" label="Overflow Types" />
          <Tab icon={<CodeIcon />} iconPosition="start" label="Vulnerable Code" />
          <Tab icon={<ShieldIcon />} iconPosition="start" label="Protections" />
          <Tab icon={<WarningIcon />} iconPosition="start" label="Exploitation" />
          <Tab icon={<HistoryIcon />} iconPosition="start" label="Real-World CVEs" />
          <Tab icon={<BuildIcon />} iconPosition="start" label="Tools" />
          <Tab icon={<SecurityIcon />} iconPosition="start" label="Prevention" />
        </Tabs>
      </Paper>

      {/* Tab Content */}
      <Box>
        {/* Tab 0: Overflow Types */}
        {tabValue === 0 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              Types of Buffer Overflow Vulnerabilities
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

            <Accordion defaultExpanded sx={{ borderRadius: 2, mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>
                  <StorageIcon sx={{ mr: 1, verticalAlign: "middle", color: "#dc2626" }} />
                  Memory Layout Overview
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Typical Process Memory Layout (High to Low Addresses)">
{`┌─────────────────────────────────────┐  High Address (0xFFFFFFFF)
│           Kernel Space              │  (Not accessible to user programs)
├─────────────────────────────────────┤
│              Stack                  │  ← Local variables, return addresses
│              ↓                      │    (Grows downward)
├─────────────────────────────────────┤
│           (Free Space)              │
├─────────────────────────────────────┤
│              ↑                      │
│              Heap                   │  ← Dynamic memory (malloc/new)
│                                     │    (Grows upward)
├─────────────────────────────────────┤
│         Uninitialized Data          │  ← BSS segment (global vars = 0)
├─────────────────────────────────────┤
│         Initialized Data            │  ← Data segment (global vars)
├─────────────────────────────────────┤
│         Text/Code Segment           │  ← Program instructions (read-only)
└─────────────────────────────────────┘  Low Address (0x00000000)`}
                </CodeBlock>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                  Stack overflows typically overwrite the return address, causing the program to jump to 
                  attacker-controlled memory. Heap overflows corrupt metadata structures used by memory allocators.
                </Typography>
              </AccordionDetails>
            </Accordion>
          </Box>
        )}

        {/* Tab 1: Vulnerable Code */}
        {tabValue === 1 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              Vulnerable Functions & Patterns
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

            <Accordion defaultExpanded sx={{ borderRadius: 2, mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>
                  <CancelIcon sx={{ mr: 1, verticalAlign: "middle", color: "#dc2626" }} />
                  Vulnerable Code Example
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Classic Stack Buffer Overflow (C)">
{`#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];  // Fixed-size buffer
    
    // VULNERABLE: No bounds checking!
    strcpy(buffer, user_input);  // Will overflow if input > 63 chars
    
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
              </AccordionDetails>
            </Accordion>

            <Accordion sx={{ borderRadius: 2, mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>
                  <CheckCircleIcon sx={{ mr: 1, verticalAlign: "middle", color: "#22c55e" }} />
                  Safe Code Example
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Secure Implementation (C)">
{`#include <stdio.h>
#include <string.h>

void safe_function(const char *user_input) {
    char buffer[64];
    
    // SAFE: Use strncpy with explicit size limit
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';  // Ensure null termination
    
    printf("You entered: %s\\n", buffer);
}

// Even better: Use snprintf for formatted strings
void safer_function(const char *user_input) {
    char buffer[64];
    
    // snprintf always null-terminates and returns bytes needed
    int needed = snprintf(buffer, sizeof(buffer), "%s", user_input);
    if (needed >= sizeof(buffer)) {
        printf("Warning: Input truncated\\n");
    }
    
    printf("You entered: %s\\n", buffer);
}`}
                </CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Box>
        )}

        {/* Tab 2: Memory Protections */}
        {tabValue === 2 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              Modern Memory Protections
            </Typography>

            <Grid container spacing={3}>
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

            <Accordion sx={{ borderRadius: 2, mt: 4 }}>
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
          </Box>
        )}

        {/* Tab 3: Exploitation Techniques */}
        {tabValue === 3 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              Exploitation Techniques
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

            <Accordion defaultExpanded sx={{ borderRadius: 2, mb: 2 }}>
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
┌──────────────────────────────────────────────────┐
│ [PADDING]     [RET ADDR]    [SHELLCODE/ROP]      │
│ (64 bytes)    (4/8 bytes)   (variable)           │
└──────────────────────────────────────────────────┘

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
          </Box>
        )}

        {/* Tab 4: Real-World CVEs */}
        {tabValue === 4 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              Notable Real-World Vulnerabilities
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

            <Accordion sx={{ borderRadius: 2, mb: 2 }}>
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
                    { year: "2014", event: "Heartbleed (CVE-2014-0160) disclosed" },
                    { year: "2017", event: "EternalBlue leaked, WannaCry ransomware" },
                    { year: "2021", event: "Baron Samedit sudo heap overflow" },
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
          </Box>
        )}

        {/* Tab 5: Tools */}
        {tabValue === 5 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              Analysis & Exploitation Tools
            </Typography>

            <Grid container spacing={2}>
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

            <Accordion sx={{ borderRadius: 2, mt: 4 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>
                  <BuildIcon sx={{ mr: 1, verticalAlign: "middle", color: "#3b82f6" }} />
                  pwntools Basic Usage
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Python pwntools exploit template">
{`from pwn import *

# Set context for target architecture
context.arch = 'i386'  # or 'amd64'
context.os = 'linux'

# Connect to target
# p = process('./vulnerable')  # Local
# p = remote('target.com', 1337)  # Remote

# Create payload
payload = b"A" * 64          # Padding
payload += p32(0xdeadbeef)   # Return address (32-bit)
# payload += p64(0xdeadbeef) # Return address (64-bit)

# Send payload
p.sendline(payload)

# Interact with shell
p.interactive()`}
                </CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Box>
        )}

        {/* Tab 6: Prevention */}
        {tabValue === 6 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              Prevention & Mitigation
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

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#22c55e" }} />
                Secure Development Checklist
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    ✅ DO
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
                    ❌ DON'T
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
          </Box>
        )}

        <Paper
          id="quiz-section"
          sx={{
            mt: 4,
            p: 4,
            borderRadius: 3,
            border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
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
