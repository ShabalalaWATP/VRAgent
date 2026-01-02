import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  AlertTitle,
  IconButton,
  Tooltip,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import DataArrayIcon from "@mui/icons-material/DataArray";
import VisibilityIcon from "@mui/icons-material/Visibility";
import EditIcon from "@mui/icons-material/Edit";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import QuizIcon from "@mui/icons-material/Quiz";
import InfoIcon from "@mui/icons-material/Info";
import SecurityIcon from "@mui/icons-material/Security";
import CodeIcon from "@mui/icons-material/Code";
import BugReportIcon from "@mui/icons-material/BugReport";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import LayersIcon from "@mui/icons-material/Layers";
import ListAltIcon from "@mui/icons-material/ListAlt";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SchoolIcon from "@mui/icons-material/School";
import BuildIcon from "@mui/icons-material/Build";
import { Link, useNavigate } from "react-router-dom";

// OOB vulnerability types with detailed information
const oobVulnerabilities = [
  {
    name: "Out-of-Bounds Read (OOB-R)",
    color: "#3b82f6",
    icon: <VisibilityIcon />,
    description: "Reading memory beyond allocated buffer boundaries, accessing adjacent memory regions",
    severity: "Medium to High",
    impacts: [
      "Information disclosure - leak sensitive data from memory",
      "ASLR bypass - reveal randomized addresses via pointer leaks",
      "Canary leak - read stack canaries to defeat stack protection",
      "Credential exposure - passwords, keys, tokens in adjacent memory",
      "Crash potential - SIGSEGV if accessing unmapped pages",
    ],
    commonScenarios: [
      "Array index exceeds array bounds",
      "Loop iterates one element too far",
      "Missing null terminator on strings",
      "Incorrect length calculation in parsers",
      "Negative index treated as large unsigned value",
    ],
    realWorldExamples: [
      { name: "Heartbleed (CVE-2014-0160)", description: "OOB read in OpenSSL leaked 64KB of memory per request" },
      { name: "CloudFlare Parser Bug", description: "HTML parser OOB read leaked customer data" },
    ],
  },
  {
    name: "Out-of-Bounds Write (OOB-W)",
    color: "#ef4444",
    icon: <EditIcon />,
    description: "Writing memory beyond allocated buffer boundaries, corrupting adjacent data structures",
    severity: "High to Critical",
    impacts: [
      "Memory corruption - overwrite critical data structures",
      "Control flow hijacking - corrupt function pointers or vtables",
      "Heap metadata corruption - enable heap exploitation primitives",
      "Return address overwrite - redirect execution on stack",
      "Privilege escalation - in kernel or setuid contexts",
    ],
    commonScenarios: [
      "Buffer overflow via unchecked copy operations",
      "Off-by-one write corrupts adjacent byte",
      "Integer overflow results in undersized buffer",
      "Array write with attacker-controlled index",
      "String operations without size validation",
    ],
    realWorldExamples: [
      { name: "BlueKeep (CVE-2019-0708)", description: "RDP OOB write enabled remote code execution" },
      { name: "Sudo Baron Samedit", description: "Heap-based OOB write in sudo led to root escalation" },
    ],
  },
];

// Common root causes of OOB vulnerabilities
const rootCauses = [
  {
    cause: "Missing Bounds Checks",
    description: "No validation that index is within valid range before access",
    example: "buf[user_controlled_index]",
    fix: "if (index < buf_len) { access buf[index]; }",
    severity: "High",
  },
  {
    cause: "Off-by-One Errors",
    description: "Loop condition uses <= instead of <, or size-1 calculation errors",
    example: "for (i = 0; i <= size; i++)",
    fix: "for (i = 0; i < size; i++)",
    severity: "High",
  },
  {
    cause: "Integer Overflow in Index",
    description: "Arithmetic overflow produces unexpectedly small or large index",
    example: "buf[base + offset] where overflow wraps",
    fix: "Check for overflow: if (base > SIZE_MAX - offset) fail;",
    severity: "Critical",
  },
  {
    cause: "Signed/Unsigned Confusion",
    description: "Negative signed value interpreted as large unsigned index",
    example: "size_t idx = (int)-1; // becomes SIZE_MAX",
    fix: "Use consistent types; validate signed values >= 0",
    severity: "High",
  },
  {
    cause: "Incorrect Length Calculation",
    description: "Wrong size passed to memory operations (memcpy, read, etc.)",
    example: "memcpy(dst, src, wrong_calculated_size)",
    fix: "Validate length against destination capacity",
    severity: "Critical",
  },
  {
    cause: "Type Confusion",
    description: "Object accessed with wrong size assumptions",
    example: "Treating struct A as struct B with different sizes",
    fix: "Type-safe casting and size validation",
    severity: "High",
  },
];

// Language-specific considerations
const languageConsiderations = [
  {
    language: "C",
    features: "No bounds checking on arrays, raw pointers, manual memory management",
    risks: "High - developer responsible for all bounds validation",
    safePractices: [
      "Always validate array indices before access",
      "Use safe string functions (strncpy, snprintf)",
      "Prefer size_t for array indices/lengths",
      "Enable compiler warnings (-Wall -Wextra)",
    ],
    unsafeAPIs: ["strcpy", "strcat", "gets", "sprintf", "scanf with unbounded %s"],
  },
  {
    language: "C++",
    features: "std::vector, std::array with .at() bounds-checked access, operator[] unchecked",
    risks: "Medium - safe containers available but unchecked access still possible",
    safePractices: [
      "Use .at() instead of operator[] when bounds unknown",
      "Use std::span (C++20) for safer array views",
      "Enable iterator debugging in Debug builds",
      "Use std::string instead of char arrays",
    ],
    unsafeAPIs: ["operator[] on containers", "pointer arithmetic", "C-style casts"],
  },
  {
    language: "Rust",
    features: "Bounds checking enforced by default, safe/unsafe distinction, borrow checker",
    risks: "Low - unsafe blocks required to bypass bounds checks",
    safePractices: [
      "Avoid unsafe blocks unless necessary",
      "Use get() for fallible indexing",
      "Enable debug_assert for extra validation",
      "Audit all unsafe code carefully",
    ],
    unsafeAPIs: ["get_unchecked", "slice::from_raw_parts", "pointer::offset"],
  },
  {
    language: "Python/Java/C#",
    features: "Automatic bounds checking, exceptions on out-of-range access",
    risks: "Very Low - language enforces bounds, but still possible in native extensions",
    safePractices: [
      "Handle IndexError/IndexOutOfBoundsException appropriately",
      "Validate indices in native/FFI code",
      "Use language-native collections",
      "Audit native library dependencies",
    ],
    unsafeAPIs: ["Native extensions", "P/Invoke (C#)", "JNI (Java)", "ctypes (Python)"],
  },
];

// Exploitation techniques and primitives
const exploitTechniques = [
  {
    name: "Relative Read/Write",
    description: "Access adjacent objects or data structures by controlled offset from base",
    requirements: ["OOB vulnerability", "Known or controlled offset", "Adjacent target object"],
    steps: [
      "Identify vulnerable array/buffer access",
      "Determine memory layout of adjacent objects",
      "Calculate offset from vulnerable buffer to target",
      "Trigger OOB access with crafted index",
      "Read sensitive data or corrupt target structure",
    ],
    impact: "Leak adjacent data or corrupt specific fields",
  },
  {
    name: "Arbitrary Read via Controlled Index",
    description: "Fully controlled array index enables reading arbitrary memory",
    requirements: ["User-controlled index", "Readable memory region", "No bounds checking"],
    steps: [
      "Identify array access with attacker-controlled index",
      "Leak or calculate target address",
      "Compute array index to reach target (target_addr - base_addr) / element_size",
      "Trigger read with calculated index",
      "Exfiltrate data via side channel or direct output",
    ],
    impact: "Read arbitrary memory regions, leak keys/pointers",
  },
  {
    name: "Arbitrary Write via Controlled Index + Value",
    description: "Control both index and written value for arbitrary memory write",
    requirements: ["User-controlled index", "User-controlled value", "Writable memory"],
    steps: [
      "Identify array write with controlled index and value",
      "Choose target address (function pointer, GOT entry, return address)",
      "Calculate index to target",
      "Craft payload value (shellcode address, ROP gadget, etc.)",
      "Trigger write to achieve control flow hijack",
    ],
    impact: "Arbitrary code execution via control flow hijack",
  },
  {
    name: "Information Leak to Defeat ASLR",
    description: "Use OOB read to leak randomized addresses, enabling further exploitation",
    requirements: ["OOB read", "Adjacent pointers (heap, libc, stack)"],
    steps: [
      "Trigger OOB read to access adjacent memory",
      "Leak pointer value (heap, libc function, stack)",
      "Calculate base address from leaked pointer",
      "Use calculated addresses for subsequent exploitation",
      "Chain with ROP or shellcode injection",
    ],
    impact: "Bypass ASLR, enable reliable exploitation",
  },
];

// Mitigations and defenses
const mitigationStrategies = [
  {
    category: "Development Practices",
    color: "#10b981",
    techniques: [
      {
        name: "Rigorous Bounds Checking",
        description: "Validate all array/buffer indices before access",
        effectiveness: "Very High",
        implementation: "if (index < array_length && index >= 0) { access array[index]; }",
      },
      {
        name: "Safe String Functions",
        description: "Use length-limited functions (strncpy, snprintf, strlcpy)",
        effectiveness: "High",
        implementation: "snprintf(buf, sizeof(buf), fmt, args); buf[sizeof(buf)-1] = 0;",
      },
      {
        name: "Size_t for Indices/Lengths",
        description: "Use unsigned types matching array size semantics",
        effectiveness: "Medium",
        implementation: "size_t index; for (index = 0; index < len; index++)",
      },
      {
        name: "Input Validation",
        description: "Sanitize and validate all untrusted input lengths and indices",
        effectiveness: "Very High",
        implementation: "if (user_len > MAX_LEN || user_len < 0) reject;",
      },
    ],
  },
  {
    category: "Language & Runtime",
    color: "#3b82f6",
    techniques: [
      {
        name: "Memory-Safe Languages",
        description: "Rust, Go, Java, C#, Python enforce bounds checking",
        effectiveness: "Very High",
        implementation: "Choose memory-safe language when possible",
      },
      {
        name: "Checked Container Access",
        description: "Use .at() in C++, checked methods in libraries",
        effectiveness: "High",
        implementation: "vec.at(index) throws std::out_of_range",
      },
      {
        name: "Smart Pointers & RAII",
        description: "C++ smart pointers reduce manual memory errors",
        effectiveness: "Medium",
        implementation: "std::vector, std::unique_ptr, std::shared_ptr",
      },
    ],
  },
  {
    category: "Compiler & Tooling",
    color: "#8b5cf6",
    techniques: [
      {
        name: "AddressSanitizer (ASan)",
        description: "Runtime detection of OOB accesses (reads and writes)",
        effectiveness: "Very High",
        implementation: "gcc -fsanitize=address or clang -fsanitize=address",
      },
      {
        name: "UndefinedBehaviorSanitizer",
        description: "Detect integer overflows and other undefined behavior",
        effectiveness: "High",
        implementation: "gcc -fsanitize=undefined",
      },
      {
        name: "Static Analysis",
        description: "Tools like Coverity, CodeQL, clang-tidy find OOB patterns",
        effectiveness: "Medium",
        implementation: "Integrate into CI/CD pipeline",
      },
      {
        name: "Compiler Warnings",
        description: "Enable maximum warning levels to catch suspicious code",
        effectiveness: "Medium",
        implementation: "gcc -Wall -Wextra -Werror",
      },
    ],
  },
  {
    category: "System Mitigations",
    color: "#f59e0b",
    techniques: [
      {
        name: "Guard Pages",
        description: "Unmapped pages after allocations trigger faults on OOB",
        effectiveness: "Medium",
        implementation: "Allocator configuration, mprotect",
      },
      {
        name: "ASLR",
        description: "Randomizes addresses to make OOB exploitation less reliable",
        effectiveness: "Medium",
        implementation: "Enabled by default on modern OSes",
      },
      {
        name: "Stack Canaries",
        description: "Detect stack OOB writes before return",
        effectiveness: "High for stack",
        implementation: "gcc -fstack-protector-strong",
      },
      {
        name: "W^X / NX",
        description: "Prevent code execution from writable regions",
        effectiveness: "Medium",
        implementation: "Enabled by default, forces ROP instead of shellcode",
      },
    ],
  },
];

// Testing strategies
const testingStrategies = [
  {
    strategy: "Boundary Value Testing",
    description: "Test edge cases at array boundaries",
    testCases: ["index = 0", "index = length - 1", "index = length", "index = length + 1", "index = -1", "index = SIZE_MAX"],
    expectedResult: "Accept valid indices, reject invalid indices gracefully",
  },
  {
    strategy: "Fuzzing",
    description: "Generate random/malformed inputs to trigger OOB",
    tools: ["AFL++", "libFuzzer", "Honggfuzz", "OSS-Fuzz"],
    approach: "Feed boundary values, negative numbers, large indices, overflow values",
    expectedResult: "Crashes or ASan reports indicate OOB vulnerabilities",
  },
  {
    strategy: "Property-Based Testing",
    description: "Assert invariants about array access",
    properties: ["∀ index: 0 <= index < length", "∀ write: written_size <= buffer_capacity"],
    tools: ["QuickCheck (Haskell)", "Hypothesis (Python)", "proptest (Rust)"],
    expectedResult: "Property violations reveal OOB bugs",
  },
  {
    strategy: "Sanitizer-Enabled Testing",
    description: "Run test suite with ASan/UBSan enabled",
    configuration: "Build with -fsanitize=address,undefined",
    approach: "Execute full test suite and regression tests",
    expectedResult: "Sanitizers report OOB accesses immediately",
  },
];

// Code examples
const codeExamples = [
  {
    title: "Vulnerable Code - Missing Bounds Check",
    language: "C",
    code: `// VULNERABLE: No bounds checking
int array[10];
int index = get_user_input();
int value = array[index];  // OOB read if index >= 10 or < 0

// Also vulnerable
char buf[256];
int len = get_user_length();
memcpy(buf, src, len);  // OOB write if len > 256`,
    issue: "No validation of user-controlled index or length",
  },
  {
    title: "Secure Code - Bounds Checking",
    language: "C",
    code: `// SECURE: Validate index before access
int array[10];
int index = get_user_input();
if (index >= 0 && index < 10) {
    int value = array[index];
} else {
    // Handle error
    return -1;
}

// Secure memcpy with validation
char buf[256];
int len = get_user_length();
if (len > 0 && len <= sizeof(buf)) {
    memcpy(buf, src, len);
} else {
    return -1;
}`,
    improvement: "Explicit bounds validation prevents OOB access",
  },
  {
    title: "Vulnerable Code - Off-by-One",
    language: "C",
    code: `// VULNERABLE: Off-by-one error
char buf[10];
for (int i = 0; i <= 10; i++) {  // Wrong: should be i < 10
    buf[i] = 'A';  // Writes 11 bytes, last write is OOB
}

// Also vulnerable
char str[10];
strncpy(str, input, 10);  // May not null-terminate
printf("%s", str);  // OOB read if not terminated`,
    issue: "Loop writes past end, strncpy may not null-terminate",
  },
  {
    title: "Secure Code - Correct Bounds",
    language: "C",
    code: `// SECURE: Correct loop bounds
char buf[10];
for (int i = 0; i < 10; i++) {
    buf[i] = 'A';
}

// Safe string handling
char str[10];
strncpy(str, input, sizeof(str) - 1);
str[sizeof(str) - 1] = '\\0';  // Ensure null termination`,
    improvement: "Use < instead of <=, always null-terminate strings",
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#8b5cf6";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "An out-of-bounds read means:",
    options: ["Reading past a buffer's boundary", "Writing to disk", "Encrypting memory", "Zeroing a buffer"],
    correctAnswer: 0,
    explanation: "OOB read accesses memory outside a buffer.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "An out-of-bounds write means:",
    options: ["Writing past a buffer's boundary", "Reading a file", "Allocating memory", "Freeing memory"],
    correctAnswer: 0,
    explanation: "OOB write corrupts memory outside a buffer.",
  },
  {
    id: 3,
    topic: "Impact",
    question: "OOB reads commonly lead to:",
    options: ["Information disclosure", "Automatic patching", "Stronger encryption", "Lower CPU usage"],
    correctAnswer: 0,
    explanation: "Reading outside a buffer can leak sensitive data.",
  },
  {
    id: 4,
    topic: "Impact",
    question: "OOB writes commonly lead to:",
    options: ["Memory corruption", "Safer execution", "Better performance", "Less logging"],
    correctAnswer: 0,
    explanation: "Writing outside a buffer corrupts memory.",
  },
  {
    id: 5,
    topic: "Causes",
    question: "A common cause of OOB is:",
    options: ["Missing bounds checks", "Using TLS", "Using HTTPS", "Using JSON"],
    correctAnswer: 0,
    explanation: "Without bounds checks, indexes can exceed limits.",
  },
  {
    id: 6,
    topic: "Causes",
    question: "An off-by-one error often comes from:",
    options: ["Using <= instead of <", "Using == instead of !=", "Using + instead of -", "Using * instead of /"],
    correctAnswer: 0,
    explanation: "Off-by-one errors allow one extra element.",
  },
  {
    id: 7,
    topic: "Causes",
    question: "Negative indexes are dangerous because:",
    options: ["They can access memory before the buffer", "They always crash immediately", "They are always ignored", "They are always safe"],
    correctAnswer: 0,
    explanation: "Negative indexes can underflow or access prior memory.",
  },
  {
    id: 8,
    topic: "Causes",
    question: "Integer overflow in index math can cause:",
    options: ["Out-of-bounds access", "Automatic bounds checks", "Better performance", "Smaller buffers"],
    correctAnswer: 0,
    explanation: "Overflow can bypass length checks.",
  },
  {
    id: 9,
    topic: "Causes",
    question: "Incorrect length calculations can cause:",
    options: ["OOB reads or writes", "Stronger validation", "Safer parsing", "Lower memory usage"],
    correctAnswer: 0,
    explanation: "Bad lengths lead to unsafe accesses.",
  },
  {
    id: 10,
    topic: "Causes",
    question: "Type confusion can cause OOB when:",
    options: ["Object sizes are misinterpreted", "All types are correct", "All indexes are validated", "Bounds checks are enforced"],
    correctAnswer: 0,
    explanation: "Wrong size assumptions lead to mis-sized access.",
  },
  {
    id: 11,
    topic: "Impact",
    question: "OOB reads can bypass ASLR by:",
    options: ["Leaking pointers", "Disabling randomization", "Clearing memory", "Encrypting addresses"],
    correctAnswer: 0,
    explanation: "Leaked pointers reveal address layouts.",
  },
  {
    id: 12,
    topic: "Impact",
    question: "OOB writes can lead to control flow hijack by:",
    options: ["Overwriting function pointers", "Adding logs", "Changing themes", "Reordering bytes only"],
    correctAnswer: 0,
    explanation: "Corrupted pointers can redirect execution.",
  },
  {
    id: 13,
    topic: "Language",
    question: "C arrays are:",
    options: ["Not bounds-checked by default", "Always bounds-checked", "Self-resizing", "Always safe"],
    correctAnswer: 0,
    explanation: "C provides no automatic bounds checking.",
  },
  {
    id: 14,
    topic: "Language",
    question: "C++ vector::at provides:",
    options: ["Bounds checking", "No checks", "Automatic resizing on read", "Encryption"],
    correctAnswer: 0,
    explanation: "vector::at throws on out-of-range access.",
  },
  {
    id: 15,
    topic: "Language",
    question: "C++ vector operator[]:",
    options: ["Does not bounds-check", "Always throws", "Encrypts values", "Is only for writes"],
    correctAnswer: 0,
    explanation: "operator[] is unchecked for performance.",
  },
  {
    id: 16,
    topic: "APIs",
    question: "Before calling memcpy, you should:",
    options: ["Validate the length against destination size", "Assume the length is safe", "Only check source size", "Skip checks for speed"],
    correctAnswer: 0,
    explanation: "Validate destination bounds before copying.",
  },
  {
    id: 17,
    topic: "APIs",
    question: "Using size_t for indexes helps because:",
    options: ["It matches size types and reduces signedness bugs", "It prevents all OOB", "It disables checks", "It forces negative values"],
    correctAnswer: 0,
    explanation: "Consistent types reduce conversion errors.",
  },
  {
    id: 18,
    topic: "Pointers",
    question: "Pointer arithmetic errors can cause:",
    options: ["OOB access", "Automatic resizing", "Encryption", "Compression"],
    correctAnswer: 0,
    explanation: "Wrong offsets can cross buffer boundaries.",
  },
  {
    id: 19,
    topic: "Strings",
    question: "Off-by-one string bugs often corrupt:",
    options: ["The null terminator or adjacent data", "Only the string length", "Only the header", "Only the heap base"],
    correctAnswer: 0,
    explanation: "One extra byte can corrupt metadata or terminators.",
  },
  {
    id: 20,
    topic: "Impact",
    question: "OOB reads may crash when:",
    options: ["Memory is unmapped", "Memory is valid", "ASLR is enabled", "The input is small"],
    correctAnswer: 0,
    explanation: "Accessing unmapped memory triggers a fault.",
  },
  {
    id: 21,
    topic: "Impact",
    question: "OOB reads may leak:",
    options: ["Passwords, keys, or pointers", "Only zeros", "Only timestamps", "Only logs"],
    correctAnswer: 0,
    explanation: "Adjacent memory can contain secrets.",
  },
  {
    id: 22,
    topic: "Impact",
    question: "OOB writes on the heap can corrupt:",
    options: ["Allocator metadata", "Only CPU registers", "Only files", "Only sockets"],
    correctAnswer: 0,
    explanation: "Heap metadata corruption can lead to exploits.",
  },
  {
    id: 23,
    topic: "Impact",
    question: "OOB writes on the stack can overwrite:",
    options: ["Return addresses or locals", "Only heap data", "Only kernel state", "Only environment variables"],
    correctAnswer: 0,
    explanation: "Stack corruption can hijack control flow.",
  },
  {
    id: 24,
    topic: "Impact",
    question: "OOB writes on the heap can corrupt:",
    options: ["Adjacent objects", "Only stack data", "Only registers", "Only constants"],
    correctAnswer: 0,
    explanation: "Heap objects are often adjacent in memory.",
  },
  {
    id: 25,
    topic: "Causes",
    question: "An underflow in an index can:",
    options: ["Access memory before a buffer", "Always return zero", "Always crash", "Always be safe"],
    correctAnswer: 0,
    explanation: "Underflow can produce a large unsigned index.",
  },
  {
    id: 26,
    topic: "Loops",
    question: "A loop like for (i <= len) can cause:",
    options: ["One extra access past the end", "Perfect bounds", "No iterations", "Only empty loops"],
    correctAnswer: 0,
    explanation: "Using <= reads or writes one element too far.",
  },
  {
    id: 27,
    topic: "Mitigations",
    question: "Guard pages help by:",
    options: ["Catching OOB accesses early", "Disabling checks", "Hiding crashes", "Reducing memory use"],
    correctAnswer: 0,
    explanation: "Accessing guard pages triggers a fault.",
  },
  {
    id: 28,
    topic: "Mitigations",
    question: "AddressSanitizer helps by:",
    options: ["Detecting OOB reads and writes", "Fixing bugs automatically", "Disabling ASLR", "Encrypting memory"],
    correctAnswer: 0,
    explanation: "ASan reports out-of-bounds accesses at runtime.",
  },
  {
    id: 29,
    topic: "Mitigations",
    question: "Fuzzing helps find OOB issues by:",
    options: ["Generating boundary and malformed inputs", "Disabling checks", "Reducing coverage", "Avoiding edge cases"],
    correctAnswer: 0,
    explanation: "Fuzzers hit boundary conditions frequently.",
  },
  {
    id: 30,
    topic: "Mitigations",
    question: "The primary defense is:",
    options: ["Consistent bounds checking", "Relying on luck", "Disabling warnings", "Using only random tests"],
    correctAnswer: 0,
    explanation: "Bounds checks are the first line of defense.",
  },
  {
    id: 31,
    topic: "Mitigations",
    question: "Memory-safe languages help by:",
    options: ["Enforcing bounds checks automatically", "Removing validation", "Disabling sanitizers", "Avoiding testing"],
    correctAnswer: 0,
    explanation: "Memory-safe languages enforce bounds and safety.",
  },
  {
    id: 32,
    topic: "Mitigations",
    question: "Using checked containers helps by:",
    options: ["Throwing or handling out-of-range access", "Silently wrapping", "Ignoring errors", "Disabling checks"],
    correctAnswer: 0,
    explanation: "Checked access prevents silent corruption.",
  },
  {
    id: 33,
    topic: "Mitigations",
    question: "Input validation should include:",
    options: ["Ensuring lengths match actual data", "Only checking file names", "Only checking UI", "Only checking logs"],
    correctAnswer: 0,
    explanation: "Lengths must be validated before access.",
  },
  {
    id: 34,
    topic: "Causes",
    question: "Integer overflow in size calculations can cause:",
    options: ["OOB accesses due to undersized buffers", "More coverage", "Automatic fixes", "Slower parsing only"],
    correctAnswer: 0,
    explanation: "Overflow can reduce buffer size unexpectedly.",
  },
  {
    id: 35,
    topic: "Impact",
    question: "Accessing unmapped memory typically triggers:",
    options: ["SIGSEGV", "SIGCHLD", "SIGALRM", "SIGPIPE"],
    correctAnswer: 0,
    explanation: "SIGSEGV indicates invalid memory access.",
  },
  {
    id: 36,
    topic: "Impact",
    question: "OOB reads may return data if:",
    options: ["The adjacent memory is mapped and accessible", "ASLR is enabled", "NX is enabled", "The input is empty"],
    correctAnswer: 0,
    explanation: "Mapped memory can be read even if it is out of bounds.",
  },
  {
    id: 37,
    topic: "Impact",
    question: "OOB writes can cause:",
    options: ["Silent data corruption", "Guaranteed crashes only", "Safer execution", "Faster parsing"],
    correctAnswer: 0,
    explanation: "Corruption may not crash immediately.",
  },
  {
    id: 38,
    topic: "Strings",
    question: "Using strncpy still requires:",
    options: ["Correct length calculations and termination", "No checks", "No termination", "No validation"],
    correctAnswer: 0,
    explanation: "strncpy may not null-terminate.",
  },
  {
    id: 39,
    topic: "Strings",
    question: "Ensure strings are:",
    options: ["Null-terminated within bounds", "Always empty", "Always encrypted", "Always compressed"],
    correctAnswer: 0,
    explanation: "Missing terminators can cause over-reads.",
  },
  {
    id: 40,
    topic: "Parsers",
    question: "OOB reads in parsers can leak:",
    options: ["Adjacent file or memory contents", "Only formatting", "Only headers", "Only timestamps"],
    correctAnswer: 0,
    explanation: "Parsers can expose data beyond intended bounds.",
  },
  {
    id: 41,
    topic: "Parsers",
    question: "OOB writes in decoders can lead to:",
    options: ["Remote code execution", "Only log entries", "Only validation errors", "Only warnings"],
    correctAnswer: 0,
    explanation: "Memory corruption can lead to code execution.",
  },
  {
    id: 42,
    topic: "Causes",
    question: "A partial overwrite can occur from:",
    options: ["Off-by-one writes", "Only large overflows", "Only reads", "Only stack frames"],
    correctAnswer: 0,
    explanation: "One-byte overwrites can corrupt adjacent data.",
  },
  {
    id: 43,
    topic: "Types",
    question: "Signed and unsigned mixing can lead to:",
    options: ["Bounds check bypass", "Safer comparisons", "Automatic fixes", "Lower risk"],
    correctAnswer: 0,
    explanation: "Conversions can make negative values large.",
  },
  {
    id: 44,
    topic: "Types",
    question: "Using size_t for loop counters is good when:",
    options: ["The loop is over a size_t length", "You need negative values", "You want wraparound", "You skip checks"],
    correctAnswer: 0,
    explanation: "Match types to avoid signedness issues.",
  },
  {
    id: 45,
    topic: "Checks",
    question: "A safe access pattern is:",
    options: ["if (index < length) use index", "if (index <= length) use index", "if (index != length) use index", "No checks"],
    correctAnswer: 0,
    explanation: "Index must be strictly less than length.",
  },
  {
    id: 46,
    topic: "Mitigations",
    question: "Using -fsanitize=address helps detect:",
    options: ["OOB accesses at runtime", "SQL injection", "CSRF", "TLS issues"],
    correctAnswer: 0,
    explanation: "ASan detects memory boundary violations.",
  },
  {
    id: 47,
    topic: "Pointers",
    question: "Pointer-to-int conversions are risky because:",
    options: ["They can truncate addresses", "They increase precision", "They prevent OOB", "They encrypt pointers"],
    correctAnswer: 0,
    explanation: "Truncation can lead to invalid offsets.",
  },
  {
    id: 48,
    topic: "Mitigations",
    question: "Memory-safe libraries help by:",
    options: ["Providing bounds-checked APIs", "Disabling validations", "Removing tests", "Hiding errors"],
    correctAnswer: 0,
    explanation: "Safe libraries check bounds for you.",
  },
  {
    id: 49,
    topic: "Kernel",
    question: "OOB reads in kernel space can lead to:",
    options: ["Information disclosure and KASLR bypass", "Only slowdowns", "Only logs", "No impact"],
    correctAnswer: 0,
    explanation: "Kernel OOB reads can leak sensitive data.",
  },
  {
    id: 50,
    topic: "Kernel",
    question: "OOB writes in kernel space can lead to:",
    options: ["Privilege escalation", "Only a warning", "Only slower IO", "Only log noise"],
    correctAnswer: 0,
    explanation: "Kernel memory corruption can escalate privileges.",
  },
  {
    id: 51,
    topic: "Allocator",
    question: "Guard regions in allocators help:",
    options: ["Detect or prevent OOB", "Speed allocations only", "Disable checks", "Reduce memory use only"],
    correctAnswer: 0,
    explanation: "Guard regions can detect overflows.",
  },
  {
    id: 52,
    topic: "Input",
    question: "User-controlled length fields should be:",
    options: ["Validated against actual data", "Trusted blindly", "Ignored", "Used without checks"],
    correctAnswer: 0,
    explanation: "Untrusted lengths must be validated.",
  },
  {
    id: 53,
    topic: "Input",
    question: "Loop bounds should be:",
    options: ["Based on validated lengths", "Based on user input only", "Based on file name length", "Randomized"],
    correctAnswer: 0,
    explanation: "Use validated lengths to avoid OOB.",
  },
  {
    id: 54,
    topic: "Strings",
    question: "Using strlen on untrusted input can:",
    options: ["Read past bounds if no null terminator", "Always be safe", "Encrypt data", "Prevent OOB"],
    correctAnswer: 0,
    explanation: "Missing terminators can cause over-reads.",
  },
  {
    id: 55,
    topic: "Prevention",
    question: "Static analysis can help by:",
    options: ["Flagging risky bounds checks", "Fixing bugs automatically", "Removing tests", "Disabling checks"],
    correctAnswer: 0,
    explanation: "Static tools detect suspicious patterns.",
  },
  {
    id: 56,
    topic: "Prevention",
    question: "Dynamic analysis helps by:",
    options: ["Catching OOB at runtime", "Only linting", "Only code formatting", "Only build checks"],
    correctAnswer: 0,
    explanation: "Runtime tools detect real violations.",
  },
  {
    id: 57,
    topic: "Examples",
    question: "Heartbleed was an example of:",
    options: ["Out-of-bounds read", "Out-of-bounds write", "SQL injection", "CSRF"],
    correctAnswer: 0,
    explanation: "Heartbleed leaked memory via OOB read.",
  },
  {
    id: 58,
    topic: "Impact",
    question: "OOB write differs from OOB read because it:",
    options: ["Changes program state", "Only leaks data", "Is always safe", "Is always detected"],
    correctAnswer: 0,
    explanation: "Writes can corrupt state and control flow.",
  },
  {
    id: 59,
    topic: "Structures",
    question: "OOB reads in struct arrays can leak:",
    options: ["Adjacent object fields", "Only headers", "Only logs", "Only timestamps"],
    correctAnswer: 0,
    explanation: "Adjacent structs may hold sensitive data.",
  },
  {
    id: 60,
    topic: "Structures",
    question: "OOB writes can corrupt:",
    options: ["Vtables or function pointers", "Only constants", "Only stack size", "Only strings"],
    correctAnswer: 0,
    explanation: "Corrupting control pointers can hijack execution.",
  },
  {
    id: 61,
    topic: "Leaks",
    question: "OOB reads can leak:",
    options: ["Canary values or pointers", "Only zeros", "Only nulls", "Only environment variables"],
    correctAnswer: 0,
    explanation: "Leaked values can help bypass mitigations.",
  },
  {
    id: 62,
    topic: "Arrays",
    question: "Multi-dimensional arrays require:",
    options: ["Bounds checks on each dimension", "Only one check", "No checks", "Only size_t casts"],
    correctAnswer: 0,
    explanation: "Each dimension can exceed bounds independently.",
  },
  {
    id: 63,
    topic: "Alignment",
    question: "Memory alignment does:",
    options: ["Not provide bounds checking", "Prevent all OOB", "Encrypt memory", "Disable overflow"],
    correctAnswer: 0,
    explanation: "Alignment is unrelated to bounds safety.",
  },
  {
    id: 64,
    topic: "Heap",
    question: "Heap OOB writes can corrupt:",
    options: ["Allocator metadata and neighbors", "Only stack frames", "Only registers", "Only code segments"],
    correctAnswer: 0,
    explanation: "Heap metadata is stored near chunks.",
  },
  {
    id: 65,
    topic: "Stack",
    question: "Stack OOB writes can corrupt:",
    options: ["Local variables and return addresses", "Only heap chunks", "Only files", "Only sockets"],
    correctAnswer: 0,
    explanation: "Stack corruption can hijack control flow.",
  },
  {
    id: 66,
    topic: "Strings",
    question: "Using strcpy without checks can cause:",
    options: ["OOB writes", "Safe copies", "Automatic truncation", "Only logging"],
    correctAnswer: 0,
    explanation: "strcpy does not validate destination size.",
  },
  {
    id: 67,
    topic: "Strings",
    question: "Using length-1 incorrectly can cause:",
    options: ["Off-by-one bugs", "Safer bounds", "Smaller loops only", "No impact"],
    correctAnswer: 0,
    explanation: "Length math errors often cause one-byte issues.",
  },
  {
    id: 68,
    topic: "Checks",
    question: "Using sentinel values helps by:",
    options: ["Defining clear bounds for validation", "Removing checks", "Adding overflow", "Disabling exceptions"],
    correctAnswer: 0,
    explanation: "Sentinels clarify valid ranges.",
  },
  {
    id: 69,
    topic: "Checks",
    question: "The best practice for indexing is:",
    options: ["Validate index before each access", "Assume inputs are safe", "Use only negative indexes", "Skip checks for speed"],
    correctAnswer: 0,
    explanation: "Always validate index against bounds.",
  },
  {
    id: 70,
    topic: "Concepts",
    question: "OOB differs from use-after-free because:",
    options: ["OOB accesses the wrong bounds, UAF uses freed memory", "They are identical", "UAF is only read", "OOB is only write"],
    correctAnswer: 0,
    explanation: "They are different classes of memory bugs.",
  },
  {
    id: 71,
    topic: "Testing",
    question: "Boundary testing should include:",
    options: ["0, length-1, length, length+1", "Only length/2", "Only random values", "Only negative values"],
    correctAnswer: 0,
    explanation: "Boundary values reveal off-by-one errors.",
  },
  {
    id: 72,
    topic: "Testing",
    question: "A good crash report includes:",
    options: ["Repro input and stack trace", "Only logs", "Only timestamps", "Only file size"],
    correctAnswer: 0,
    explanation: "Repro and traces help debugging.",
  },
  {
    id: 73,
    topic: "Mitigations",
    question: "The most effective mitigation is:",
    options: ["Correct bounds checking and safe APIs", "Relying on ASLR only", "Disabling logs", "Ignoring warnings"],
    correctAnswer: 0,
    explanation: "Fixing bounds checks prevents the bug.",
  },
  {
    id: 74,
    topic: "Mitigations",
    question: "Using memory-safe languages helps because they:",
    options: ["Prevent OOB by design", "Disable all checks", "Remove all tests", "Always allow unsafe casts"],
    correctAnswer: 0,
    explanation: "Memory-safe languages enforce bounds and safety.",
  },
  {
    id: 75,
    topic: "Summary",
    question: "OOB issues are most often caused by:",
    options: ["Incorrect bounds or size handling", "Network latency", "Disk fragmentation", "UI rendering"],
    correctAnswer: 0,
    explanation: "Bounds and size mistakes are the main cause.",
  },
];

// Advanced exploitation scenarios
const advancedExploitationScenarios = [
  {
    context: "Kernel OOB Exploitation",
    description: "Out-of-bounds vulnerabilities in kernel space are particularly dangerous as they can lead to privilege escalation and complete system compromise. Kernel OOB bugs often occur in drivers, system call handlers, and network stack code where complex data structures are parsed from untrusted user input.",
    keyCharacteristics: [
      "Direct access to physical memory and hardware",
      "No ASLR in older kernels, partial KASLR in modern systems",
      "Corrupting kernel structures can bypass all security checks",
      "Stack cookies often absent in kernel code paths",
      "Exploitation typically via syscalls or ioctl interfaces"
    ],
    exploitationApproach: "Identify OOB write in kernel driver → Spray kernel heap with controlled objects → Trigger OOB to corrupt adjacent object → Overwrite function pointer or cred structure → Escalate to root privileges",
    examples: [
      "CVE-2017-7308 - Linux packet socket OOB write enabling privilege escalation",
      "CVE-2016-0728 - Keyring reference count OOB leading to UAF and root",
      "CVE-2022-0847 (Dirty Pipe) - OOB write in pipe buffers for arbitrary file modification"
    ]
  },
  {
    context: "Browser JIT OOB Exploitation",
    description: "Modern JavaScript engines (V8, SpiderMonkey, JavaScriptCore) use Just-In-Time compilation to optimize hot code paths. OOB vulnerabilities in JIT compilers are critical as they occur at the boundary between JavaScript and native code, often allowing attackers to escape the JavaScript sandbox and achieve arbitrary code execution in the browser process.",
    keyCharacteristics: [
      "Type confusion leading to incorrect bounds assumptions",
      "Optimization bugs causing bounds check elimination",
      "Array access optimizations that miss edge cases",
      "JIT-compiled code bypassing runtime safety checks",
      "Complex interactions between interpreter and JIT tiers"
    ],
    exploitationApproach: "Trigger JIT optimization bug → Cause incorrect type assumption → Access JavaScript array OOB → Corrupt adjacent ArrayBuffer or typed array → Gain arbitrary memory read/write → Construct ROP chain or shellcode → Escape sandbox",
    examples: [
      "CVE-2019-11707 - Firefox IonMonkey type confusion OOB write",
      "CVE-2020-16009 - Chrome V8 side-effect modeling error causing OOB access",
      "CVE-2021-30551 - WebKit JavaScriptCore optimization bug leading to OOB"
    ]
  },
  {
    context: "Parser OOB Vulnerabilities",
    description: "File format parsers (PDF, image codecs, document parsers) and network protocol parsers are rich sources of OOB vulnerabilities. These components process complex untrusted input with intricate state machines and size calculations, making them prone to index and length errors.",
    keyCharacteristics: [
      "Length fields from untrusted input used for memory operations",
      "Nested structures with recursive size calculations",
      "Compression/decompression with untrusted size metadata",
      "Multi-stage parsing with state carried between phases",
      "Integer overflows in size calculations"
    ],
    exploitationApproach: "Craft malformed input with invalid length field → Trigger undersized buffer allocation → Cause parser to write beyond buffer → Corrupt heap metadata or adjacent objects → Redirect control flow or leak information",
    examples: [
      "CVE-2014-0160 (Heartbleed) - TLS heartbeat OOB read leaking memory",
      "CVE-2017-0199 - Office RTF parser OOB enabling remote code execution",
      "CVE-2020-1350 (SIGRed) - Windows DNS server integer overflow causing OOB write"
    ]
  },
  {
    context: "Media Decoder OOB Bugs",
    description: "Audio and video decoders handle complex compressed formats with intricate frame structures, color spaces, and codec-specific metadata. OOB vulnerabilities in media decoders are particularly valuable to attackers as media files are commonly shared and automatically processed by applications.",
    keyCharacteristics: [
      "Frame dimension fields controlling buffer allocations",
      "Codec-specific metadata with complex interdependencies",
      "Multi-threaded decoding with shared state",
      "Hardware acceleration paths with different validation",
      "Chroma subsampling and pixel format conversions"
    ],
    exploitationApproach: "Craft malicious media file with invalid dimension metadata → Cause decoder to allocate undersized buffer → Trigger OOB write during frame decode → Corrupt decoder state or adjacent allocations → Achieve code execution when playback reaches corrupted state",
    examples: [
      "CVE-2019-2107 - Android media framework OOB write in video decoder",
      "CVE-2020-15999 - FreeType font rendering OOB write (used in Chrome)",
      "CVE-2021-30737 - Apple CoreAudio OOB read in AAC decoder"
    ]
  }
];

// Common OOB patterns table
const commonOOBPatterns = [
  {
    pattern: "Unchecked Array Index",
    context: "Direct array access with user-controlled index",
    vulnerability: "array[user_input] without bounds validation",
    occurrence: "Configuration parsers, command processors, lookup tables",
    example: "int config_values[100]; return config_values[user_option];",
    fix: "if (user_option >= 0 && user_option < 100) return config_values[user_option];"
  },
  {
    pattern: "Loop Off-by-One",
    context: "Loop condition uses <= instead of < or miscalculates end",
    vulnerability: "for (i = 0; i <= size; i++) writes size+1 elements",
    occurrence: "String processing, array initialization, data copying",
    example: "for (int i = 0; i <= strlen(str); i++) buffer[i] = str[i];",
    fix: "for (int i = 0; i < strlen(str); i++) buffer[i] = str[i]; buffer[strlen(str)] = 0;"
  },
  {
    pattern: "Length Field Trust",
    context: "Using untrusted length field directly for memory operations",
    vulnerability: "memcpy(dest, src, packet->length) without validation",
    occurrence: "Network protocol handlers, file format parsers, IPC mechanisms",
    example: "memcpy(buffer, packet->data, packet->length);",
    fix: "if (packet->length <= sizeof(buffer)) memcpy(buffer, packet->data, packet->length);"
  },
  {
    pattern: "Negative Index as Unsigned",
    context: "Signed negative value interpreted as large unsigned index",
    vulnerability: "int offset = -1; array[(size_t)offset] accesses high memory",
    occurrence: "Offset calculations, relative indexing, error return values",
    example: "int get_offset(); size_t idx = get_offset(); return array[idx];",
    fix: "int offset = get_offset(); if (offset >= 0 && offset < size) return array[offset];"
  },
  {
    pattern: "Integer Overflow in Index",
    context: "Arithmetic on index values wraps, bypassing bounds checks",
    vulnerability: "if (base + offset < size) passes due to overflow",
    occurrence: "Multi-dimensional array access, pointer arithmetic, offset calculations",
    example: "if (base + offset < size) return array[base + offset];",
    fix: "if (base < size && offset < size - base) return array[base + offset];"
  },
  {
    pattern: "String Missing Null Terminator",
    context: "String operation assumes null termination but buffer isn't terminated",
    vulnerability: "strlen(buffer) reads past end if no null terminator",
    occurrence: "Network string parsing, file reading, buffer manipulation",
    example: "char buf[10]; strncpy(buf, input, 10); printf(\"%s\", buf);",
    fix: "char buf[10]; strncpy(buf, input, 9); buf[9] = '\\0'; printf(\"%s\", buf);"
  },
  {
    pattern: "Recursive Structure Size",
    context: "Nested structures with multiplicative size calculations overflow",
    vulnerability: "width * height * bytes_per_pixel overflows, allocates small buffer",
    occurrence: "Image decoders, video processing, matrix operations",
    example: "size_t size = width * height * 4; buffer = malloc(size);",
    fix: "if (width > SIZE_MAX / height / 4) fail; size_t size = width * height * 4;"
  },
  {
    pattern: "Multi-dimensional Unchecked",
    context: "Checking only one dimension of multi-dimensional access",
    vulnerability: "if (x < width) return array[y * width + x]; (y unchecked)",
    occurrence: "2D arrays, image buffers, matrix operations",
    example: "if (x < width) return image[y * width + x];",
    fix: "if (x < width && y < height) return image[y * width + x];"
  }
];

// Platform-specific deep dive
const platformSpecifics = [
  {
    platform: "Windows",
    heapDetails: "Windows uses various heap implementations (NT Heap, Segment Heap, Low-Fragmentation Heap). OOB writes can corrupt heap metadata (HEAP_ENTRY structures) leading to heap exploitation. Heap spray techniques are commonly used to control memory layout.",
    stackDetails: "Stack grows downward from high addresses. Stack cookies (GS cookies) are placed before return addresses. OOB write can overwrite SEH (Structured Exception Handling) chains in addition to return addresses.",
    specificMitigations: [
      "Control Flow Guard (CFG) - Validates indirect call targets",
      "Arbitrary Code Guard (ACG) - Prevents dynamic code generation",
      "Code Integrity Guard (CIG) - Restricts code page modifications",
      "Stack cookies (/GS) - Detects stack buffer overruns",
      "Safe SEH - Validates exception handler addresses"
    ],
    exploitConsiderations: "DEP (Data Execution Prevention) requires ROP chains. ASLR entropy is moderate (8-bit for DLLs on 32-bit). Heap spray more effective on 32-bit. Exception-based techniques (SEH overwrite) are Windows-specific.",
    keyStructures: "HEAP_ENTRY, SEH frames, TEB/PEB structures, virtual function tables"
  },
  {
    platform: "Linux",
    heapDetails: "Linux typically uses ptmalloc2 (glibc) or musl allocator. Heap chunks have metadata (size, prev_size, flags) immediately before allocated data. OOB writes can corrupt chunk metadata enabling heap exploitation techniques like unlink attacks, House of Force, or tcache poisoning.",
    stackDetails: "Stack grows downward with guard pages to detect overflows. Stack canaries (SSP) protect return addresses. No SEH equivalent, but frame pointers and saved registers can be corrupted.",
    specificMitigations: [
      "FORTIFY_SOURCE - Adds bounds checking to common functions",
      "PIE (Position Independent Executable) - Full ASLR",
      "RELRO (Relocation Read-Only) - Makes GOT read-only after relocation",
      "Stack canaries (-fstack-protector-strong)",
      "Seccomp - Restricts system calls available after exploit"
    ],
    exploitConsiderations: "Full ASLR requires PIE compilation. GOT overwrite possible if partial RELRO. Heap exploitation very advanced due to mitigations. Modern kernels have SMAP/SMEP preventing kernel/user mixing.",
    keyStructures: "malloc_chunk metadata, GOT/PLT entries, ELF headers, stack canaries"
  },
  {
    platform: "macOS/iOS",
    heapDetails: "Uses magazine malloc (macOS) or nano allocator (iOS). Heap has guard pages and metadata protection. Zone-based allocation with separate regions for different size classes. Heap randomization is aggressive.",
    stackDetails: "Stack layout similar to Linux but with additional protections. Stack cookies always enabled. iOS has stricter memory protections and more aggressive ASLR.",
    specificMitigations: [
      "Pointer Authentication Codes (PAC) - ARM64 pointer signing (iOS/M1+)",
      "System Integrity Protection (SIP) - Protects critical system files",
      "Hardened Runtime - Restricts dynamic code and library loading",
      "Library Validation - Code signing checks for loaded libraries",
      "Strong ASLR - High entropy randomization across all regions"
    ],
    exploitConsiderations: "PAC makes ROP extremely difficult on ARM64. Code signing prevents shellcode injection. Sandbox and entitlements restrict post-exploitation. JIT regions are tightly controlled. iOS has no executable heap allocations.",
    keyStructures: "Objective-C objects, dispatch tables, PAC-signed pointers, mach ports"
  },
  {
    platform: "Android",
    heapDetails: "Uses jemalloc or Scudo allocator with hardening features. Heap is segregated by thread arenas. Metadata is protected via guard pages and checksums. Native heap separate from Java heap.",
    stackDetails: "Similar to Linux with stack canaries and guard pages. SELinux policies restrict exploitation paths. Stack executable prevention via NX.",
    specificMitigations: [
      "Scudo hardened allocator - Checksums on metadata",
      "SELinux enforcement - Mandatory access control",
      "Seccomp filters - Syscall filtering",
      "Chrome renderer sandbox - Additional process isolation",
      "Control Flow Integrity (CFI) - In system components"
    ],
    exploitConsiderations: "SELinux policies restrict file access and process capabilities. Modern Android has very strong ASLR. WebView exploits need sandbox escape. Root exploits require kernel vulnerability chaining.",
    keyStructures: "JNI method tables, native library GOT/PLT, Binder IPC structures, SELinux contexts"
  }
];

// Platform comparison table
const platformComparison = [
  {
    feature: "Heap Allocator",
    windows: "NT Heap / Segment Heap / LFH",
    linux: "ptmalloc2 / musl",
    macos: "Magazine malloc / Nano",
    android: "jemalloc / Scudo"
  },
  {
    feature: "Stack Cookies",
    windows: "/GS (optional but default)",
    linux: "SSP (-fstack-protector)",
    macos: "Always enabled",
    android: "Always enabled"
  },
  {
    feature: "ASLR Entropy (64-bit)",
    windows: "17-bit (moderate)",
    linux: "28-bit (PIE required)",
    macos: "30+ bit (strong)",
    android: "30+ bit (strong)"
  },
  {
    feature: "Control Flow Protection",
    windows: "CFG / ACG / CIG",
    linux: "CET (Intel CPUs)",
    macos: "PAC (ARM64)",
    android: "CFI (system components)"
  },
  {
    feature: "Heap Hardening",
    windows: "Moderate (LFH randomization)",
    linux: "Strong (tcache checks, safe-linking)",
    macos: "Very Strong (guard pages, metadata protection)",
    android: "Very Strong (Scudo checksums)"
  },
  {
    feature: "Exploitation Difficulty",
    windows: "Medium (older), High (modern)",
    linux: "High (requires PIE + modern hardening)",
    macos: "Very High (PAC + strong mitigations)",
    android: "Very High (SELinux + sandboxing)"
  }
];

// Memory layout structures
const memoryLayoutExamples = [
  {
    structure: "Stack Frame Layout",
    description: "Typical stack frame showing how OOB write can corrupt saved data",
    layout: [
      { offset: "High addresses", content: "Previous frame's data", type: "previous" },
      { offset: "+24", content: "Return address", type: "critical" },
      { offset: "+20", content: "Saved frame pointer (RBP/EBP)", type: "critical" },
      { offset: "+16", content: "Stack canary (if enabled)", type: "protection" },
      { offset: "+8", content: "Local variable 2", type: "safe" },
      { offset: "0 (buffer start)", content: "Local variable 1 (vulnerable buffer)", type: "vulnerable" },
      { offset: "Low addresses", content: "Function arguments / Next frame", type: "previous" }
    ],
    oobImpact: "Writing past buffer[size] overwrites Local variable 2, then canary (detected), then frame pointer (control flow corruption), then return address (code execution)",
    alignment: "Typically 16-byte aligned on modern systems for performance and ABI compliance"
  },
  {
    structure: "Heap Chunk Layout (ptmalloc2)",
    description: "Linux glibc heap chunk showing metadata vulnerable to OOB corruption",
    layout: [
      { offset: "-16", content: "prev_size (if previous chunk is free)", type: "metadata" },
      { offset: "-8", content: "size (includes flags: PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA)", type: "metadata" },
      { offset: "0", content: "User data (allocated region)", type: "safe" },
      { offset: "+size", content: "Next chunk's metadata", type: "vulnerable" }
    ],
    oobImpact: "OOB write can corrupt next chunk's size field, enabling heap exploitation techniques like chunk overlapping, consolidation attacks, or unsafe unlink",
    alignment: "8-byte alignment on 32-bit, 16-byte on 64-bit systems"
  },
  {
    structure: "Array of Structures",
    description: "How structure padding creates gaps that OOB can exploit",
    layout: [
      { offset: "0", content: "struct { char flag; (1 byte)", type: "safe" },
      { offset: "1-3", content: "padding (3 bytes)", type: "padding" },
      { offset: "4", content: "int value; (4 bytes)", type: "safe" },
      { offset: "8", content: "void* ptr; (8 bytes on 64-bit)", type: "critical" },
      { offset: "16", content: "} items[10]; // Next struct starts here", type: "vulnerable" }
    ],
    oobImpact: "Writing to items[10].flag accesses next array element or adjacent heap data. Padding means OOB write at offset 1-3 may not corrupt visible data, making detection harder",
    alignment: "Structure alignment matches largest member (8 bytes for pointer in this case)"
  },
  {
    structure: "Virtual Method Table (vtable)",
    description: "C++ object layout showing vtable pointer vulnerable to OOB corruption",
    layout: [
      { offset: "0", content: "vptr (pointer to vtable)", type: "critical" },
      { offset: "8", content: "Member variable 1", type: "safe" },
      { offset: "16", content: "Member variable 2", type: "safe" },
      { offset: "24", content: "Vulnerable buffer", type: "vulnerable" },
      { offset: "+size", content: "Next object or heap metadata", type: "vulnerable" }
    ],
    oobImpact: "OOB write past buffer corrupts next object. If next object's vptr is corrupted, virtual function call will jump to attacker-controlled address, achieving code execution",
    alignment: "Object alignment based on member types, typically 8-16 bytes"
  }
];

// Memory alignment and padding issues
const alignmentIssues = [
  {
    issue: "Structure Padding",
    description: "Compilers insert padding to align structure members to natural boundaries. This padding creates hidden gaps where OOB writes may land without immediately visible corruption.",
    example: "struct { char a; int b; } has 3 bytes padding between a and b on most platforms",
    implication: "OOB write into padding may go undetected but corrupt the structure in subtle ways. Type confusion can treat padding as valid data.",
    mitigation: "Use __attribute__((packed)) or #pragma pack, but beware performance penalty. Validate structure sizes match expectations."
  },
  {
    issue: "Page Boundaries",
    description: "Memory pages are typically 4KB (4096 bytes). Accessing beyond page boundaries may trigger page fault if next page is unmapped or has different permissions.",
    example: "Buffer at address 0x7fff0ffc (4 bytes from page end). Reading 8 bytes crosses to next page.",
    implication: "Small OOB reads may crash due to page fault, making exploitation unreliable. Attackers must carefully control buffer positioning.",
    mitigation: "Guard pages after allocations will fault on OOB access. AddressSanitizer uses this technique extensively."
  },
  {
    issue: "Cache Line Alignment",
    description: "CPU cache lines are typically 64 bytes. Allocators may align objects to cache line boundaries for performance, creating larger-than-expected gaps between allocations.",
    example: "20-byte allocation padded to 64 bytes for cache alignment, wasting 44 bytes",
    implication: "OOB write might land in padding rather than adjacent object, reducing exploitation reliability but potentially hiding the bug longer.",
    mitigation: "Don't rely on tight packing of allocations. Assume padding exists. Use allocator-specific debugging features to detect OOB in padding."
  },
  {
    issue: "SIMD Alignment Requirements",
    description: "SIMD instructions (SSE, AVX) often require 16 or 32-byte alignment. Buffers processed with SIMD may have strict alignment requirements.",
    example: "AVX2 instruction requires 32-byte alignment. Unaligned access may fault or perform poorly.",
    implication: "Buffer overflow into unaligned region may cause crash in SIMD code path even if OOB write succeeds. Makes some exploitation techniques unreliable.",
    mitigation: "Use aligned_alloc() or posix_memalign() for SIMD buffers. Check alignment before SIMD operations. Validate buffer sizes are multiples of SIMD width."
  }
];

// Advanced debugging techniques
const advancedDebuggingTechniques = [
  {
    category: "GDB/LLDB Commands",
    description: "Essential debugger commands for detecting and analyzing OOB vulnerabilities at runtime",
    commands: [
      {
        command: "watch -l *((char*)buffer + size)",
        purpose: "Set hardware watchpoint on first byte past buffer end. Triggers when OOB write occurs.",
        notes: "Limited number of hardware watchpoints (usually 4). Use for targeted OOB detection."
      },
      {
        command: "catch signal SIGSEGV",
        purpose: "Break on segmentation fault to analyze crash context and determine if OOB access crossed page boundary.",
        notes: "Examine $pc (program counter) and memory maps to identify unmapped access."
      },
      {
        command: "x/100xg $rsp-64",
        purpose: "Examine stack memory around stack pointer to detect stack corruption from OOB writes.",
        notes: "Look for overwritten canaries (pattern like 0x00007f... on 64-bit), corrupted frame pointers, modified return addresses."
      },
      {
        command: "heap chunks",
        purpose: "Display heap chunk metadata (requires gef/pwndbg). Shows size, flags, and corruption.",
        notes: "Look for inconsistent sizes, corrupted PREV_INUSE flags, impossible chunk addresses."
      },
      {
        command: "pattern create 1000 / pattern search $rax",
        purpose: "Generate cyclic pattern to determine exact offset of OOB write in register/memory.",
        notes: "Use pwntools, peda, or gef pattern generation. Helps calculate exact overflow distance."
      }
    ]
  },
  {
    category: "AddressSanitizer Output",
    description: "Interpreting ASan reports to understand OOB context and root cause",
    outputTypes: [
      {
        type: "heap-buffer-overflow",
        sample: "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61400000fe44 at pc 0x... READ of size 4",
        interpretation: "Heap OOB read of 4 bytes. Address 0x614... is ASan's shadow memory region for heap. PC shows exact instruction.",
        actionable: "Examine stack trace to find vulnerable function. Check 'allocated by' and 'located' sections to understand allocation size vs. access offset."
      },
      {
        type: "stack-buffer-overflow",
        sample: "ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc... WRITE of size 1",
        interpretation: "Stack OOB write of 1 byte (classic off-by-one). Address in stack region (0x7ffc...).",
        actionable: "Stack trace shows vulnerable function. Look for loop with <= instead of <, or missing null termination."
      },
      {
        type: "global-buffer-overflow",
        sample: "ERROR: AddressSanitizer: global-buffer-overflow on address 0x... READ of size 8",
        interpretation: "OOB read in global/static array. Common in lookup tables with unchecked index.",
        actionable: "Check if global array is indexed with user input. Verify bounds checking on all access paths."
      },
      {
        type: "Shadow byte legend",
        sample: "Shadow bytes: 00=addressable, fa=left redzone, fb=right redzone",
        interpretation: "ASan uses shadow memory (1 shadow byte per 8 real bytes). Redzones are poisoned regions around allocations.",
        actionable: "If access hits redzone (fa/fb), it's OOB. Shadow byte value indicates offset into redzone."
      }
    ]
  },
  {
    category: "Valgrind Analysis",
    description: "Using Valgrind memcheck to detect OOB and understand memory errors",
    techniques: [
      {
        technique: "Invalid read/write detection",
        command: "valgrind --leak-check=full --track-origins=yes ./program",
        interpretation: "Invalid read of size N at 0x... - Shows OOB access with stack trace. --track-origins traces uninitialized values to allocation.",
        limitations: "Slower than ASan (10-50x). May miss some OOB if access is in valid but wrong memory region."
      },
      {
        technique: "Heap block tracking",
        command: "valgrind --show-leak-kinds=all --malloc-fill=0xAB --free-fill=0xCD",
        interpretation: "Fills allocated memory with 0xAB, freed memory with 0xCD. Helps identify UAF vs. OOB.",
        limitations: "Pattern fill can hide bugs if code happens to work with fill values. Use in combination with AddressSanitizer."
      },
      {
        technique: "Client requests",
        command: "VALGRIND_MALLOCLIKE_BLOCK / VALGRIND_FREELIKE_BLOCK",
        interpretation: "Annotate custom allocators so Valgrind can track them. Essential for non-malloc allocations.",
        limitations: "Requires code modification. May not work with all allocator designs."
      }
    ]
  },
  {
    category: "Memory Dump Analysis",
    description: "Analyzing memory dumps to identify OOB corruption post-mortem",
    approaches: [
      {
        approach: "Canary verification",
        method: "Search crash dump for canary pattern. On Linux, canary is random value stored in TLS. Compare stack value with TLS original.",
        tools: "gdb 'x/gx $fs_base+0x28' shows canary on 64-bit Linux. Compare with stack value before return address.",
        indicators: "Corrupted canary indicates stack overflow. Intact canary with corrupted return address indicates canary bypass or heap corruption."
      },
      {
        approach: "Heap metadata validation",
        method: "Examine heap chunk headers before each allocation. Verify size field, flags (PREV_INUSE), and forward/backward pointers in free chunks.",
        tools: "GDB heap extensions (gef, pwndbg), manual chunk walking with 'x/8gx chunk_address-16'",
        indicators: "Corrupted size field (impossibly large or small), invalid flags, pointers outside heap region indicate OOB heap corruption."
      },
      {
        approach: "Structure integrity checks",
        method: "If OOB corrupted a known structure, compare expected vs. actual layout. Look for type confusion or partial overwrites.",
        tools: "pahole (shows structure layout with padding), GDB pretty-printers for complex types",
        indicators: "Pointer values that don't match expected ranges, bit patterns suggesting partial overwrite, padding bytes changed."
      },
      {
        approach: "Pattern recognition",
        method: "Look for repeated patterns in corrupted region. Attackers often use cyclic patterns or repeated values to control exploitation.",
        tools: "GDB patterns (gef/peda), manual inspection, strings command on dump",
        indicators: "Cyclic patterns like 'AAAABBBBCCCC', repeated addresses, shell code signatures (common x86 instructions)."
      }
    ]
  },
  {
    category: "Root Cause Analysis Workflow",
    description: "Systematic process for tracing OOB bug from crash to root cause",
    steps: [
      {
        step: 1,
        action: "Reproduce under ASan/Valgrind",
        rationale: "Get detailed error report with exact instruction, allocation site, and access offset",
        output: "ASan report showing heap-buffer-overflow at specific PC with allocation stack trace"
      },
      {
        step: 2,
        action: "Identify buffer and index variables",
        rationale: "Trace back from OOB access instruction to find buffer allocation and index calculation",
        output: "Buffer allocated at line X with size Y, accessed at line Z with index calculation I"
      },
      {
        step: 3,
        action: "Trace index dataflow",
        rationale: "Follow index value from user input through calculations to access point",
        output: "Index originates from packet->length, passed through function F, incremented by G, used in access"
      },
      {
        step: 4,
        action: "Find missing or incorrect bounds check",
        rationale: "Identify where validation should occur but doesn't, or where check is incorrect",
        output: "Function F checks if length < 100, but buffer is only 50 bytes. Off-by-one in check (should be < not <=)."
      },
      {
        step: 5,
        action: "Develop minimal reproducer",
        rationale: "Create smallest input that triggers bug, isolating exact condition",
        output: "Bug triggers when input length = buffer_size exactly, due to off-by-one in loop condition"
      },
      {
        step: 6,
        action: "Verify fix and add regression test",
        rationale: "Confirm fix prevents OOB without breaking functionality, ensure future detection",
        output: "Patch changes < to <=, ASan clean, fuzzer regression test added to prevent reintroduction"
      }
    ]
  }
];

// Valgrind/ASan output interpretation table
const sanitizerOutputGuide = [
  {
    errorType: "heap-buffer-overflow (READ)",
    meaning: "Read accessed memory past end of heap allocation",
    severity: "High - Information disclosure, potential crash",
    rootCauses: ["Array index exceeds bounds", "Loop reads one extra element", "Pointer arithmetic error"],
    debugging: "Check allocation size vs. access offset in ASan report. Verify index calculation logic."
  },
  {
    errorType: "heap-buffer-overflow (WRITE)",
    meaning: "Write accessed memory past end of heap allocation",
    severity: "Critical - Memory corruption, code execution potential",
    rootCauses: ["Buffer overflow", "Off-by-one write", "Integer overflow in size calculation"],
    debugging: "Examine write size and destination. Check if size calculation involves untrusted input or can overflow."
  },
  {
    errorType: "stack-buffer-overflow",
    meaning: "Stack buffer accessed beyond bounds",
    severity: "Critical - Stack corruption, return address overwrite",
    rootCauses: ["Local array overflow", "String operation without size limit", "Recursive function with accumulating local variables"],
    debugging: "Check local buffer sizes and access patterns. Look for strcpy, strcat without bounds or loops with <= conditions."
  },
  {
    errorType: "global-buffer-overflow",
    meaning: "Global/static array accessed out of bounds",
    severity: "High - Data segment corruption",
    rootCauses: ["Lookup table with unchecked index", "Configuration array access with user input", "Static buffer overflow"],
    debugging: "Verify all global array accesses have bounds checks. Consider if array should be dynamically sized."
  },
  {
    errorType: "heap-use-after-free",
    meaning: "Accessing freed memory (distinct from OOB but often confused)",
    severity: "Critical - Can be exploited for code execution",
    rootCauses: ["Dangling pointer", "Double-free followed by reallocation", "Lifetime management error"],
    debugging: "Not an OOB issue, but ASan reports it similarly. Check if pointer is freed before use."
  },
  {
    errorType: "Invalid read of size N (Valgrind)",
    meaning: "Valgrind detected access to unallocated or freed memory",
    severity: "High - May be OOB or UAF",
    rootCauses: ["OOB access", "Use after free", "Uninitialized pointer dereference"],
    debugging: "Check if address is near known allocation (OOB) or in freed region (UAF). Valgrind shows allocation/free stack traces."
  },
  {
    errorType: "Conditional jump depends on uninit (Valgrind)",
    meaning: "Control flow based on uninitialized value, may indicate OOB read",
    severity: "Medium - Logic error, potential info leak",
    rootCauses: ["Reading uninitialized stack variable", "OOB read into padding or unallocated region", "Missing initialization"],
    debugging: "Use --track-origins=yes to find where uninitialized value originated. May point to OOB read source."
  }
];

// Case Studies
const caseStudies = [
  {
    name: "Heartbleed (CVE-2014-0160)",
    category: "OOB Read",
    discovered: "April 2014",
    impact: "Critical - Leaked sensitive data from millions of servers including private keys, passwords, session tokens",
    affectedSystems: "OpenSSL 1.0.1 through 1.0.1f (released March 2012 - April 2014)",
    technicalDetails: {
      rootCause: "The TLS heartbeat extension allowed clients to send a payload with a declared length. The server would allocate a response buffer based on client-provided length without validating it against actual payload size. A client could send 1 byte of payload but claim 64KB length.",
      vulnerableCode: "The bug was in ssl/d1_both.c and ssl/t1_lib.c. The server used the client's payload_length field directly: memcpy(bp, pl, payload_length) where pl was the actual payload and payload_length was attacker-controlled.",
      exploitMechanism: "Attacker sends heartbeat request with payload=1 byte but length=65535. Server copies 1 byte from payload, then continues copying 65534 bytes from adjacent server memory into response. This memory contains whatever happens to be next: other users' data, private keys, session tokens.",
      informationLeaked: "Each heartbeat request could leak up to 64KB of server memory. Repeated requests could map out large portions of server memory. Leaked data included: SSL private keys, session cookies, user credentials, personal information, application data.",
      whyItMattered: "The vulnerability affected ~17% of all secure web servers at the time. It was present for 2+ years before discovery, potentially allowing massive historical data theft. The name 'Heartbleed' and logo raised public awareness of SSL/TLS security."
    },
    exploitation: {
      difficulty: "Trivial - Simple crafted packet, no authentication required",
      tools: "Python scripts available within hours of disclosure. Metasploit module released immediately.",
      realWorldUse: "Evidence of exploitation found in logs predating public disclosure. Likely used for espionage and credential theft.",
      detectionDifficulty: "Very hard to detect - leaves minimal logs, looks like normal heartbeat traffic"
    },
    fix: {
      patch: "Added bounds check: if payload_length > actual_payload_length, reject request. Updated memcpy to use actual payload length.",
      code: "if (1 + 2 + payload + 16 > s->s3->rrec.length) return 0; /* silently discard */",
      mitigation: "Revoke and reissue all SSL certificates. Rotate all credentials. Update OpenSSL to 1.0.1g or later.",
      lessons: "Fundamental failure to validate untrusted length field. Code review missed obvious lack of bounds check. Highlights danger of trusting protocol-provided sizes."
    },
    timeline: [
      "March 2012: Vulnerable code introduced in OpenSSL 1.0.1",
      "April 1, 2014: Google Security and Codenomicon independently discover bug",
      "April 7, 2014: Public disclosure with proof-of-concept",
      "April 7-30, 2014: Massive patching effort across internet",
      "Months following: Certificate revocation and reissuance, credential rotation"
    ]
  },
  {
    name: "BlueKeep (CVE-2019-0708)",
    category: "OOB Write",
    discovered: "May 2019",
    impact: "Critical - Wormable remote code execution in RDP without authentication",
    affectedSystems: "Windows XP, Windows 7, Windows Server 2003/2008/2008 R2 (pre-patch), ~1 million internet-exposed systems",
    technicalDetails: {
      rootCause: "The Remote Desktop Protocol (RDP) service had a use-after-free vulnerability in channel handling that could be triggered to cause OOB write. Specifically, the MS_T120 channel handling code failed to properly bind virtual channels, allowing UAF that manifested as OOB write when channel object was reallocated.",
      vulnerableCode: "In termdd.sys driver, the IcaBindChannel and IcaRebindVirtualChannels functions had incorrect reference counting. An attacker could send specially crafted RDP packets during session setup to cause channel object to be freed while still referenced.",
      exploitMechanism: "1) Connect to RDP but don't complete authentication. 2) Send malformed channel join requests to trigger UAF. 3) Spray heap with controlled data to occupy freed channel object memory. 4) Trigger access to dangling channel pointer, causing OOB write with attacker-controlled data. 5) Corrupt adjacent kernel structures to achieve code execution.",
      informationLeaked: "This was primarily an OOB write bug (via UAF), not information disclosure. However, heap grooming to exploit it could potentially leak kernel memory layout information.",
      whyItMattered: "Wormable (can spread without user interaction), affects critical infrastructure, RDP widely exposed to internet, high reliability exploit possible, reminiscent of WannaCry/NotPetya potential."
    },
    exploitation: {
      difficulty: "High - Requires precise heap manipulation and kernel exploitation knowledge",
      tools: "Metasploit module released months after disclosure. Nation-state actors likely had exploits quickly.",
      realWorldUse: "Limited evidence of exploitation in wild. Mostly proof-of-concept demonstrations. Rapid patching prevented WannaCry-scale worm.",
      detectionDifficulty: "Medium - Unusual RDP packets during connection phase, but legitimate failures look similar"
    },
    fix: {
      patch: "Microsoft released patches for even out-of-support Windows XP and Windows 7 due to severity. Fixed reference counting in channel binding code.",
      code: "Added proper channel lifetime management, fixed IcaBindChannel reference count logic, added validation on channel object access.",
      mitigation: "Disable RDP if not needed. Restrict RDP access via firewall to trusted networks only. Enable Network Level Authentication (NLA) as defense-in-depth (though not full mitigation).",
      lessons: "Legacy protocols (RDP dates to 1996) accumulate complex code with subtle bugs. Kernel-mode network protocol parsing is extremely dangerous. Reference counting in kernel is notoriously difficult."
    },
    timeline: [
      "May 14, 2019: Microsoft discloses and patches CVE-2019-0708",
      "May 2019: NSA issues rare public warning about patching urgency",
      "June-July 2019: Scanning activity increases, ~1M vulnerable systems detected",
      "September 2019: Metasploit releases working exploit module",
      "Late 2019: Scanning and exploitation attempts continue, but no major worm emerged"
    ]
  },
  {
    name: "Cloudbleed (2017)",
    category: "OOB Read",
    discovered: "February 2017",
    impact: "Critical - Leaked sensitive customer data across Cloudflare-proxied sites",
    affectedSystems: "Cloudflare edge servers serving ~5-10% of internet traffic. Affected sites included dating sites, hotel bookings, password managers.",
    technicalDetails: {
      rootCause: "Cloudflare's HTML parser (written in Ragel, compiled to C) had an OOB read bug. The parser used pointer arithmetic to traverse HTML documents. Under specific conditions (malformed HTML with certain tag patterns), the pointer would advance past the buffer end, reading adjacent memory.",
      vulnerableCode: "The bug was in cf-html parser's pointer arithmetic. When processing closing tags, the code assumed well-formed HTML and advanced pointers without bounds checking. Pointer could end up past buffer boundary.",
      exploitMechanism: "No attacker action required - bug triggered by legitimate but unusual HTML patterns. When parser hit OOB condition, it read adjacent memory (which might contain other users' data from Cloudflare's request/response buffers) and included it in served HTML. Search engine crawlers cached these leaked pages.",
      informationLeaked: "Private messages, auth tokens, cookies, POST data, passwords, personal information from unrelated Cloudflare customers. Data leaked into served HTML pages and cached by search engines, making it publicly discoverable.",
      whyItMattered: "Affected massive portion of internet. Leaked data was indexed by search engines, making it permanently available. Violated trust boundary between Cloudflare customers. Similar impact to Heartbleed but different mechanism."
    },
    exploitation: {
      difficulty: "N/A - Not deliberately exploitable, but passively leaked data",
      tools: "N/A - Bug triggered by normal traffic patterns",
      realWorldUse: "Data leakage occurred for months before discovery. Search engines indexed leaked data. Evidence found in cache dumps.",
      detectionDifficulty: "Very hard - appeared as occasional garbage in HTML output, easily dismissed as encoding issues"
    },
    fix: {
      patch: "Cloudflare disabled problematic features (email obfuscation, Automatic HTTPS Rewrites, Server-Side Excludes) immediately. Fixed pointer arithmetic in HTML parser to include proper bounds checking.",
      code: "Added bounds checks before pointer advancement: if (ptr + advance_len > buffer_end) { handle_error; } else { ptr += advance_len; }",
      mitigation: "Cloudflare contacted search engines to purge cached pages containing leaked data. Recommended customers rotate credentials and session tokens. No action possible for end users.",
      lessons: "Pointer arithmetic errors in parsers handling untrusted input are extremely dangerous. Manual memory management in C for complex parsing is risky. Fuzzing would likely have caught this. The scale of cloud services amplifies impact of individual bugs."
    },
    timeline: [
      "September 2016: Bug introduced during parser optimization",
      "February 18, 2017: Google Project Zero engineer Tavis Ormandy discovers bug while browsing",
      "February 18, 2017 (hours later): Cloudflare disables vulnerable features, deploys fix",
      "February 23, 2017: Public disclosure by Cloudflare",
      "Following weeks: Search engine cache purging, customer notification, credential rotation"
    ]
  },
  {
    name: "Stack Clash (CVE-2017-1000364 and others)",
    category: "OOB Write",
    discovered: "June 2017",
    impact: "High - Privilege escalation on Linux, *BSD, and other Unix-like systems",
    affectedSystems: "Linux kernel (all versions prior to patches), OpenBSD, NetBSD, FreeBSD, Solaris. Affects many architectures.",
    technicalDetails: {
      rootCause: "Stack Clash is a class of vulnerabilities exploiting insufficient guard pages between memory regions (stack, heap, mmap). The stack grows dynamically but guard pages meant to prevent stack-heap collision could be bypassed. An attacker could cause stack to grow large enough to overlap with another memory region without triggering guard page fault.",
      vulnerableCode: "Kernel's memory management didn't enforce sufficient gap between stack and other mappings. Stack expansion code checked for guard page but could be bypassed with specific allocation patterns. Large stack allocations (alloca, variable-length arrays) could jump over guard page.",
      exploitMechanism: "1) Exploit setuid binary with large stack allocation (alloca or VLA). 2) Trigger stack expansion that jumps over guard page. 3) Stack collides with mapped library or heap. 4) Stack write corrupts library code or heap data. 5) Redirect execution to attacker-controlled code. 6) Achieve privilege escalation to root.",
      informationLeaked: "Not primarily info leak, but stack-heap collision could cause stack data to overwrite heap structures, potentially leaking stack contents into heap-allocated structures accessible to attacker.",
      whyItMattered: "Fundamental OS memory management flaw affecting all major Unix-like systems. Multiple exploitation paths. Affected privilege separation model. Demonstrated importance of memory region gaps."
    },
    exploitation: {
      difficulty: "High - Requires finding suitable setuid binary with large stack allocation, precise heap layout control",
      tools: "Qualys published PoC exploits for specific setuid binaries (sudoedit, exim). Metasploit modules for some variants.",
      realWorldUse: "Primarily used in security research and penetration testing. No evidence of widespread real-world exploitation before patches.",
      detectionDifficulty: "Hard to detect during exploitation. Post-exploit forensics might show unusual memory mappings or corrupted memory regions."
    },
    fix: {
      patch: "Linux kernel patches increased stack guard gap from single page to 256 pages (1MB on 4KB page systems). Added runtime checks for stack-to-heap proximity. Compiler mitigations to limit alloca/VLA sizes.",
      code: "Kernel: Enforce larger gap in vm_unmapped_area. Compilers: -fstack-clash-protection flag to probe stack expansion page-by-page.",
      mitigation: "Update kernel and recompile applications with stack-clash-protection. Reduce use of setuid binaries. Use containers/namespaces for privilege separation rather than setuid.",
      lessons: "Memory region separation is a critical security property. Guard pages must be wide enough to prevent jumping. Compiler and OS must cooperate on stack safety. Decades-old assumptions about memory layout can be wrong."
    },
    timeline: [
      "2010s: Researchers begin exploring stack layout assumptions",
      "2017: Qualys researchers discover multiple exploitation paths",
      "June 19, 2017: Coordinated disclosure with patches",
      "June 2017: Immediate patching by major Linux distributions",
      "Following months: Compiler updates to add -fstack-clash-protection support"
    ]
  },
  {
    name: "Sudo Baron Samedit (CVE-2021-3156)",
    category: "OOB Write",
    discovered: "January 2021",
    impact: "Critical - Local privilege escalation to root on major Linux/Unix systems",
    affectedSystems: "Sudo 1.8.2 through 1.8.31p2 and 1.9.0 through 1.9.5p1 (default install on most Linux distributions, ~10 years of versions)",
    technicalDetails: {
      rootCause: "Heap-based buffer overflow in sudo's command-line argument parsing. When sudo runs in shell mode (sudoedit -s or sudo -s), it unescapes special characters in arguments. An off-by-one error in the unescaping logic allowed writing one byte past the allocated buffer.",
      vulnerableCode: "In sudo's set_cmnd() function, the code removes escape backslashes from arguments. It used a pointer to track position in destination buffer but off-by-one error in size calculation allowed one extra byte write. Bug: size = strlen(src); dst = malloc(size); /* should be size+1 for null terminator */ ... dst[i] = ...; /* can write at dst[size] */",
      exploitMechanism: "1) Run sudoedit -s with crafted argument containing backslashes. 2) Trigger off-by-one write past heap buffer. 3) Overflow into adjacent heap chunk metadata. 4) Corrupt heap structure to cause controlled write later. 5) Use heap exploitation techniques (House of Force or similar) to overwrite service_user structure. 6) Redirect NSS (Name Service Switch) library loading to attacker-controlled library. 7) Escalate to root.",
      informationLeaked: "Primarily OOB write, but heap manipulation could leak heap layout information useful for exploitation.",
      whyItMattered: "Sudo is installed by default on virtually all Linux/Unix systems. Bug present for ~10 years. Any local user could exploit. Single vulnerability compromises fundamental Unix security model of privilege separation."
    },
    exploitation: {
      difficulty: "High - Requires advanced heap exploitation, bypass of modern mitigations (ASLR, heap hardening)",
      tools: "Multiple PoC exploits released by Qualys and security researchers. Exploits tailored to specific distributions due to heap layout differences.",
      realWorldUse: "Likely used in targeted attacks post-disclosure. Widely used in penetration testing. Rapid patching limited widespread exploitation.",
      detectionDifficulty: "Medium - Exploitation involves unusual sudo command lines (sudoedit -s with backslash patterns), but sudo is commonly used so detection requires behavioral analysis"
    },
    fix: {
      patch: "Sudo 1.9.5p2 fixed the off-by-one by correctly calculating buffer size (adding 1 for null terminator) and adding explicit bounds check in unescaping loop.",
      code: "Changed: size = strlen(src); dst = malloc(size); → size = strlen(src) + 1; dst = malloc(size); Also added: if (i >= size - 1) break; before writes.",
      mitigation: "Update sudo to patched version. No workaround exists. Monitor for unusual sudo command lines. Review sudo logs for suspicious patterns.",
      lessons: "Classic off-by-one errors remain prevalent even in mature, widely-reviewed code. String handling in C (malloc size, null termination) is perpetually error-prone. Defense-in-depth (heap hardening) made exploitation harder but not impossible. Regular security audits of privileged software are essential."
    },
    timeline: [
      "July 2011: Vulnerable code introduced in sudo 1.8.2",
      "January 13, 2021: Qualys researchers discover vulnerability",
      "January 26, 2021: Coordinated disclosure and patch release",
      "January 26, 2021: Immediate emergency patching by all major Linux distributions",
      "Following weeks: PoC exploits published, widespread exploitation in penetration tests"
    ]
  }
];

// Common OOB patterns in different contexts - extended table
const oobPatternsInContexts = [
  {
    context: "Protocol Parsers (Network)",
    pattern: "Length field trust",
    description: "Using packet->length directly for buffer operations without validation",
    example: "read(socket, buffer, packet->length); where packet->length is attacker-controlled",
    realWorld: "Heartbleed (TLS), SIGRed (DNS), SMBGhost (SMB)",
    prevention: "Validate length against buffer capacity and maximum protocol limits before use"
  },
  {
    context: "File Format Parsers",
    pattern: "Chunk size trust",
    description: "File headers specify data sizes, parser allocates and copies without verification",
    example: "width*height from PNG header used to allocate image buffer, but values can overflow",
    realWorld: "libpng overflows, ImageMagick vulnerabilities, PDF parser bugs",
    prevention: "Check for integer overflow in size calculations, validate against file size, enforce maximum dimensions"
  },
  {
    context: "String Handling",
    pattern: "Null terminator assumptions",
    description: "Assuming string is null-terminated when it may not be",
    example: "strncpy(dest, src, n); strlen(dest); // dest may not be null-terminated",
    realWorld: "Numerous C string bugs, OpenSSH, sudo vulnerabilities",
    prevention: "Always explicitly null-terminate after strncpy/memcpy, use strlcpy where available"
  },
  {
    context: "Array Indexing",
    pattern: "User-controlled index",
    description: "Direct array access with external input as index without bounds check",
    example: "int config[100]; return config[user_index]; // no validation",
    realWorld: "Kernel driver vulnerabilities, embedded device config parsers",
    prevention: "Always validate index >= 0 && index < array_length before access"
  },
  {
    context: "Loop Iterations",
    pattern: "Off-by-one in condition",
    description: "Using <= instead of < in loop bound, or size instead of size-1",
    example: "for (i=0; i<=size; i++) buffer[i]=val; // writes size+1 times",
    realWorld: "Countless C/C++ vulnerabilities, sudo Baron Samedit",
    prevention: "Use < for exclusive upper bound, carefully review loop conditions, prefer iterators in C++"
  },
  {
    context: "Memory Allocation",
    pattern: "Integer overflow in malloc size",
    description: "Multiplication for allocation size overflows, allocating too-small buffer",
    example: "buf = malloc(width * height * 4); // overflow makes small allocation",
    realWorld: "Image codec vulnerabilities, matrix operation bugs",
    prevention: "Check for overflow before multiplication: if (a > SIZE_MAX/b) fail; size = a*b;"
  },
  {
    context: "Pointer Arithmetic",
    pattern: "Unchecked pointer increment",
    description: "Advancing pointer without checking if it exceeds buffer end",
    example: "char *p=buf; while(*data) *p++=*data++; // no end check",
    realWorld: "Cloudbleed, parser vulnerabilities",
    prevention: "Always check if (p + increment < buf_end) before advancing, use safer iteration patterns"
  },
  {
    context: "Decoders (Audio/Video)",
    pattern: "Frame dimension trust",
    description: "Media file specifies frame dimensions, decoder allocates and fills without validation",
    example: "allocate(frame_width * frame_height); // dimensions from untrusted file",
    realWorld: "FFmpeg vulnerabilities, Android mediaserver bugs, codec exploits",
    prevention: "Enforce maximum dimensions, check overflow in calculations, validate against total file size"
  }
];

// Prevention strategies in practice
const preventionStrategiesInPractice = [
  {
    category: "Secure Coding Checklist",
    description: "Essential practices to incorporate into daily development workflow",
    practices: [
      {
        practice: "Validate all array indices before access",
        implementation: "For any array[index], ensure if (index >= 0 && index < array_length) check exists",
        importance: "Critical - prevents vast majority of OOB bugs",
        automation: "Static analyzers can catch missing checks, custom linters for project patterns"
      },
      {
        practice: "Use size-limited string functions exclusively",
        implementation: "Replace strcpy→strncpy/strlcpy, strcat→strncat/strlcat, sprintf→snprintf",
        importance: "High - eliminates unbounded string copies",
        automation: "Compiler warnings (-Wdeprecated-declarations), ban dangerous functions via linting rules"
      },
      {
        practice: "Always check for integer overflow in size calculations",
        implementation: "Before malloc(a*b), check if (a > 0 && b > SIZE_MAX/a) return error;",
        importance: "Critical - prevents undersized allocations leading to OOB",
        automation: "UBSan detects overflows at runtime, static analysis can catch some patterns"
      },
      {
        practice: "Explicitly null-terminate all strings",
        implementation: "After strncpy or memcpy into string buffer: buf[size-1] = '\\0';",
        importance: "High - prevents string over-reads",
        automation: "Custom static analysis rules, code review checklists"
      },
      {
        practice: "Use unsigned types for sizes and indices",
        implementation: "size_t for lengths/indices, not int or unsigned int (to match SIZE_MAX)",
        importance: "Medium - prevents negative index bugs",
        automation: "Compiler warnings on signedness mismatch, style guides"
      },
      {
        practice: "Validate all external input before use in memory operations",
        implementation: "For any length/size from network, file, user: if (len > MAX || len < MIN) reject;",
        importance: "Critical - untrusted input is primary attack vector",
        automation: "Fuzzing finds missing validation, code review focuses on trust boundaries"
      }
    ]
  },
  {
    category: "Code Review Guidelines",
    description: "What to look for when reviewing code for OOB vulnerabilities",
    guidelines: [
      {
        focus: "Loop boundaries",
        checkFor: "Loop conditions using <= instead of <, off-by-one in upper bound calculations (size vs size-1)",
        redFlags: "for (i=0; i<=n; i++), while (p < end+1), array access at loop_var+1 inside loop",
        reviewAction: "Verify loop executes exactly array_length times, check fence-post errors, test boundary conditions"
      },
      {
        focus: "Memory operations with untrusted sizes",
        checkFor: "memcpy, memset, read, recv, copy operations where size comes from external input",
        redFlags: "memcpy(buf, data, packet->len), read(fd, buffer, user_size), no validation visible",
        reviewAction: "Trace size/length variable to origin, verify bounds check exists, confirm check is correct (<= vs <)"
      },
      {
        focus: "Pointer arithmetic",
        checkFor: "ptr++, ptr += offset, ptr - base used without bounds verification",
        redFlags: "while(*ptr), ptr += user_offset, (ptr - base) used as size without validation",
        reviewAction: "Ensure pointer stays within [buffer, buffer+size), check before dereferencing, verify arithmetic doesn't overflow"
      },
      {
        focus: "Array indexing",
        checkFor: "array[index] where index may be external, calculated, or from untrusted source",
        redFlags: "array[user_input], array[packet->offset], no visible bounds check nearby",
        reviewAction: "Verify bounds check exists and is correct, check for integer overflow in index calculation, confirm signedness matches"
      },
      {
        focus: "String operations",
        checkFor: "strcpy, strcat, sprintf, scanf, gets - all inherently unsafe",
        redFlags: "Any use of these functions, assumptions about input string length",
        reviewAction: "Require replacement with size-limited versions, verify destination buffer size, check null termination"
      },
      {
        focus: "Integer overflow in allocation sizes",
        checkFor: "malloc(a*b), calloc(n, size), array allocation with multiplication",
        redFlags: "No overflow check visible, values come from untrusted input, large multiplications",
        reviewAction: "Verify overflow check before multiplication, use safe multiplication functions, validate against maximum allocations"
      }
    ]
  },
  {
    category: "Defense-in-Depth Architecture",
    description: "Layered security approach to limit OOB impact even if bugs exist",
    layers: [
      {
        layer: "Input Validation Layer",
        purpose: "Sanitize and validate all external input before processing",
        implementation: "Dedicated validation module checking lengths, ranges, formats. Reject malformed input early.",
        benefit: "Prevents malicious input from reaching vulnerable code paths. Reduces attack surface."
      },
      {
        layer: "Memory Safety Layer",
        purpose: "Use memory-safe abstractions where possible",
        implementation: "std::vector/std::string in C++, bounds-checked container classes, smart pointers, RAII",
        benefit: "Language-level bounds checking, automatic memory management, reduced manual error opportunities"
      },
      {
        layer: "Compile-Time Protection",
        purpose: "Enable all compiler security features",
        implementation: "FORTIFY_SOURCE, stack protector, AddressSanitizer in testing, UBSan, -Wall -Wextra -Werror",
        benefit: "Catches bugs at compile time (warnings) and runtime (sanitizers), forces code quality standards"
      },
      {
        layer: "Runtime Protection",
        purpose: "OS-level mitigations to make exploitation harder",
        implementation: "ASLR, DEP/NX, stack canaries, heap hardening, seccomp filters",
        benefit: "Raises exploitation difficulty even if OOB bug exists, may prevent reliable exploitation"
      },
      {
        layer: "Sandboxing Layer",
        purpose: "Isolate vulnerable components",
        implementation: "Separate processes for parsing untrusted input, containers, VMs, privilege separation",
        benefit: "Limits impact of successful exploitation, contains compromise to unprivileged sandbox"
      },
      {
        layer: "Monitoring Layer",
        purpose: "Detect anomalous behavior indicating exploitation attempts",
        implementation: "Crash reporting, anomaly detection, security event logging, runtime application self-protection (RASP)",
        benefit: "Enables incident response even if exploitation succeeds, provides forensic data"
      }
    ]
  }
];

// Dangerous functions table with safe alternatives
const dangerousFunctionsTable = [
  {
    dangerous: "strcpy(dest, src)",
    problem: "No bounds checking, will overflow dest if src is longer",
    safe: "strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1]='\\0';",
    better: "strlcpy(dest, src, sizeof(dest)); // BSD/some Linux",
    notes: "strncpy doesn't always null-terminate, manual termination required"
  },
  {
    dangerous: "strcat(dest, src)",
    problem: "No bounds checking on destination buffer",
    safe: "strncat(dest, src, sizeof(dest)-strlen(dest)-1);",
    better: "strlcat(dest, src, sizeof(dest)); // BSD/some Linux",
    notes: "Must account for existing dest string length in size calculation"
  },
  {
    dangerous: "sprintf(buf, fmt, ...)",
    problem: "No buffer size limit, can overflow buf",
    safe: "snprintf(buf, sizeof(buf), fmt, ...);",
    better: "std::string formatting in C++20, asprintf (check return)",
    notes: "Always use snprintf, verify return value doesn't exceed buffer size"
  },
  {
    dangerous: "gets(buf)",
    problem: "No size parameter, always overflows with long input",
    safe: "fgets(buf, sizeof(buf), stdin);",
    better: "getline() for dynamic allocation, std::getline in C++",
    notes: "gets() is so dangerous it was removed from C11 standard"
  },
  {
    dangerous: "scanf(\"%s\", buf)",
    problem: "No width specifier, reads unlimited input",
    safe: "scanf(\"%99s\", buf); // for char buf[100]",
    better: "fgets + sscanf, or std::cin with limits in C++",
    notes: "Width must be buffer_size-1 to leave room for null terminator"
  },
  {
    dangerous: "memcpy(dest, src, len)",
    problem: "Trusts len parameter, no built-in bounds check",
    safe: "if (len <= sizeof(dest)) memcpy(dest, src, len);",
    better: "std::copy with iterators (C++), explicit bounds check wrapper",
    notes: "Not inherently unsafe, but requires correct len calculation and validation"
  },
  {
    dangerous: "strtok(str, delim)",
    problem: "Modifies source string, not thread-safe, can be misused",
    safe: "strtok_r(str, delim, &saveptr); // thread-safe version",
    better: "std::string::find + substr, dedicated parsing libraries",
    notes: "OOB risk mainly from incorrect buffer sizing based on parsed tokens"
  },
  {
    dangerous: "alloca(size)",
    problem: "Stack allocation with user-controlled size, can overflow stack",
    safe: "malloc(size); // with validation and free()",
    better: "std::vector<T>(size) for dynamic arrays in C++",
    notes: "alloca can jump over stack guard pages (Stack Clash), avoid with untrusted sizes"
  },
  {
    dangerous: "char buf[SIZE]; memcpy(buf, src, user_len);",
    problem: "Trusting user-provided length without validation",
    safe: "if (user_len > SIZE) error; memcpy(buf, src, user_len);",
    better: "std::vector with range checking, or explicit size validation layer",
    notes: "All external lengths must be validated against actual buffer capacity"
  },
  {
    dangerous: "char *p = buf; while(*src) *p++ = *src++;",
    problem: "No check if p exceeds buf+size",
    safe: "char *p=buf, *end=buf+size; while(*src && p<end) *p++=*src++;",
    better: "Use standard library functions with size limits",
    notes: "Manual pointer manipulation requires explicit end-of-buffer checks"
  }
];

// Section navigation
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: "📖" },
  { id: "vulnerability-types", label: "Vulnerability Types", icon: "🎯" },
  { id: "root-causes", label: "Root Causes", icon: "🔍" },
  { id: "advanced-scenarios", label: "Advanced Exploitation", icon: "🔥" },
  { id: "languages", label: "Language Considerations", icon: "💻" },
  { id: "platform-specific", label: "Platform Deep Dive", icon: "🖥️" },
  { id: "memory-layout", label: "Memory Layout & OOB", icon: "📊" },
  { id: "debugging", label: "Advanced Debugging", icon: "🔧" },
  { id: "exploitation", label: "Exploitation Techniques", icon: "⚔️" },
  { id: "common-patterns", label: "Common OOB Patterns", icon: "🎯" },
  { id: "prevention-practice", label: "Prevention in Practice", icon: "✅" },
  { id: "mitigations", label: "Mitigations", icon: "🛡️" },
  { id: "testing", label: "Testing Strategies", icon: "🧪" },
  { id: "case-studies", label: "Case Studies", icon: "📚" },
  { id: "code-examples", label: "Code Examples", icon: "📝" },
  { id: "quiz", label: "Knowledge Check", icon: "❓" },
];

export default function OutOfBoundsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [activeSection, setActiveSection] = useState("intro");
  const [showScrollTop, setShowScrollTop] = useState(false);

  const pageContext = `Out-of-Bounds Read/Write Vulnerabilities - Comprehensive guide covering OOB-R (information disclosure, ASLR bypass) and OOB-W (memory corruption, code execution), root causes (missing bounds checks, off-by-one, integer overflow), language-specific risks (C, C++, Rust, Python), exploitation techniques, mitigations (ASan, bounds checking, safe languages), testing strategies (fuzzing, boundary testing), and secure coding examples.`;

  const accent = "#8b5cf6";

  // Scroll tracking
  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 400);

      const sections = sectionNavItems.map((item) => item.id);
      let currentSection = "intro";

      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150 && rect.bottom >= 150) {
            currentSection = sectionId;
            break;
          }
        }
      }
      setActiveSection(currentSection);
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      const offset = 80;
      const elementPosition = element.getBoundingClientRect().top + window.scrollY;
      window.scrollTo({ top: elementPosition - offset, behavior: "smooth" });
    }
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const progressPercent = ((sectionNavItems.findIndex((item) => item.id === activeSection) + 1) / sectionNavItems.length) * 100;

  // Sidebar Navigation
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        position: "sticky",
        top: 80,
        width: 240,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        display: { xs: "none", md: "block" },
        borderRadius: 3,
        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
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
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}>
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
    <LearnPageLayout pageTitle="Out-of-Bounds Read/Write" pageContext={pageContext}>
      <Box sx={{ display: "flex", gap: 3, position: "relative" }}>
        {/* Sidebar Navigation */}
        {sidebarNav}

        {/* Main Content */}
        <Container maxWidth="lg" sx={{ py: 4, flex: 1 }}>
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
              background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.15)} 0%, ${alpha("#7c3aed", 0.1)} 100%)`,
              border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Box
              sx={{
                position: "absolute",
                top: -50,
                right: -50,
                width: 200,
                height: 200,
                borderRadius: "50%",
                background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)}, transparent)`,
              }}
            />
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #8b5cf6, #7c3aed)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#8b5cf6", 0.3)}`,
                }}
              >
                <DataArrayIcon sx={{ fontSize: 45, color: "white" }} />
              </Box>
              <Box>
                <Chip label="Memory Corruption" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
                  Out-of-Bounds Vulnerabilities
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                  Understanding and preventing buffer boundary violations
                </Typography>
              </Box>
            </Box>
          </Paper>

          {/* Overview Section */}
          <Box id="intro">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <InfoIcon sx={{ color: "#8b5cf6" }} />
                Overview
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Out-of-bounds (OOB) vulnerabilities represent one of the most prevalent classes of memory corruption bugs in systems programming.
                These vulnerabilities occur when software accesses memory beyond the intended boundaries of an allocated buffer, either through
                reading (OOB-R) or writing (OOB-W) operations. Unlike buffer overflows which specifically target sequential writes past buffer
                ends, OOB vulnerabilities encompass any access—read or write, positive or negative offset—that violates buffer boundaries.
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Out-of-bounds reads can leak sensitive information from adjacent memory regions, including cryptographic keys, passwords, memory
                layout information (defeating ASLR), stack canaries, and other security-critical data. Famous vulnerabilities like Heartbleed
                (CVE-2014-0160) demonstrated how a simple OOB read could expose massive amounts of sensitive data from server memory. OOB writes
                are generally more severe, enabling attackers to corrupt program state, overwrite control flow data (return addresses, function
                pointers, vtables), and achieve arbitrary code execution.
              </Typography>
              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                These vulnerabilities are particularly common in languages like C and C++ that provide direct memory access without built-in bounds
                checking. The root causes are diverse: missing bounds validation, off-by-one errors in loop conditions, integer overflows in index
                calculations, signed/unsigned type confusion, and incorrect size assumptions. This guide explores OOB vulnerabilities comprehensively,
                from root causes and language-specific considerations to exploitation techniques, mitigations, and secure coding practices.
              </Typography>

              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>
                      Who This Is For
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Software developers in C/C++/Rust, security researchers, penetration testers, vulnerability analysts, and anyone working
                      with native code or memory-unsafe systems.
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                      Prerequisites
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Basic understanding of C/C++ programming, pointers and arrays, memory layout (stack, heap), and familiarity with debugging
                      tools. Knowledge of basic exploitation concepts is helpful but not required.
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>
                      What You'll Learn
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Root causes of OOB bugs, language-specific risks, exploitation primitives, real-world examples (Heartbleed, BlueKeep),
                      comprehensive mitigations (ASan, bounds checking), and secure coding patterns.
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </Paper>

            {/* Quick Stats */}
            <Grid container spacing={2} sx={{ mb: 5 }}>
              {[
                { value: "2", label: "Vulnerability Types", color: "#8b5cf6", icon: <BugReportIcon /> },
                { value: "6", label: "Root Causes", color: "#ef4444", icon: <WarningIcon /> },
                { value: "4", label: "Languages Covered", color: "#10b981", icon: <CodeIcon /> },
                { value: "4", label: "Exploit Techniques", color: "#3b82f6", icon: <SecurityIcon /> },
                { value: "4", label: "Mitigation Categories", color: "#f59e0b", icon: <CheckCircleIcon /> },
                { value: "4", label: "Testing Strategies", color: "#06b6d4", icon: <BuildIcon /> },
              ].map((stat) => (
                <Grid item xs={6} md={2} key={stat.label}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      borderRadius: 3,
                      border: `1px solid ${alpha(stat.color, 0.2)}`,
                      transition: "all 0.2s",
                      "&:hover": {
                        transform: "translateY(-2px)",
                        boxShadow: `0 4px 20px ${alpha(stat.color, 0.15)}`,
                      },
                    }}
                  >
                    <Box sx={{ color: stat.color, mb: 0.5 }}>{stat.icon}</Box>
                    <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {stat.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            {/* Introduction Alert */}
            <Alert severity="info" icon={<InfoIcon />} sx={{ mb: 4, borderRadius: 3 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Why OOB Vulnerabilities Matter</AlertTitle>
              Out-of-bounds vulnerabilities are responsible for critical security incidents including Heartbleed, CloudFlare's memory leak bug, and
              numerous privilege escalation exploits. Understanding OOB bugs is essential for secure software development and vulnerability research
              in systems programming.
            </Alert>
          </Box>

          {/* Vulnerability Types Section */}
          <Box id="vulnerability-types">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🎯 Vulnerability Types
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Two primary classes of out-of-bounds vulnerabilities with distinct impacts and exploitation paths
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {oobVulnerabilities.map((vuln) => (
                <Grid item xs={12} key={vuln.name}>
                  <Accordion
                    sx={{
                      borderRadius: 3,
                      border: `1px solid ${alpha(vuln.color, 0.2)}`,
                      "&:before": { display: "none" },
                      "&.Mui-expanded": {
                        boxShadow: `0 8px 24px ${alpha(vuln.color, 0.15)}`,
                      },
                    }}
                  >
                    <AccordionSummary
                      expandIcon={<ExpandMoreIcon />}
                      sx={{
                        bgcolor: alpha(vuln.color, 0.05),
                        "&:hover": { bgcolor: alpha(vuln.color, 0.08) },
                        borderRadius: 3,
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%", gap: 2 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                          <Box
                            sx={{
                              width: 48,
                              height: 48,
                              borderRadius: 2,
                              bgcolor: vuln.color,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              color: "white",
                            }}
                          >
                            {vuln.icon}
                          </Box>
                          <Box>
                            <Typography variant="h6" sx={{ fontWeight: 700 }}>
                              {vuln.name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {vuln.description}
                            </Typography>
                          </Box>
                        </Box>
                        <Chip
                          label={vuln.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(vuln.color, 0.1),
                            color: vuln.color,
                            fontWeight: 600,
                          }}
                        />
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={3}>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                            Security Impacts:
                          </Typography>
                          <List dense>
                            {vuln.impacts.map((impact, idx) => (
                              <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <CheckCircleIcon sx={{ fontSize: 16, color: vuln.color }} />
                                </ListItemIcon>
                                <ListItemText primary={impact} primaryTypographyProps={{ variant: "body2" }} />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                            Common Scenarios:
                          </Typography>
                          <List dense>
                            {vuln.commonScenarios.map((scenario, idx) => (
                              <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <BugReportIcon sx={{ fontSize: 16, color: vuln.color }} />
                                </ListItemIcon>
                                <ListItemText primary={scenario} primaryTypographyProps={{ variant: "body2" }} />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                            Real-World Examples:
                          </Typography>
                          <Grid container spacing={2}>
                            {vuln.realWorldExamples.map((example, idx) => (
                              <Grid item xs={12} md={6} key={idx}>
                                <Paper sx={{ p: 2, bgcolor: alpha(vuln.color, 0.03), borderRadius: 2 }}>
                                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: vuln.color }}>
                                    {example.name}
                                  </Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    {example.description}
                                  </Typography>
                                </Paper>
                              </Grid>
                            ))}
                          </Grid>
                        </Grid>
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Root Causes Section */}
          <Box id="root-causes">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🔍 Root Causes of OOB Vulnerabilities
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Common programming errors that lead to out-of-bounds memory access
            </Typography>

            <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Root Cause</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Vulnerable Example</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Fix</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Severity</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rootCauses.map((cause) => (
                    <TableRow key={cause.cause} sx={{ "&:hover": { bgcolor: alpha("#ef4444", 0.02) } }}>
                      <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{cause.cause}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{cause.description}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#000", 0.02) }}>{cause.example}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#10b981", 0.05) }}>{cause.fix}</TableCell>
                      <TableCell>
                        <Chip
                          label={cause.severity}
                          size="small"
                          sx={{
                            bgcolor: cause.severity === "Critical" ? alpha("#ef4444", 0.1) : alpha("#f59e0b", 0.1),
                            color: cause.severity === "Critical" ? "#ef4444" : "#f59e0b",
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>

          {/* Language Considerations Section */}
          <Box id="languages">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              💻 Language-Specific Considerations
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              How different programming languages handle bounds checking and memory safety
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {languageConsiderations.map((lang) => (
                <Grid item xs={12} md={6} key={lang.language}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                      transition: "all 0.2s",
                      "&:hover": {
                        boxShadow: `0 8px 24px ${alpha("#3b82f6", 0.15)}`,
                      },
                    }}
                  >
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>
                        {lang.language}
                      </Typography>
                      <Chip
                        label={lang.risks.split(" - ")[0]}
                        size="small"
                        sx={{
                          bgcolor:
                            lang.risks.includes("High")
                              ? alpha("#ef4444", 0.1)
                              : lang.risks.includes("Medium")
                                ? alpha("#f59e0b", 0.1)
                                : alpha("#10b981", 0.1),
                          color: lang.risks.includes("High") ? "#ef4444" : lang.risks.includes("Medium") ? "#f59e0b" : "#10b981",
                          fontWeight: 600,
                        }}
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      <strong>Features:</strong> {lang.features}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      <strong>Risk Level:</strong> {lang.risks}
                    </Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      Safe Practices:
                    </Typography>
                    <List dense>
                      {lang.safePractices.map((practice, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                          </ListItemIcon>
                          <ListItemText primary={practice} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 2, mb: 0.5 }}>
                      Unsafe APIs/Patterns:
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {lang.unsafeAPIs.map((api) => (
                        <Chip key={api} label={api} size="small" sx={{ fontSize: "0.7rem", bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Advanced Exploitation Scenarios Section */}
          <Box id="advanced-scenarios">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🔥 Advanced Exploitation Scenarios
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Deep dive into OOB exploitation in kernel, browser JIT, parsers, and media decoders
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {advancedExploitationScenarios.map((scenario) => (
                <Grid item xs={12} key={scenario.context}>
                  <Paper
                    sx={{
                      p: 3,
                      borderRadius: 3,
                      border: `1px solid ${alpha("#ef4444", 0.2)}`,
                      "&:hover": {
                        boxShadow: `0 8px 24px ${alpha("#ef4444", 0.15)}`,
                      },
                    }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                      {scenario.context}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                      {scenario.description}
                    </Typography>

                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      Key Characteristics:
                    </Typography>
                    <List dense>
                      {scenario.keyCharacteristics.map((char, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <BugReportIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                          </ListItemIcon>
                          <ListItemText primary={char} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>

                    <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, mb: 2 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 1 }}>
                        Exploitation Approach:
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {scenario.exploitationApproach}
                      </Typography>
                    </Paper>

                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                      Real-World Examples:
                    </Typography>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                      {scenario.examples.map((example, idx) => (
                        <Chip key={idx} label={example} size="small" sx={{ fontSize: "0.7rem", bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            {/* Common OOB Patterns Table */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Common OOB Patterns in Exploitation Contexts
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Pattern</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Context</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Vulnerability</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Where It Occurs</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Fix</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {commonOOBPatterns.map((pattern, idx) => (
                    <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha("#ef4444", 0.02) } }}>
                      <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{pattern.pattern}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{pattern.context}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#ef4444", 0.05) }}>{pattern.vulnerability}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{pattern.occurrence}</TableCell>
                      <TableCell sx={{ fontSize: "0.7rem", fontFamily: "monospace" }}>{pattern.example}</TableCell>
                      <TableCell sx={{ fontSize: "0.7rem", fontFamily: "monospace", bgcolor: alpha("#10b981", 0.05) }}>{pattern.fix}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>

          {/* Platform-Specific Deep Dive Section */}
          <Box id="platform-specific">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🖥️ Platform-Specific Deep Dive
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Understanding OOB exploitation nuances across Windows, Linux, macOS/iOS, and Android
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {platformSpecifics.map((platform) => (
                <Grid item xs={12} md={6} key={platform.platform}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                      "&:hover": {
                        boxShadow: `0 8px 24px ${alpha("#3b82f6", 0.15)}`,
                      },
                    }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                      {platform.platform}
                    </Typography>

                    <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                      Heap Details:
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2, fontSize: "0.85rem" }}>
                      {platform.heapDetails}
                    </Typography>

                    <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                      Stack Details:
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2, fontSize: "0.85rem" }}>
                      {platform.stackDetails}
                    </Typography>

                    <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 1 }}>
                      Platform-Specific Mitigations:
                    </Typography>
                    <List dense>
                      {platform.specificMitigations.map((mit, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 12, color: "#10b981" }} />
                          </ListItemIcon>
                          <ListItemText primary={mit} primaryTypographyProps={{ variant: "caption", fontSize: "0.75rem" }} />
                        </ListItem>
                      ))}
                    </List>

                    <Alert severity="info" sx={{ mt: 2, fontSize: "0.75rem" }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                        Exploit Considerations:
                      </Typography>
                      <Typography variant="caption">{platform.exploitConsiderations}</Typography>
                    </Alert>

                    <Paper sx={{ p: 1.5, mt: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                        Key Structures:
                      </Typography>
                      <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                        {platform.keyStructures}
                      </Typography>
                    </Paper>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            {/* Platform Comparison Table */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Cross-Platform Comparison
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Feature</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Windows</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Linux</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>macOS</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Android</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {platformComparison.map((row, idx) => (
                    <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha("#3b82f6", 0.02) } }}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.feature}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{row.windows}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{row.linux}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{row.macos}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{row.android}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>

          {/* Memory Layout and OOB Section */}
          <Box id="memory-layout">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              📊 Memory Layout and OOB Implications
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Understanding how memory structures, alignment, and padding affect OOB vulnerabilities
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {memoryLayoutExamples.map((example) => (
                <Grid item xs={12} md={6} key={example.structure}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                    }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 1.5, color: "#8b5cf6" }}>
                      {example.structure}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                      {example.description}
                    </Typography>

                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 700, fontSize: "0.7rem" }}>Offset</TableCell>
                            <TableCell sx={{ fontWeight: 700, fontSize: "0.7rem" }}>Content</TableCell>
                            <TableCell sx={{ fontWeight: 700, fontSize: "0.7rem" }}>Type</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {example.layout.map((item, idx) => (
                            <TableRow
                              key={idx}
                              sx={{
                                bgcolor:
                                  item.type === "critical"
                                    ? alpha("#ef4444", 0.05)
                                    : item.type === "vulnerable"
                                      ? alpha("#f59e0b", 0.05)
                                      : item.type === "protection"
                                        ? alpha("#10b981", 0.05)
                                        : "transparent",
                              }}
                            >
                              <TableCell sx={{ fontSize: "0.7rem", fontFamily: "monospace" }}>{item.offset}</TableCell>
                              <TableCell sx={{ fontSize: "0.7rem" }}>{item.content}</TableCell>
                              <TableCell>
                                <Chip
                                  label={item.type}
                                  size="small"
                                  sx={{
                                    fontSize: "0.6rem",
                                    height: 18,
                                    bgcolor:
                                      item.type === "critical"
                                        ? alpha("#ef4444", 0.1)
                                        : item.type === "vulnerable"
                                          ? alpha("#f59e0b", 0.1)
                                          : item.type === "protection"
                                            ? alpha("#10b981", 0.1)
                                            : alpha("#64748b", 0.1),
                                    color:
                                      item.type === "critical"
                                        ? "#ef4444"
                                        : item.type === "vulnerable"
                                          ? "#f59e0b"
                                          : item.type === "protection"
                                            ? "#10b981"
                                            : "#64748b",
                                  }}
                                />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>

                    <Alert severity="warning" sx={{ mt: 2, fontSize: "0.75rem" }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                        OOB Impact:
                      </Typography>
                      <Typography variant="caption">{example.oobImpact}</Typography>
                    </Alert>

                    <Paper sx={{ p: 1.5, mt: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700 }}>
                        Alignment: {example.alignment}
                      </Typography>
                    </Paper>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            {/* Alignment and Padding Issues */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Memory Alignment and Padding Issues
            </Typography>
            <Grid container spacing={2} sx={{ mb: 5 }}>
              {alignmentIssues.map((issue) => (
                <Grid item xs={12} md={6} key={issue.issue}>
                  <Accordion
                    sx={{
                      borderRadius: 2,
                      border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                      "&:before": { display: "none" },
                    }}
                  >
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: alpha("#8b5cf6", 0.05) }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                        {issue.issue}
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                        {issue.description}
                      </Typography>
                      <Paper sx={{ p: 1.5, bgcolor: alpha("#000", 0.02), borderRadius: 1, mb: 1.5 }}>
                        <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                          Example:
                        </Typography>
                        <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                          {issue.example}
                        </Typography>
                      </Paper>
                      <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                        Implication:
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
                        {issue.implication}
                      </Typography>
                      <Alert severity="success" sx={{ fontSize: "0.7rem" }}>
                        <Typography variant="caption" sx={{ fontWeight: 700 }}>
                          Mitigation:
                        </Typography>{" "}
                        <Typography variant="caption">{issue.mitigation}</Typography>
                      </Alert>
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Advanced Debugging Techniques Section */}
          <Box id="debugging">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🔧 Advanced Debugging Techniques
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Expert-level debugging approaches for detecting, analyzing, and understanding OOB vulnerabilities
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {advancedDebuggingTechniques.map((technique) => (
                <Grid item xs={12} key={technique.category}>
                  <Accordion
                    sx={{
                      borderRadius: 3,
                      border: `1px solid ${alpha("#06b6d4", 0.2)}`,
                      "&:before": { display: "none" },
                    }}
                  >
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: alpha("#06b6d4", 0.05) }}>
                      <Box>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>
                          {technique.category}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {technique.description}
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      {technique.commands && (
                        <Grid container spacing={2}>
                          {technique.commands.map((cmd, idx) => (
                            <Grid item xs={12} key={idx}>
                              <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
                                <Paper
                                  sx={{
                                    p: 1,
                                    bgcolor: alpha("#000", 0.05),
                                    fontFamily: "monospace",
                                    fontSize: "0.75rem",
                                    mb: 1,
                                    borderRadius: 1,
                                  }}
                                >
                                  {cmd.command}
                                </Paper>
                                <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                                  Purpose:
                                </Typography>
                                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                                  {cmd.purpose}
                                </Typography>
                                <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                                  Notes:
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {cmd.notes}
                                </Typography>
                              </Paper>
                            </Grid>
                          ))}
                        </Grid>
                      )}
                      {technique.outputTypes && (
                        <Grid container spacing={2}>
                          {technique.outputTypes.map((output, idx) => (
                            <Grid item xs={12} md={6} key={idx}>
                              <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                                <Chip label={output.type} size="small" sx={{ mb: 1.5, bgcolor: "#06b6d4", color: "white", fontWeight: 700 }} />
                                <Paper
                                  sx={{
                                    p: 1,
                                    bgcolor: alpha("#000", 0.05),
                                    fontFamily: "monospace",
                                    fontSize: "0.65rem",
                                    mb: 1.5,
                                    borderRadius: 1,
                                  }}
                                >
                                  {output.sample}
                                </Paper>
                                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                                  {output.interpretation}
                                </Typography>
                                <Alert severity="info" sx={{ fontSize: "0.7rem" }}>
                                  <Typography variant="caption" sx={{ fontWeight: 700 }}>
                                    Action:
                                  </Typography>{" "}
                                  {output.actionable}
                                </Alert>
                              </Paper>
                            </Grid>
                          ))}
                        </Grid>
                      )}
                      {technique.techniques && (
                        <Grid container spacing={2}>
                          {technique.techniques.map((tech, idx) => (
                            <Grid item xs={12} key={idx}>
                              <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
                                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                                  {tech.technique}
                                </Typography>
                                <Paper
                                  sx={{
                                    p: 1,
                                    bgcolor: alpha("#000", 0.05),
                                    fontFamily: "monospace",
                                    fontSize: "0.7rem",
                                    mb: 1,
                                    borderRadius: 1,
                                  }}
                                >
                                  {tech.command}
                                </Paper>
                                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                                  {tech.interpretation}
                                </Typography>
                                <Typography variant="caption" sx={{ fontWeight: 700, color: "#ef4444" }}>
                                  Limitations: {tech.limitations}
                                </Typography>
                              </Paper>
                            </Grid>
                          ))}
                        </Grid>
                      )}
                      {technique.approaches && (
                        <Grid container spacing={2}>
                          {technique.approaches.map((approach, idx) => (
                            <Grid item xs={12} md={6} key={idx}>
                              <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>
                                  {approach.approach}
                                </Typography>
                                <Typography variant="caption" sx={{ display: "block", mb: 1, fontSize: "0.75rem" }}>
                                  <strong>Method:</strong> {approach.method}
                                </Typography>
                                <Typography variant="caption" sx={{ display: "block", mb: 1, fontSize: "0.75rem" }}>
                                  <strong>Tools:</strong> {approach.tools}
                                </Typography>
                                <Paper sx={{ p: 1, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 1 }}>
                                  <Typography variant="caption" sx={{ fontSize: "0.7rem" }}>
                                    <strong>Indicators:</strong> {approach.indicators}
                                  </Typography>
                                </Paper>
                              </Paper>
                            </Grid>
                          ))}
                        </Grid>
                      )}
                      {technique.steps && (
                        <Box>
                          {technique.steps.map((step) => (
                            <Paper key={step.step} sx={{ p: 2, mb: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
                              <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                                <Chip
                                  label={`Step ${step.step}`}
                                  sx={{ bgcolor: "#06b6d4", color: "white", fontWeight: 700, minWidth: 70 }}
                                />
                                <Box sx={{ flex: 1 }}>
                                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                                    {step.action}
                                  </Typography>
                                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                                    {step.rationale}
                                  </Typography>
                                  <Paper sx={{ p: 1, bgcolor: alpha("#10b981", 0.1), borderRadius: 1 }}>
                                    <Typography variant="caption" sx={{ fontSize: "0.7rem", fontStyle: "italic" }}>
                                      {step.output}
                                    </Typography>
                                  </Paper>
                                </Box>
                              </Box>
                            </Paper>
                          ))}
                        </Box>
                      )}
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>

            {/* Sanitizer Output Guide Table */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Sanitizer Output Interpretation Guide
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Error Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Meaning</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Severity</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Root Causes</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Debugging</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sanitizerOutputGuide.map((guide, idx) => (
                    <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha("#06b6d4", 0.02) } }}>
                      <TableCell sx={{ fontWeight: 600, fontFamily: "monospace", fontSize: "0.75rem" }}>{guide.errorType}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{guide.meaning}</TableCell>
                      <TableCell>
                        <Chip
                          label={guide.severity.split(" - ")[0]}
                          size="small"
                          sx={{
                            bgcolor: guide.severity.includes("Critical")
                              ? alpha("#ef4444", 0.1)
                              : guide.severity.includes("High")
                                ? alpha("#f59e0b", 0.1)
                                : alpha("#3b82f6", 0.1),
                            color: guide.severity.includes("Critical") ? "#ef4444" : guide.severity.includes("High") ? "#f59e0b" : "#3b82f6",
                            fontWeight: 600,
                            fontSize: "0.7rem",
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontSize: "0.75rem" }}>{guide.rootCauses.join(", ")}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem" }}>{guide.debugging}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>

          {/* Exploitation Techniques Section */}
          <Box id="exploitation">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              ⚔️ Exploitation Techniques
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              How attackers leverage OOB vulnerabilities for information disclosure and code execution
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {exploitTechniques.map((tech) => (
                <Grid item xs={12} key={tech.name}>
                  <Accordion
                    sx={{
                      borderRadius: 3,
                      border: `1px solid ${alpha("#6366f1", 0.2)}`,
                      "&:before": { display: "none" },
                    }}
                  >
                    <AccordionSummary
                      expandIcon={<ExpandMoreIcon />}
                      sx={{
                        bgcolor: alpha("#6366f1", 0.05),
                        "&:hover": { bgcolor: alpha("#6366f1", 0.08) },
                        borderRadius: 3,
                      }}
                    >
                      <Box sx={{ width: "100%" }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#6366f1", mb: 0.5 }}>
                          {tech.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {tech.description}
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        <Grid item xs={12} md={4}>
                          <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                            Requirements:
                          </Typography>
                          <List dense>
                            {tech.requirements.map((req, idx) => (
                              <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 20 }}>
                                  <CheckCircleIcon sx={{ fontSize: 12, color: "#6366f1" }} />
                                </ListItemIcon>
                                <ListItemText primary={req} primaryTypographyProps={{ variant: "caption" }} />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                        <Grid item xs={12} md={8}>
                          <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                            Exploitation Steps:
                          </Typography>
                          <List dense>
                            {tech.steps.map((step, idx) => (
                              <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 28 }}>
                                  <Chip label={idx + 1} size="small" sx={{ width: 20, height: 20, fontSize: "0.65rem", bgcolor: "#6366f1", color: "white" }} />
                                </ListItemIcon>
                                <ListItemText primary={step} primaryTypographyProps={{ variant: "caption" }} />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                        <Grid item xs={12}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#6366f1", 0.05), borderRadius: 2 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: "#6366f1" }}>
                              Impact: {tech.impact}
                            </Typography>
                          </Paper>
                        </Grid>
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Common OOB Patterns Section */}
          <Box id="common-patterns">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🎯 Common OOB Patterns Across Codebases
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Recurring patterns and anti-patterns that lead to OOB vulnerabilities in different contexts
            </Typography>

            <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Context</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pattern</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Real-World CVEs</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Prevention</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {oobPatternsInContexts.map((pattern, idx) => (
                    <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha("#8b5cf6", 0.02) } }}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{pattern.context}</TableCell>
                      <TableCell sx={{ fontWeight: 600, fontSize: "0.8rem" }}>{pattern.pattern}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{pattern.description}</TableCell>
                      <TableCell sx={{ fontSize: "0.7rem", fontFamily: "monospace", bgcolor: alpha("#ef4444", 0.05) }}>{pattern.example}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem" }}>{pattern.realWorld}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", bgcolor: alpha("#10b981", 0.05) }}>{pattern.prevention}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>

          {/* Prevention Strategies in Practice Section */}
          <Box id="prevention-practice">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              ✅ Prevention Strategies in Practice
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Practical, actionable strategies for preventing OOB vulnerabilities in real-world development
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {preventionStrategiesInPractice.map((category) => (
                <Grid item xs={12} key={category.category}>
                  <Accordion
                    sx={{
                      borderRadius: 3,
                      border: `1px solid ${alpha("#10b981", 0.2)}`,
                      "&:before": { display: "none" },
                    }}
                  >
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: alpha("#10b981", 0.05) }}>
                      <Box>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981" }}>
                          {category.category}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {category.description}
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      {category.practices && (
                        <Grid container spacing={2}>
                          {category.practices.map((practice, idx) => (
                            <Grid item xs={12} md={6} key={idx}>
                              <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.03), borderRadius: 2, height: "100%" }}>
                                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                                  {practice.practice}
                                </Typography>
                                <Paper
                                  sx={{
                                    p: 1.5,
                                    bgcolor: alpha("#000", 0.02),
                                    fontFamily: "monospace",
                                    fontSize: "0.7rem",
                                    mb: 1.5,
                                    borderRadius: 1,
                                  }}
                                >
                                  {practice.implementation}
                                </Paper>
                                <Chip
                                  label={practice.importance}
                                  size="small"
                                  sx={{
                                    mb: 1,
                                    bgcolor: practice.importance.includes("Critical") ? alpha("#ef4444", 0.1) : alpha("#f59e0b", 0.1),
                                    color: practice.importance.includes("Critical") ? "#ef4444" : "#f59e0b",
                                    fontWeight: 600,
                                  }}
                                />
                                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                                  <strong>Automation:</strong> {practice.automation}
                                </Typography>
                              </Paper>
                            </Grid>
                          ))}
                        </Grid>
                      )}
                      {category.guidelines && (
                        <Grid container spacing={2}>
                          {category.guidelines.map((guideline, idx) => (
                            <Grid item xs={12} key={idx}>
                              <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.03), borderRadius: 2 }}>
                                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                                  Focus: {guideline.focus}
                                </Typography>
                                <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                                  <strong>Check For:</strong> {guideline.checkFor}
                                </Typography>
                                <Alert severity="warning" sx={{ mb: 1.5, fontSize: "0.75rem" }}>
                                  <Typography variant="caption" sx={{ fontWeight: 700 }}>
                                    Red Flags:
                                  </Typography>{" "}
                                  {guideline.redFlags}
                                </Alert>
                                <Alert severity="success" sx={{ fontSize: "0.75rem" }}>
                                  <Typography variant="caption" sx={{ fontWeight: 700 }}>
                                    Review Action:
                                  </Typography>{" "}
                                  {guideline.reviewAction}
                                </Alert>
                              </Paper>
                            </Grid>
                          ))}
                        </Grid>
                      )}
                      {category.layers && (
                        <Grid container spacing={2}>
                          {category.layers.map((layer, idx) => (
                            <Grid item xs={12} md={6} key={idx}>
                              <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.03), borderRadius: 2, height: "100%" }}>
                                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                                  {layer.layer}
                                </Typography>
                                <Typography variant="caption" sx={{ display: "block", mb: 1, fontSize: "0.75rem" }}>
                                  <strong>Purpose:</strong> {layer.purpose}
                                </Typography>
                                <Typography variant="caption" sx={{ display: "block", mb: 1, fontSize: "0.75rem" }}>
                                  <strong>Implementation:</strong> {layer.implementation}
                                </Typography>
                                <Paper sx={{ p: 1, bgcolor: alpha("#10b981", 0.1), borderRadius: 1 }}>
                                  <Typography variant="caption" sx={{ fontSize: "0.7rem" }}>
                                    <strong>Benefit:</strong> {layer.benefit}
                                  </Typography>
                                </Paper>
                              </Paper>
                            </Grid>
                          ))}
                        </Grid>
                      )}
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>

            {/* Dangerous Functions Table */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Dangerous Functions and Safe Alternatives
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Dangerous Function</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Problem</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Safe Alternative</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Better Option</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dangerousFunctionsTable.map((func, idx) => (
                    <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha("#ef4444", 0.02) } }}>
                      <TableCell sx={{ fontWeight: 600, fontFamily: "monospace", fontSize: "0.8rem", color: "#ef4444", bgcolor: alpha("#ef4444", 0.05) }}>
                        {func.dangerous}
                      </TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{func.problem}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", bgcolor: alpha("#f59e0b", 0.05) }}>{func.safe}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", bgcolor: alpha("#10b981", 0.05) }}>{func.better}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem" }}>{func.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>

          {/* Mitigations Section */}
          <Box id="mitigations">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🛡️ Mitigations and Defenses
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Comprehensive strategies to prevent and detect out-of-bounds vulnerabilities
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {mitigationStrategies.map((category) => (
                <Grid item xs={12} md={6} key={category.category}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha(category.color, 0.2)}`,
                    }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: category.color }}>
                      {category.category}
                    </Typography>
                    <List dense>
                      {category.techniques.map((tech) => (
                        <ListItem key={tech.name} sx={{ flexDirection: "column", alignItems: "flex-start", py: 1.5, px: 0 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, width: "100%" }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
                              {tech.name}
                            </Typography>
                            <Chip
                              label={tech.effectiveness}
                              size="small"
                              sx={{
                                bgcolor:
                                  tech.effectiveness === "Very High"
                                    ? alpha("#10b981", 0.1)
                                    : tech.effectiveness === "High"
                                      ? alpha("#3b82f6", 0.1)
                                      : alpha("#f59e0b", 0.1),
                                color:
                                  tech.effectiveness === "Very High" ? "#10b981" : tech.effectiveness === "High" ? "#3b82f6" : "#f59e0b",
                                fontWeight: 600,
                                fontSize: "0.7rem",
                              }}
                            />
                          </Box>
                          <Typography variant="caption" color="text.secondary" sx={{ mb: 1 }}>
                            {tech.description}
                          </Typography>
                          <Paper
                            sx={{
                              p: 1,
                              bgcolor: alpha("#000", 0.02),
                              fontFamily: "monospace",
                              fontSize: "0.7rem",
                              width: "100%",
                              borderRadius: 1,
                            }}
                          >
                            {tech.implementation}
                          </Paper>
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Alert severity="success" icon={<CheckCircleIcon />} sx={{ mb: 5, borderRadius: 3 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Defense in Depth</AlertTitle>
              Combine multiple mitigation layers for robust protection: use bounds checking in code, enable AddressSanitizer during testing, choose
              memory-safe languages when possible, and deploy system-level mitigations (ASLR, stack canaries) in production.
            </Alert>
          </Box>

          {/* Testing Strategies Section */}
          <Box id="testing">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              🧪 Testing Strategies
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Methods to discover out-of-bounds vulnerabilities before attackers do
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {testingStrategies.map((strategy) => (
                <Grid item xs={12} md={6} key={strategy.strategy}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha("#06b6d4", 0.2)}`,
                      transition: "all 0.2s",
                      "&:hover": {
                        boxShadow: `0 8px 24px ${alpha("#06b6d4", 0.15)}`,
                      },
                    }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
                      {strategy.strategy}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {strategy.description}
                    </Typography>
                    {strategy.testCases && (
                      <>
                        <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                          Test Cases:
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                          {strategy.testCases.map((tc) => (
                            <Chip key={tc} label={tc} size="small" variant="outlined" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }} />
                          ))}
                        </Box>
                      </>
                    )}
                    {strategy.tools && (
                      <>
                        <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                          Recommended Tools:
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                          {strategy.tools.map((tool) => (
                            <Chip key={tool} label={tool} size="small" sx={{ bgcolor: alpha("#06b6d4", 0.1), color: "#06b6d4" }} />
                          ))}
                        </Box>
                      </>
                    )}
                    {strategy.properties && (
                      <>
                        <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                          Properties to Test:
                        </Typography>
                        <List dense>
                          {strategy.properties.map((prop, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                              <ListItemText primary={prop} primaryTypographyProps={{ variant: "caption", fontFamily: "monospace" }} />
                            </ListItem>
                          ))}
                        </List>
                        <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5, mt: 1 }}>
                          Tools:
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                          {strategy.tools?.map((tool) => (
                            <Chip key={tool} label={tool} size="small" sx={{ fontSize: "0.7rem" }} />
                          ))}
                        </Box>
                      </>
                    )}
                    {strategy.configuration && (
                      <>
                        <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                          Configuration:
                        </Typography>
                        <Paper sx={{ p: 1, bgcolor: alpha("#000", 0.02), fontFamily: "monospace", fontSize: "0.7rem", mb: 2, borderRadius: 1 }}>
                          {strategy.configuration}
                        </Paper>
                      </>
                    )}
                    {strategy.approach && (
                      <>
                        <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                          Approach:
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                          {strategy.approach}
                        </Typography>
                      </>
                    )}
                    <Paper sx={{ p: 1.5, bgcolor: alpha("#06b6d4", 0.05), borderRadius: 2 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                        Expected Result:
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {strategy.expectedResult}
                      </Typography>
                    </Paper>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Case Studies Section */}
          <Box id="case-studies">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              📚 Real-World Case Studies
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              In-depth analysis of major OOB vulnerabilities, their exploitation, impact, and lessons learned
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {caseStudies.map((study) => (
                <Grid item xs={12} key={study.name}>
                  <Accordion
                    sx={{
                      borderRadius: 3,
                      border: `1px solid ${alpha("#ef4444", 0.2)}`,
                      "&:before": { display: "none" },
                    }}
                  >
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: alpha("#ef4444", 0.05) }}>
                      <Box sx={{ width: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%", gap: 2 }}>
                          <Box>
                            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>
                              {study.name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {study.category} | Discovered: {study.discovered}
                            </Typography>
                          </Box>
                          <Chip
                            label={study.impact.split(" - ")[0]}
                            sx={{ bgcolor: alpha("#ef4444", 0.2), color: "#ef4444", fontWeight: 700 }}
                          />
                        </Box>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={3}>
                        <Grid item xs={12}>
                          <Alert severity="error" icon={<WarningIcon />}>
                            <AlertTitle sx={{ fontWeight: 700 }}>Impact</AlertTitle>
                            {study.impact}
                          </Alert>
                        </Grid>

                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#ef4444" }}>
                              Affected Systems
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {study.affectedSystems}
                            </Typography>
                          </Paper>
                        </Grid>

                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#3b82f6" }}>
                              Technical Details
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                              <strong>Root Cause:</strong> {study.technicalDetails.rootCause}
                            </Typography>
                          </Paper>
                        </Grid>

                        <Grid item xs={12}>
                          <Accordion sx={{ bgcolor: alpha("#f59e0b", 0.03), "&:before": { display: "none" } }}>
                            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                                Vulnerable Code & Exploitation
                              </Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                              <Typography variant="caption" sx={{ display: "block", mb: 1.5, lineHeight: 1.6 }}>
                                <strong>Vulnerable Code:</strong> {study.technicalDetails.vulnerableCode}
                              </Typography>
                              <Typography variant="caption" sx={{ display: "block", mb: 1.5, lineHeight: 1.6 }}>
                                <strong>Exploit Mechanism:</strong> {study.technicalDetails.exploitMechanism}
                              </Typography>
                              <Typography variant="caption" sx={{ display: "block", mb: 1.5, lineHeight: 1.6 }}>
                                <strong>Information Leaked:</strong> {study.technicalDetails.informationLeaked}
                              </Typography>
                              <Alert severity="info" sx={{ fontSize: "0.75rem" }}>
                                <Typography variant="caption" sx={{ fontWeight: 700 }}>
                                  Why It Mattered:
                                </Typography>{" "}
                                {study.technicalDetails.whyItMattered}
                              </Alert>
                            </AccordionDetails>
                          </Accordion>
                        </Grid>

                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#8b5cf6" }}>
                              Exploitation Details
                            </Typography>
                            <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                              <strong>Difficulty:</strong> {study.exploitation.difficulty}
                            </Typography>
                            <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                              <strong>Tools:</strong> {study.exploitation.tools}
                            </Typography>
                            <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                              <strong>Real-World Use:</strong> {study.exploitation.realWorldUse}
                            </Typography>
                            <Typography variant="caption" sx={{ display: "block" }}>
                              <strong>Detection Difficulty:</strong> {study.exploitation.detectionDifficulty}
                            </Typography>
                          </Paper>
                        </Grid>

                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.03), borderRadius: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#10b981" }}>
                              Fix & Mitigation
                            </Typography>
                            <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                              <strong>Patch:</strong> {study.fix.patch}
                            </Typography>
                            {study.fix.code && (
                              <Paper
                                sx={{
                                  p: 1,
                                  mb: 1,
                                  bgcolor: alpha("#000", 0.05),
                                  fontFamily: "monospace",
                                  fontSize: "0.65rem",
                                  borderRadius: 1,
                                }}
                              >
                                {study.fix.code}
                              </Paper>
                            )}
                            <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                              <strong>Mitigation:</strong> {study.fix.mitigation}
                            </Typography>
                            <Alert severity="success" sx={{ fontSize: "0.7rem" }}>
                              <Typography variant="caption" sx={{ fontWeight: 700 }}>
                                Lessons:
                              </Typography>{" "}
                              {study.fix.lessons}
                            </Alert>
                          </Paper>
                        </Grid>

                        <Grid item xs={12}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#64748b", 0.03), borderRadius: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>
                              Timeline
                            </Typography>
                            <List dense>
                              {study.timeline.map((event, idx) => (
                                <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                                  <ListItemIcon sx={{ minWidth: 28 }}>
                                    <Chip
                                      label={idx + 1}
                                      size="small"
                                      sx={{ width: 24, height: 24, fontSize: "0.65rem", bgcolor: "#64748b", color: "white" }}
                                    />
                                  </ListItemIcon>
                                  <ListItemText primary={event} primaryTypographyProps={{ variant: "caption", fontSize: "0.75rem" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Paper>
                        </Grid>
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>

            <Alert severity="warning" icon={<TipsAndUpdatesIcon />} sx={{ mb: 5, borderRadius: 3 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Key Takeaways from Case Studies</AlertTitle>
              These real-world vulnerabilities demonstrate that OOB bugs can persist for years in mature, widely-reviewed code. Common
              themes include: trusting untrusted length fields (Heartbleed, Cloudbleed), off-by-one errors (Baron Samedit), insufficient
              memory region separation (Stack Clash), and complex state machines with subtle bugs (BlueKeep). Defense-in-depth is
              critical - no single mitigation prevented these exploits, but layered defenses made exploitation harder and detection
              easier.
            </Alert>
          </Box>

          {/* Code Examples Section */}
          <Box id="code-examples">
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
              📝 Code Examples
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Side-by-side comparison of vulnerable and secure code patterns
            </Typography>

            <Grid container spacing={3} sx={{ mb: 5 }}>
              {codeExamples.map((example, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha(example.title.includes("Vulnerable") ? "#ef4444" : "#10b981", 0.2)}`,
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                      {example.title.includes("Vulnerable") ? (
                        <WarningIcon sx={{ color: "#ef4444" }} />
                      ) : (
                        <CheckCircleIcon sx={{ color: "#10b981" }} />
                      )}
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>
                        {example.title}
                      </Typography>
                    </Box>
                    <Chip label={example.language} size="small" sx={{ mb: 2 }} />
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: alpha("#000", 0.05),
                        fontFamily: "monospace",
                        fontSize: "0.8rem",
                        overflowX: "auto",
                        borderRadius: 2,
                        mb: 2,
                      }}
                    >
                      <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{example.code}</pre>
                    </Paper>
                    <Alert
                      severity={example.title.includes("Vulnerable") ? "error" : "success"}
                      icon={example.title.includes("Vulnerable") ? <WarningIcon /> : <CheckCircleIcon />}
                      sx={{ borderRadius: 2 }}
                    >
                      <Typography variant="caption" sx={{ fontWeight: 700 }}>
                        {example.title.includes("Vulnerable") ? "Issue:" : "Improvement:"}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        {example.title.includes("Vulnerable") ? example.issue : example.improvement}
                      </Typography>
                    </Alert>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Related Learning */}
          <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <SchoolIcon sx={{ color: "#8b5cf6" }} />
              Related Learning Topics
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              <Chip label="Buffer Overflow →" clickable onClick={() => navigate("/learn/buffer-overflow")} sx={{ fontWeight: 600 }} />
              <Chip label="Integer Overflow →" clickable onClick={() => navigate("/learn/integer-overflow")} sx={{ fontWeight: 600 }} />
              <Chip label="Heap Exploitation →" clickable onClick={() => navigate("/learn/heap-exploitation")} sx={{ fontWeight: 600 }} />
              <Chip label="Binary Analysis Guide →" clickable onClick={() => navigate("/learn/binary-analysis")} sx={{ fontWeight: 600 }} />
            </Box>
          </Paper>

          {/* Quiz Section */}
          <Paper
            id="quiz"
            sx={{
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
              title="Out-of-Bounds Vulnerabilities Knowledge Check"
              description="Random 10-question quiz drawn from a 75-question bank covering OOB reads/writes, root causes, mitigations, and secure coding."
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
        </Container>

        {/* Scroll to Top FAB */}
        {showScrollTop && (
          <Tooltip title="Scroll to top" placement="left">
            <IconButton
              onClick={scrollToTop}
              sx={{
                position: "fixed",
                bottom: 24,
                right: 24,
                bgcolor: accent,
                color: "white",
                "&:hover": {
                  bgcolor: alpha(accent, 0.8),
                },
                boxShadow: `0 4px 20px ${alpha(accent, 0.3)}`,
              }}
            >
              <KeyboardArrowUpIcon />
            </IconButton>
          </Tooltip>
        )}
      </Box>
    </LearnPageLayout>
  );
}
