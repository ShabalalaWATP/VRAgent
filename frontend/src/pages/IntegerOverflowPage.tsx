import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  AlertTitle,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
  Card,
  CardContent,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CalculateIcon from "@mui/icons-material/Calculate";
import WarningIcon from "@mui/icons-material/Warning";
import CodeIcon from "@mui/icons-material/Code";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import MemoryIcon from "@mui/icons-material/Memory";
import TerminalIcon from "@mui/icons-material/Terminal";
import ShieldIcon from "@mui/icons-material/Shield";
import ErrorIcon from "@mui/icons-material/Error";
import DataObjectIcon from "@mui/icons-material/DataObject";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import HistoryEduIcon from "@mui/icons-material/HistoryEdu";
import ScienceIcon from "@mui/icons-material/Science";
import TranslateIcon from "@mui/icons-material/Translate";
import { Link, useNavigate } from "react-router-dom";

// CodeBlock component for syntax highlighting
const CodeBlock: React.FC<{ children: string; language?: string; title?: string }> = ({
  children,
  language = "c",
  title,
}) => {
  return (
    <Box sx={{ my: 2 }}>
      {title && (
        <Typography
          variant="caption"
          sx={{
            display: "block",
            bgcolor: "action.selected",
            px: 2,
            py: 0.5,
            borderTopLeftRadius: 8,
            borderTopRightRadius: 8,
            fontWeight: 600,
          }}
        >
          {title}
        </Typography>
      )}
      <Box
        component="pre"
        sx={{
          bgcolor: "grey.900",
          color: "grey.100",
          p: 2,
          borderRadius: title ? "0 0 8px 8px" : 2,
          overflow: "auto",
          fontSize: "0.8rem",
          fontFamily: "monospace",
          m: 0,
          "& code": {
            fontFamily: "inherit",
          },
        }}
      >
        <code>{children}</code>
      </Box>
    </Box>
  );
};

interface VulnType {
  title: string;
  description: string;
  example: string;
  color: string;
}

const vulnTypes: VulnType[] = [
  {
    title: "Integer Overflow",
    description: "Value exceeds maximum, wraps to minimum (or small positive)",
    example: "UINT_MAX + 1 = 0",
    color: "#ef4444",
  },
  {
    title: "Integer Underflow",
    description: "Value goes below minimum, wraps to maximum",
    example: "0u - 1 = UINT_MAX",
    color: "#f59e0b",
  },
  {
    title: "Signed/Unsigned Mismatch",
    description: "Signed negative interpreted as large unsigned value",
    example: "(unsigned)(-1) = 4294967295",
    color: "#8b5cf6",
  },
  {
    title: "Width Truncation",
    description: "Larger type cast to smaller loses high bits",
    example: "(short)0x12345678 = 0x5678",
    color: "#3b82f6",
  },
];

const exploitScenarios = [
  "Buffer size calculation -> heap/stack overflow",
  "Loop bounds -> out-of-bounds access",
  "Memory allocation size -> undersized buffer",
  "Array indexing -> arbitrary read/write",
  "Length checks bypass -> buffer overflow",
];

const codePatterns = [
  { pattern: "size + offset", risk: "Overflow before allocation" },
  { pattern: "count * sizeof()", risk: "Multiplication overflow" },
  { pattern: "len - header_size", risk: "Underflow if len < header_size" },
  { pattern: "(int)user_input", risk: "Sign issues if input > INT_MAX" },
];

const rootCauses = [
  "Implicit type conversions and integer promotions",
  "Arithmetic on user-controlled sizes (count * size)",
  "Assuming values are non-negative or within range",
  "Mixing signed and unsigned types in comparisons",
  "Narrowing casts from 64-bit to 32-bit types",
  "Off-by-one errors at boundaries (MAX, MIN)",
];

const untrustedSources = [
  "Network protocol length fields and headers",
  "File format metadata (dimensions, offsets, counts)",
  "API parameters and JSON numeric values",
  "Database values stored in smaller types",
  "Compression or decompression sizes",
  "Time calculations (timeouts, durations, TTL)",
];

const conversionPitfalls = [
  {
    rule: "Signed to unsigned comparison",
    example: "if (offset < size)",
    risk: "negative becomes huge and bypasses checks",
  },
  {
    rule: "Integer promotion in expressions",
    example: "uint8_t a, b; int c = a + b;",
    risk: "overflow checks on smaller type are ineffective",
  },
  {
    rule: "Narrowing cast",
    example: "uint32_t n = (uint64_t)len;",
    risk: "truncation hides large values",
  },
  {
    rule: "Mixed signedness arithmetic",
    example: "size_t n; int len; if (len - n > 0)",
    risk: "underflow to a large unsigned value",
  },
  {
    rule: "Loop index type mismatch",
    example: "for (int i = 0; i < size_t_len; i++)",
    risk: "size_t_len > INT_MAX causes incorrect bounds",
  },
];

const boundaryValues = [
  "0, 1, 2",
  "MAX - 1, MAX, MAX + 1",
  "MIN, MIN - 1 (signed)",
  "Powers of two (2^n) and 2^n +/- 1",
  "Values that wrap: (MAX / size) + 1",
  "Negative values and -1 (often becomes MAX when cast)",
];

const safeSizingWorkflow = [
  {
    title: "Normalize inputs",
    detail: "Reject negative values before converting to unsigned types.",
  },
  {
    title: "Validate ranges",
    detail: "Check against protocol or format limits before arithmetic.",
  },
  {
    title: "Use checked arithmetic",
    detail: "Use builtins or checked_* helpers for add and multiply.",
  },
  {
    title: "Allocate and verify",
    detail: "Check allocation results and track computed size.",
  },
  {
    title: "Use the computed size",
    detail: "Never reuse the original untrusted length after checks.",
  },
];

// Data type limits for different architectures
const dataTypeLimits = [
  { type: "char", signed: "-128 to 127", unsigned: "0 to 255", bits: 8 },
  { type: "short", signed: "-32,768 to 32,767", unsigned: "0 to 65,535", bits: 16 },
  { type: "int", signed: "-2,147,483,648 to 2,147,483,647", unsigned: "0 to 4,294,967,295", bits: 32 },
  { type: "long (32-bit)", signed: "-2,147,483,648 to 2,147,483,647", unsigned: "0 to 4,294,967,295", bits: 32 },
  { type: "long (64-bit)", signed: "-9.2e18 to 9.2e18", unsigned: "0 to 1.8e19", bits: 64 },
  { type: "size_t (32-bit)", signed: "N/A", unsigned: "0 to 4,294,967,295", bits: 32 },
  { type: "size_t (64-bit)", signed: "N/A", unsigned: "0 to 1.8e19", bits: 64 },
];

// Real-world CVEs
const realWorldCVEs = [
  {
    cve: "CVE-2021-21224",
    name: "Chrome V8 Integer Overflow",
    description: "Integer overflow in V8 JavaScript engine leading to heap buffer overflow and RCE",
    impact: "Remote Code Execution in Chrome/Edge browsers",
    cvss: "8.8",
    year: 2021,
    details: "The vulnerability existed in the handling of typed arrays. An attacker-controlled integer overflow allowed allocation of undersized buffers, leading to out-of-bounds writes.",
  },
  {
    cve: "CVE-2016-0728",
    name: "Linux Kernel Keyring Overflow",
    description: "Reference counter overflow in Linux kernel keyring facility",
    impact: "Local privilege escalation to root on Linux systems",
    cvss: "7.8",
    year: 2016,
    details: "A reference counter of type 'atomic_t' (32-bit signed) could be overflowed after ~4 billion increments, causing use-after-free leading to code execution.",
  },
  {
    cve: "CVE-2019-14287",
    name: "sudo Integer Underflow",
    description: "User ID -1 interpreted as root user (UID 0)",
    impact: "Privilege escalation to root via sudo",
    cvss: "8.8",
    year: 2019,
    details: "When specifying user ID -1 (0xFFFFFFFF), sudo interpreted this as user ID 0 (root) due to integer conversion, bypassing sudoers restrictions.",
  },
  {
    cve: "CVE-2020-0796",
    name: "SMBGhost",
    description: "Integer overflow in SMBv3 compression",
    impact: "Remote code execution on Windows 10",
    cvss: "10.0",
    year: 2020,
    details: "Integer overflow in Windows SMBv3 protocol handling during decompression. The overflow in OriginalSize field calculation led to buffer overflow and wormable RCE.",
  },
];

// Detailed vulnerable code examples
const vulnerableCodeExamples = [
  {
    name: "Classic Size Calculation Overflow",
    language: "c",
    vulnerable: `// VULNERABLE: Integer overflow in size calculation
void process_data(uint32_t count) {
    // If count = 0x40000001 (1,073,741,825)
    // size = count * 4 = 0x100000004 = 4 (truncated!)
    uint32_t size = count * sizeof(uint32_t);

    uint32_t *buffer = malloc(size);  // Allocates only 4 bytes!

    for (uint32_t i = 0; i < count; i++) {
        buffer[i] = read_input();  // HEAP OVERFLOW!
    }
}`,
    fixed: `// FIXED: Check for overflow before calculation
void process_data(uint32_t count) {
    // Check if multiplication would overflow
    if (count > SIZE_MAX / sizeof(uint32_t)) {
        return;  // Error: would overflow
    }

    size_t size = (size_t)count * sizeof(uint32_t);
    uint32_t *buffer = malloc(size);
    if (!buffer) return;

    for (uint32_t i = 0; i < count; i++) {
        buffer[i] = read_input();
    }
}`,
    explanation: "When count is large enough, multiplying by sizeof(uint32_t) causes overflow, resulting in a small allocation but large copy loop.",
  },
  {
    name: "Signed/Unsigned Comparison Bug",
    language: "c",
    vulnerable: `// VULNERABLE: Signed/unsigned comparison
int validate_offset(int offset, size_t buffer_size) {
    // Attacker provides offset = -1
    // Comparison: -1 < buffer_size?
    // -1 becomes 0xFFFFFFFF (unsigned), which is > buffer_size!
    if (offset < buffer_size) {
        return buffer[offset];  // Negative index!
    }
    return -1;
}`,
    fixed: `// FIXED: Explicit bounds checking
int validate_offset(int offset, size_t buffer_size) {
    // Check for negative first
    if (offset < 0) {
        return -1;  // Reject negative offsets
    }

    // Now safe to compare as unsigned
    if ((size_t)offset < buffer_size) {
        return buffer[offset];
    }
    return -1;
}`,
    explanation: "When a signed negative value is compared with unsigned, it's implicitly converted to a very large unsigned value, bypassing the bounds check.",
  },
  {
    name: "Length Subtraction Underflow",
    language: "c",
    vulnerable: `// VULNERABLE: Length underflow
void parse_packet(uint8_t *packet, size_t packet_len) {
    struct header *hdr = (struct header *)packet;

    // If packet_len = 10 and HEADER_SIZE = 16
    // data_len = 10 - 16 = underflow = huge number!
    size_t data_len = packet_len - HEADER_SIZE;

    // Copies way too much data!
    memcpy(data_buffer, packet + HEADER_SIZE, data_len);
}`,
    fixed: `// FIXED: Validate length before subtraction
void parse_packet(uint8_t *packet, size_t packet_len) {
    struct header *hdr = (struct header *)packet;

    // Validate minimum size first
    if (packet_len < HEADER_SIZE) {
        return;  // Packet too small
    }

    size_t data_len = packet_len - HEADER_SIZE;
    memcpy(data_buffer, packet + HEADER_SIZE, data_len);
}`,
    explanation: "Subtracting from an unsigned value when the result would be negative causes underflow, wrapping to a very large positive value.",
  },
  {
    name: "Width Truncation Attack",
    language: "c",
    vulnerable: `// VULNERABLE: 64-bit to 32-bit truncation
void allocate_buffer(uint64_t requested_size) {
    // Attacker requests 0x100000010 (4GB + 16 bytes)
    // After truncation: size = 0x10 = 16 bytes
    uint32_t size = (uint32_t)requested_size;

    char *buffer = malloc(size);  // 16 bytes allocated

    // But we copy 4GB + 16 bytes!
    read_data(buffer, requested_size);  // OVERFLOW!
}`,
    fixed: `// FIXED: Validate before truncation
void allocate_buffer(uint64_t requested_size) {
    // Check if size fits in 32 bits
    if (requested_size > UINT32_MAX) {
        return;  // Size too large
    }

    uint32_t size = (uint32_t)requested_size;
    char *buffer = malloc(size);
    if (buffer) {
        read_data(buffer, size);  // Use truncated size
    }
}`,
    explanation: "When a 64-bit value is cast to 32-bit, high bits are lost. Attackers craft values where low 32 bits are small but full value is large.",
  },
];

// Detection tools and techniques
const detectionTools = [
  {
    name: "GCC/Clang Sanitizers",
    type: "Compiler",
    description: "UBSan (Undefined Behavior Sanitizer) catches integer overflows at runtime",
    usage: "-fsanitize=undefined -fsanitize=integer -ftrapv",
    pros: ["Runtime detection", "Precise error location", "Low overhead"],
    cons: ["Requires recompilation", "Only finds executed paths"],
  },
  {
    name: "Clang Static Analyzer",
    type: "Static Analysis",
    description: "Detects potential integer overflows through code path analysis",
    usage: "scan-build make / clang --analyze",
    pros: ["No runtime overhead", "Finds unexplored paths", "IDE integration"],
    cons: ["False positives", "May miss complex overflows"],
  },
  {
    name: "CodeQL",
    type: "Static Analysis",
    description: "Query-based analysis with pre-built integer overflow queries",
    usage: "codeql database analyze --queries=cpp-security-and-quality.qls",
    pros: ["Free for open source", "Customizable queries", "CI/CD integration"],
    cons: ["Learning curve", "Requires database creation"],
  },
  {
    name: "AFL++/LibFuzzer",
    type: "Fuzzing",
    description: "Coverage-guided fuzzers that can trigger integer overflows",
    usage: "afl-fuzz -i input -o output -- ./target @@",
    pros: ["Finds real bugs", "Automated exploration", "Generates test cases"],
    cons: ["Time-intensive", "May miss rare paths"],
  },
];

// Language-specific behaviors
const languageBehaviors = [
  {
    language: "C/C++",
    behavior: "Undefined behavior for signed overflow, wrapping for unsigned",
    notes: "Compiler may optimize based on assumption that signed overflow doesn't occur",
    mitigations: ["Use -fwrapv for defined signed wrap", "Use safe integer libraries", "Enable sanitizers"],
  },
  {
    language: "Java",
    behavior: "Wrapping behavior for all integer types (defined)",
    notes: "No exceptions thrown, Math.addExact() throws ArithmeticException",
    mitigations: ["Use Math.*Exact() methods", "Manual bounds checking", "BigInteger for large numbers"],
  },
  {
    language: "Python 3",
    behavior: "Arbitrary precision integers (no overflow)",
    notes: "Integers automatically grow to accommodate large values",
    mitigations: ["Still vulnerable to algorithmic complexity attacks", "Memory exhaustion possible"],
  },
  {
    language: "Rust",
    behavior: "Panic in debug mode, wrapping in release mode",
    notes: "Wrapping_* methods for explicit wrapping, checked_* for Option return",
    mitigations: ["Use checked_* or saturating_* methods", "Debug builds catch bugs", "Clippy lint warnings"],
  },
  {
    language: "Go",
    behavior: "Wrapping behavior (defined), no panic",
    notes: "math.MaxInt64 constants available for bounds checking",
    mitigations: ["Manual bounds checking required", "Use math/big for arbitrary precision"],
  },
  {
    language: "JavaScript",
    behavior: "64-bit floating point (precision loss at 2^53)",
    notes: "BigInt type for arbitrary precision integers",
    mitigations: ["Use BigInt for large integers", "Check Number.MAX_SAFE_INTEGER"],
  },
];

// Safe integer libraries
const safeLibraries = [
  {
    name: "SafeInt (Microsoft)",
    language: "C++",
    description: "Template class for safe integer operations with exception on overflow",
    example: `SafeInt<int> a = 1000000;
SafeInt<int> b = 1000000;
SafeInt<int> c = a * b;  // Throws on overflow`,
  },
  {
    name: "safe_iop",
    language: "C",
    description: "Safe integer operation macros for C",
    example: `uint32_t result;
if (!safe_mul(&result, count, sizeof(int))) {
    // Overflow would occur
    return ERROR;
}`,
  },
  {
    name: "Boost.SafeNumerics",
    language: "C++",
    description: "Boost library for guaranteed correct integer arithmetic",
    example: `using safe_int = boost::safe_numerics::safe<int>;
safe_int x = INT_MAX;
x + 1;  // Throws std::overflow_error`,
  },
  {
    name: "checked (Rust std)",
    language: "Rust",
    description: "Built-in checked arithmetic methods in standard library",
    example: `let a: u32 = u32::MAX;
match a.checked_add(1) {
    Some(val) => println!("Result: {}", val),
    None => println!("Overflow!"),
}`,
  },
];

// Practice resources
const practiceResources = [
  {
    name: "pwn.college",
    type: "Educational Platform",
    difficulty: "Beginner to Advanced",
    description: "Structured curriculum with integer overflow challenges",
  },
  {
    name: "OverTheWire: Narnia/Behemoth",
    type: "Wargames",
    difficulty: "Intermediate",
    description: "Classic Linux exploitation including integer bugs",
  },
  {
    name: "Exploit Education: Phoenix",
    type: "VM-based Learning",
    difficulty: "Beginner to Intermediate",
    description: "Integer overflow challenges with increasing difficulty",
  },
  {
    name: "Hack The Box",
    type: "CTF Platform",
    difficulty: "Varies",
    description: "Various machines and challenges involving integer bugs",
  },
];

// Compiler flags reference
const compilerFlags = [
  {
    compiler: "GCC",
    flags: [
      { flag: "-ftrapv", description: "Trap on signed overflow (generates traps)" },
      { flag: "-fwrapv", description: "Treat signed overflow as wrapping (defined behavior)" },
      { flag: "-fsanitize=undefined", description: "Enable UBSan for runtime detection" },
      { flag: "-Wconversion", description: "Warn on implicit conversions that may lose data" },
      { flag: "-Wsign-conversion", description: "Warn on sign conversion issues" },
    ],
  },
  {
    compiler: "Clang",
    flags: [
      { flag: "-fsanitize=integer", description: "Comprehensive integer sanitizer" },
      { flag: "-fsanitize=unsigned-integer-overflow", description: "Detect unsigned overflow" },
      { flag: "-Wshorten-64-to-32", description: "Warn on 64-to-32 bit truncation" },
      { flag: "-Wimplicit-int-conversion", description: "Warn on implicit integer conversions" },
    ],
  },
  {
    compiler: "MSVC",
    flags: [
      { flag: "/RTCc", description: "Runtime check for data truncation" },
      { flag: "/sdl", description: "Enable additional security checks" },
      { flag: "/W4", description: "Enable high warning level" },
      { flag: "/analyze", description: "Enable static code analysis" },
    ],
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#22c55e";
const ACCENT_COLOR = "#f59e0b";

// 75 quiz questions with randomized correct answer positions
const quizQuestions: QuizQuestion[] = [
  // Fundamentals (Questions 1-10)
  {
    id: 1,
    topic: "Fundamentals",
    question: "An integer overflow occurs when:",
    options: ["A file is encrypted", "A pointer is null", "A value exceeds the maximum representable range", "A function returns"],
    correctAnswer: 2,
    explanation: "Overflow happens when a value cannot fit in its type - it exceeds the maximum value that type can store.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "An integer underflow occurs when:",
    options: ["A buffer is too large", "A value goes below the minimum representable range", "A file is closed", "A log is written"],
    correctAnswer: 1,
    explanation: "Underflow happens when a value drops below the minimum - like subtracting 1 from 0 in an unsigned type.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "What is the simplest analogy for integer overflow?",
    options: ["A car odometer rolling from 999999 to 000000", "A file getting corrupted", "A network packet being lost", "A password being rejected"],
    correctAnswer: 0,
    explanation: "An odometer 'wrapping around' from max to zero perfectly illustrates how integer overflow works.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "Why are integer overflows dangerous in security?",
    options: ["They slow down programs", "They can bypass security checks and cause buffer overflows", "They always crash the program", "They are logged automatically"],
    correctAnswer: 1,
    explanation: "Overflows can make large values appear small, bypassing size checks and enabling memory corruption.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "An 8-bit unsigned integer can hold values from:",
    options: ["-128 to 127", "-255 to 255", "0 to 127", "0 to 255"],
    correctAnswer: 3,
    explanation: "8 bits can represent 2^8 = 256 values. For unsigned, that's 0 through 255.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "What happens when you add 1 to the maximum value of an unsigned 8-bit integer (255)?",
    options: ["It stays at 255", "It becomes 256", "It wraps around to 0", "The program crashes"],
    correctAnswer: 2,
    explanation: "Unsigned integers wrap around - 255 + 1 = 0 because the 9th bit is discarded.",
  },
  {
    id: 7,
    topic: "Fundamentals",
    question: "A 32-bit signed integer can hold values approximately:",
    options: ["0 to 4 billion", "±65 thousand", "±2.1 billion", "0 to 255"],
    correctAnswer: 2,
    explanation: "A 32-bit signed int ranges from about -2.1 billion to +2.1 billion (±2^31).",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "What distinguishes an overflow from a truncation?",
    options: ["Overflow is arithmetic, truncation is from type casting", "They are the same thing", "Truncation only affects strings", "Overflow only affects pointers"],
    correctAnswer: 0,
    explanation: "Overflow occurs during arithmetic operations, while truncation happens when casting to a smaller type.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "In the context of memory allocation, what can happen if count * size overflows?",
    options: ["Memory is automatically expanded", "A small buffer is allocated for large data", "Nothing - it's detected automatically", "The allocation is cancelled"],
    correctAnswer: 1,
    explanation: "If the multiplication overflows to a small value, malloc allocates a tiny buffer that will be overflowed when data is written.",
  },
  {
    id: 10,
    topic: "Fundamentals",
    question: "Which operation is MOST likely to cause an integer overflow?",
    options: ["Division", "Subtraction of positive numbers", "Multiplication of large numbers", "Comparison"],
    correctAnswer: 2,
    explanation: "Multiplication can rapidly increase values - multiplying two 16-bit numbers can easily exceed 32 bits.",
  },

  // C/C++ Behavior (Questions 11-20)
  {
    id: 11,
    topic: "C/C++",
    question: "Signed integer overflow in C/C++ is:",
    options: ["Guaranteed wraparound", "Always safe", "Undefined behavior", "A compile-time error"],
    correctAnswer: 2,
    explanation: "Signed overflow is undefined behavior in C/C++ - the compiler can do ANYTHING, including 'optimizing away' your checks.",
  },
  {
    id: 12,
    topic: "C/C++",
    question: "Unsigned integer overflow in C/C++ typically:",
    options: ["Crashes immediately", "Wraps modulo 2^n", "Is undefined", "Always saturates"],
    correctAnswer: 1,
    explanation: "Unsigned arithmetic is well-defined - it wraps around modulo 2^n (the bit width).",
  },
  {
    id: 13,
    topic: "C/C++",
    question: "Why is signed overflow being 'undefined behavior' particularly dangerous?",
    options: ["It always crashes", "The compiler may remove 'impossible' overflow checks", "It corrupts the stack", "It's logged but not prevented"],
    correctAnswer: 1,
    explanation: "Compilers assume undefined behavior never happens, so they may optimize away checks that would catch overflow!",
  },
  {
    id: 14,
    topic: "C/C++",
    question: "The -fwrapv compiler flag does what?",
    options: ["Disables all wrapping", "Makes signed overflow wrap predictably", "Enables extra warnings", "Optimizes away checks"],
    correctAnswer: 1,
    explanation: "-fwrapv tells the compiler to treat signed overflow as wrapping, making the behavior defined.",
  },
  {
    id: 15,
    topic: "C/C++",
    question: "What does the -ftrapv flag do?",
    options: ["Traps (crashes) on signed overflow", "Enables debug tracing", "Disables all integer checks", "Converts to floating point"],
    correctAnswer: 0,
    explanation: "-ftrapv inserts runtime checks that crash the program on signed integer overflow.",
  },
  {
    id: 16,
    topic: "C/C++",
    question: "In C, what is the result of: uint8_t x = 200; uint8_t y = 100; uint8_t z = x + y;",
    options: ["300", "44 (wraps around)", "Compile error", "Runtime error"],
    correctAnswer: 1,
    explanation: "200 + 100 = 300, but uint8_t max is 255. 300 mod 256 = 44.",
  },
  {
    id: 17,
    topic: "C/C++",
    question: "What is 'integer promotion' in C?",
    options: ["Converting int to long", "Small types are converted to int for arithmetic", "All integers become unsigned", "Converting to floating point"],
    correctAnswer: 1,
    explanation: "In C, char and short are promoted to int before arithmetic operations are performed.",
  },
  {
    id: 18,
    topic: "C/C++",
    question: "The __builtin_add_overflow function returns:",
    options: ["The sum, or 0 on overflow", "True if overflow occurred", "False if overflow occurred", "Always returns the wrapped value"],
    correctAnswer: 1,
    explanation: "GCC/Clang builtins return true (non-zero) if overflow occurred, and store the result in an output parameter.",
  },
  {
    id: 19,
    topic: "C/C++",
    question: "Why is calloc(count, size) sometimes safer than malloc(count * size)?",
    options: ["It's always faster", "calloc checks for multiplication overflow", "It allocates more memory", "It zeroes memory and may check overflow"],
    correctAnswer: 3,
    explanation: "Some calloc implementations check for overflow, and it always zeroes memory which can prevent info leaks.",
  },
  {
    id: 20,
    topic: "C/C++",
    question: "When comparing int x to size_t y, what happens if x is -1?",
    options: ["x is always less than y", "x becomes a very large value, may be greater than y", "The comparison fails", "It's a compile error"],
    correctAnswer: 1,
    explanation: "The signed int is converted to size_t (unsigned). -1 becomes the maximum size_t value, likely greater than y.",
  },

  // Types and Representation (Questions 21-30)
  {
    id: 21,
    topic: "Types",
    question: "size_t is:",
    options: ["Always signed", "An unsigned type for sizes", "A floating type", "A pointer type"],
    correctAnswer: 1,
    explanation: "size_t is an unsigned type guaranteed to be large enough to hold the size of any object.",
  },
  {
    id: 22,
    topic: "Types",
    question: "Casting -1 to size_t results in:",
    options: ["Zero", "An exception", "The maximum value of size_t", "Undefined behavior"],
    correctAnswer: 2,
    explanation: "-1 in two's complement is all 1 bits, which when interpreted as unsigned is the maximum value.",
  },
  {
    id: 23,
    topic: "Types",
    question: "Casting a 64-bit integer to 32-bit can:",
    options: ["Increase precision", "Prevent overflow", "Truncate the high bits", "Make it signed"],
    correctAnswer: 2,
    explanation: "Narrowing truncates - only the lower 32 bits are kept, higher bits are discarded.",
  },
  {
    id: 24,
    topic: "Types",
    question: "What is the range of a signed 16-bit integer?",
    options: ["0 to 65535", "-32768 to 32767", "-65535 to 65535", "0 to 32767"],
    correctAnswer: 1,
    explanation: "16 signed bits give -2^15 to 2^15-1 = -32768 to 32767.",
  },
  {
    id: 25,
    topic: "Types",
    question: "Two's complement representation means -1 is stored as:",
    options: ["00000001 with a sign bit", "All 1 bits (e.g., 0xFFFFFFFF for 32-bit)", "10000001", "The same as 1"],
    correctAnswer: 1,
    explanation: "In two's complement, -1 is all 1 bits. For 32-bit that's 0xFFFFFFFF.",
  },
  {
    id: 26,
    topic: "Types",
    question: "What happens when casting uint64_t value 0x100000010 to uint32_t?",
    options: ["The value stays the same", "It becomes 0x10 (16)", "Runtime error", "It becomes 0xFFFFFFFF"],
    correctAnswer: 1,
    explanation: "Only the lower 32 bits are kept: 0x00000010 = 16 decimal.",
  },
  {
    id: 27,
    topic: "Types",
    question: "The ssize_t type differs from size_t in that ssize_t is:",
    options: ["Smaller", "Signed", "Faster", "Platform independent"],
    correctAnswer: 1,
    explanation: "ssize_t is a signed type, allowing it to represent -1 for error conditions.",
  },
  {
    id: 28,
    topic: "Types",
    question: "INT_MAX + 1 in a signed int is:",
    options: ["INT_MAX (saturates)", "INT_MIN on most systems (but undefined)", "0", "A very large number"],
    correctAnswer: 1,
    explanation: "While often wrapping to INT_MIN, this is technically undefined behavior and shouldn't be relied upon.",
  },
  {
    id: 29,
    topic: "Types",
    question: "When is using int for a loop counter dangerous?",
    options: ["Always", "When the loop iterates more than INT_MAX times", "Never", "Only in debug builds"],
    correctAnswer: 1,
    explanation: "If a loop needs more iterations than INT_MAX, the counter will overflow - use size_t instead.",
  },
  {
    id: 30,
    topic: "Types",
    question: "UINT_MAX for a 32-bit unsigned int is:",
    options: ["2,147,483,647", "4,294,967,295", "65,535", "255"],
    correctAnswer: 1,
    explanation: "32-bit unsigned max is 2^32 - 1 = 4,294,967,295.",
  },

  // Arithmetic and Patterns (Questions 31-40)
  {
    id: 31,
    topic: "Arithmetic",
    question: "Multiplication overflow is risky because it can:",
    options: ["Increase bounds checks", "Improve safety", "Produce too-small allocation sizes", "Disable ASLR"],
    correctAnswer: 2,
    explanation: "Overflowed multiplication gives a small result, causing under-allocation.",
  },
  {
    id: 32,
    topic: "Arithmetic",
    question: "Which pattern safely checks for multiplication overflow?",
    options: ["if (a == b)", "if (a != 0 && b > MAX / a) error();", "if (a < b)", "if (a == 0 && b == 0)"],
    correctAnswer: 1,
    explanation: "Dividing MAX by one operand and comparing to the other detects if a*b would overflow.",
  },
  {
    id: 33,
    topic: "Arithmetic",
    question: "An off-by-one error often comes from:",
    options: ["Using == instead of !=", "Using <= instead of <", "Using + instead of -", "Using * instead of /"],
    correctAnswer: 1,
    explanation: "Boundary checks often have fencepost errors - 'less than' vs 'less than or equal'.",
  },
  {
    id: 34,
    topic: "Arithmetic",
    question: "For unsigned types, what check prevents subtraction underflow?",
    options: ["if (a > b) result = a - b;", "if (a >= b) result = a - b;", "if (a == b) result = 0;", "No check is needed"],
    correctAnswer: 1,
    explanation: "If a >= b, then a - b is guaranteed non-negative for unsigned types.",
  },
  {
    id: 35,
    topic: "Arithmetic",
    question: "The expression (size_t)(-1) evaluates to:",
    options: ["0", "-1", "SIZE_MAX", "Undefined"],
    correctAnswer: 2,
    explanation: "Casting -1 to unsigned gives the maximum value of that unsigned type.",
  },
  {
    id: 36,
    topic: "Arithmetic",
    question: "What is the result of: unsigned int x = 0; x--;",
    options: ["Runtime error", "0", "UINT_MAX", "-1"],
    correctAnswer: 2,
    explanation: "Decrementing 0 in unsigned wraps to the maximum value (UINT_MAX).",
  },
  {
    id: 37,
    topic: "Arithmetic",
    question: "Why is len - header_size dangerous when both are size_t?",
    options: ["It's always safe", "If len < header_size, result wraps to huge value", "It causes type mismatch", "size_t can't be subtracted"],
    correctAnswer: 1,
    explanation: "If len is smaller than header_size, the unsigned subtraction wraps to a massive value.",
  },
  {
    id: 38,
    topic: "Arithmetic",
    question: "What is 'wraparound' arithmetic?",
    options: ["Arithmetic that uses loops", "Overflow behavior that cycles back to min/zero", "Arithmetic with signed types only", "A compiler optimization"],
    correctAnswer: 1,
    explanation: "Wraparound means the value 'wraps around' from max to min (or vice versa) on overflow.",
  },
  {
    id: 39,
    topic: "Arithmetic",
    question: "Which is safer: a + b > MAX or a > MAX - b?",
    options: ["They're equivalent", "a + b > MAX", "a > MAX - b", "Neither is safe"],
    correctAnswer: 2,
    explanation: "a + b > MAX may overflow before the comparison. a > MAX - b checks without risking overflow.",
  },
  {
    id: 40,
    topic: "Arithmetic",
    question: "Integer division in C/C++ truncates towards:",
    options: ["Always towards zero", "Always towards negative infinity", "Implementation defined for negative", "Towards zero for C99 and later"],
    correctAnswer: 3,
    explanation: "C99 standardized truncation towards zero. Earlier versions were implementation-defined.",
  },

  // Security Implications (Questions 41-50)
  {
    id: 41,
    topic: "Security",
    question: "Integer overflow bugs often enable:",
    options: ["SQL injection", "Buffer overflows", "Phishing", "TLS downgrade"],
    correctAnswer: 1,
    explanation: "Incorrect size calculations can create undersized buffers that are then overflowed.",
  },
  {
    id: 42,
    topic: "Security",
    question: "CVE-2019-14287 (sudo) was caused by:",
    options: ["Buffer overflow", "SQL injection", "User ID -1 being interpreted as root (UID 0)", "Password bypass"],
    correctAnswer: 2,
    explanation: "UID -1 converted to unsigned became 4294967295, then to uid_t it wrapped to 0 (root).",
  },
  {
    id: 43,
    topic: "Security",
    question: "SMBGhost (CVE-2020-0796) involved overflow in:",
    options: ["User authentication", "Compression size calculation", "Password hashing", "Session tokens"],
    correctAnswer: 1,
    explanation: "An integer overflow in SMBv3 compression handling allowed remote code execution.",
  },
  {
    id: 44,
    topic: "Security",
    question: "Why are network packet lengths a common attack vector?",
    options: ["They're encrypted", "They're attacker-controlled and used in size calculations", "They're checksummed", "They're signed values"],
    correctAnswer: 1,
    explanation: "Attackers control packet content, so length fields can be crafted to cause overflows in allocation.",
  },
  {
    id: 45,
    topic: "Security",
    question: "Reference counting vulnerabilities relate to overflow when:",
    options: ["References are uncounted", "A counter wraps from max to zero, enabling use-after-free", "References are encrypted", "Counts are stored as strings"],
    correctAnswer: 1,
    explanation: "If a 32-bit counter overflows after ~4 billion increments, it wraps to 0, causing premature free.",
  },
  {
    id: 46,
    topic: "Security",
    question: "What makes integer overflow particularly dangerous in memory allocators?",
    options: ["They run slowly", "Small allocation + large copy = heap corruption", "They use floating point", "They're always checked"],
    correctAnswer: 1,
    explanation: "A tiny allocation from overflow, followed by a write of the original large size, corrupts the heap.",
  },
  {
    id: 47,
    topic: "Security",
    question: "Array indexing with negative values can cause:",
    options: ["Faster access", "Arbitrary read/write before the array", "Compile error", "Nothing harmful"],
    correctAnswer: 1,
    explanation: "A negative index becomes a large positive when cast to size_t, reading/writing unexpected memory.",
  },
  {
    id: 48,
    topic: "Security",
    question: "Why are file format parsers often vulnerable to integer overflow?",
    options: ["Files are read-only", "They use untrusted values from file headers in size calculations", "They never allocate memory", "They're written in Python"],
    correctAnswer: 1,
    explanation: "Image dimensions, chunk sizes, and offsets in files are attacker-controlled and used in arithmetic.",
  },
  {
    id: 49,
    topic: "Security",
    question: "A 'width truncation' attack exploits:",
    options: ["String length limits", "Casting from larger to smaller integer types", "Network bandwidth", "Screen resolution"],
    correctAnswer: 1,
    explanation: "Passing a 64-bit value that truncates to a small 32-bit value can bypass size checks.",
  },
  {
    id: 50,
    topic: "Security",
    question: "What is a 'signedness bug'?",
    options: ["A digital signature failure", "Mixing signed/unsigned causing unexpected comparisons", "A typo in variable names", "A function signature mismatch"],
    correctAnswer: 1,
    explanation: "When signed and unsigned types are mixed in comparisons, negative values become very large.",
  },

  // Prevention and Best Practices (Questions 51-60)
  {
    id: 51,
    topic: "Prevention",
    question: "Using 64-bit types helps by:",
    options: ["Removing all bugs", "Making code slower only", "Increasing the safe numeric range", "Disabling fuzzing"],
    correctAnswer: 2,
    explanation: "Wider types have higher maximums, making overflow less likely for realistic values.",
  },
  {
    id: 52,
    topic: "Prevention",
    question: "Checked arithmetic libraries help by:",
    options: ["Disabling the heap", "Detecting overflow at runtime", "Removing loops", "Encrypting values"],
    correctAnswer: 1,
    explanation: "Checked operations detect when overflow would occur and handle it safely.",
  },
  {
    id: 53,
    topic: "Prevention",
    question: "Saturating arithmetic means:",
    options: ["Wrapping around", "Clamping at min or max on overflow", "Always returning zero", "Throwing away results"],
    correctAnswer: 1,
    explanation: "Saturation stops at the boundary value instead of wrapping (e.g., 255+1=255 for uint8_t).",
  },
  {
    id: 54,
    topic: "Prevention",
    question: "The -Wconversion compiler flag:",
    options: ["Enables wrapping", "Warns about implicit conversions that may lose data", "Disables all conversions", "Converts to strings"],
    correctAnswer: 1,
    explanation: "-Wconversion warns when implicit type conversions might change a value's meaning.",
  },
  {
    id: 55,
    topic: "Prevention",
    question: "SafeInt (Microsoft) library works by:",
    options: ["Disabling integers", "Wrapping all integers in templates that check operations", "Using floating point", "Encrypting values"],
    correctAnswer: 1,
    explanation: "SafeInt uses C++ templates to wrap integers and throw exceptions on overflow.",
  },
  {
    id: 56,
    topic: "Prevention",
    question: "In Rust, checked_add() returns:",
    options: ["The sum or panics", "None on overflow, Some(result) otherwise", "Always the wrapped value", "A string"],
    correctAnswer: 1,
    explanation: "Rust's checked_* methods return Option types - None if overflow, Some(value) if safe.",
  },
  {
    id: 57,
    topic: "Prevention",
    question: "What should you do with user-controlled length values?",
    options: ["Use them directly", "Validate them against protocol limits before arithmetic", "Cast to signed first", "Ignore them"],
    correctAnswer: 1,
    explanation: "Always validate untrusted values against reasonable limits before using in calculations.",
  },
  {
    id: 58,
    topic: "Prevention",
    question: "The safe_iop C library provides:",
    options: ["Encryption functions", "Macros for safe integer operations that detect overflow", "String handling", "Network protocols"],
    correctAnswer: 1,
    explanation: "safe_iop provides C macros like safe_add() that check for overflow before operations.",
  },
  {
    id: 59,
    topic: "Prevention",
    question: "Which is the best approach for size calculations?",
    options: ["Trust input sizes", "Use the smallest type possible", "Check for overflow BEFORE the operation", "Use floating point"],
    correctAnswer: 2,
    explanation: "The key is detecting overflow BEFORE it happens, not after when the damage is done.",
  },
  {
    id: 60,
    topic: "Prevention",
    question: "Input validation should occur:",
    options: ["Never", "At system boundaries (user input, network, files)", "Only for strings", "Only in debug builds"],
    correctAnswer: 1,
    explanation: "Validate all data at trust boundaries before it enters your system.",
  },

  // Testing and Detection (Questions 61-70)
  {
    id: 61,
    topic: "Testing",
    question: "Fuzzing helps find integer bugs by:",
    options: ["Avoiding edge cases", "Generating boundary values automatically", "Disabling checks", "Hiding crashes"],
    correctAnswer: 1,
    explanation: "Fuzzers naturally gravitate toward edge cases like MAX, MIN, 0, and -1.",
  },
  {
    id: 62,
    topic: "Testing",
    question: "UBSan is useful because it:",
    options: ["Prevents all crashes", "Detects undefined integer behavior at runtime", "Hides errors", "Disables ASLR"],
    correctAnswer: 1,
    explanation: "UBSan (Undefined Behavior Sanitizer) catches signed overflow and other UB at runtime.",
  },
  {
    id: 63,
    topic: "Testing",
    question: "-fsanitize=integer in Clang catches:",
    options: ["Only signed overflow", "Both signed and unsigned integer issues", "Only memory errors", "Compilation errors"],
    correctAnswer: 1,
    explanation: "Clang's integer sanitizer catches signed and unsigned overflow, truncation, and more.",
  },
  {
    id: 64,
    topic: "Testing",
    question: "CodeQL can detect integer overflow through:",
    options: ["Runtime monitoring", "Static analysis with queries that track data flow", "User reports", "Code review only"],
    correctAnswer: 1,
    explanation: "CodeQL uses static analysis queries to find taint from sources to sinks like allocations.",
  },
  {
    id: 65,
    topic: "Testing",
    question: "Which boundary values are most important to test?",
    options: ["Random large numbers", "0, 1, MAX-1, MAX, and MAX+1", "Only positive numbers", "Prime numbers"],
    correctAnswer: 1,
    explanation: "Boundary values around 0 and MAX are where overflow/underflow occurs.",
  },
  {
    id: 66,
    topic: "Testing",
    question: "AFL++ (fuzzer) is effective because it:",
    options: ["Uses random testing only", "Tracks code coverage to explore new paths", "Only tests networking", "Requires source code"],
    correctAnswer: 1,
    explanation: "Coverage-guided fuzzers like AFL++ explore code paths systematically to find bugs.",
  },
  {
    id: 67,
    topic: "Testing",
    question: "Static analysis tools may miss integer overflow when:",
    options: ["The code is well-formatted", "The overflow requires complex data flow analysis", "The code has comments", "Using standard types"],
    correctAnswer: 1,
    explanation: "Complex data flows spanning many functions can exceed analysis capabilities.",
  },
  {
    id: 68,
    topic: "Testing",
    question: "What's the downside of runtime overflow detection?",
    options: ["It's too accurate", "Performance overhead and only finds executed paths", "It finds too many bugs", "It's free"],
    correctAnswer: 1,
    explanation: "Runtime checks add overhead and only catch bugs in code paths that are actually executed.",
  },
  {
    id: 69,
    topic: "Testing",
    question: "Clang Static Analyzer detects overflow by:",
    options: ["Running the code", "Analyzing code paths symbolically", "Checking documentation", "User configuration only"],
    correctAnswer: 1,
    explanation: "Static analyzers explore code paths symbolically without running the program.",
  },
  {
    id: 70,
    topic: "Testing",
    question: "A good test for malloc(count * size) includes:",
    options: ["count=0 only", "count=SIZE_MAX/size to trigger overflow", "count=1 only", "No testing needed"],
    correctAnswer: 1,
    explanation: "Testing with values that cause count * size to overflow reveals the vulnerability.",
  },

  // Language-Specific (Questions 71-75)
  {
    id: 71,
    topic: "Languages",
    question: "Python 3 handles integer overflow by:",
    options: ["Crashing", "Wrapping around", "Automatically using arbitrary precision", "Throwing exceptions"],
    correctAnswer: 2,
    explanation: "Python 3 integers automatically grow to arbitrary precision - no overflow possible.",
  },
  {
    id: 72,
    topic: "Languages",
    question: "Java's integer overflow behavior is:",
    options: ["Undefined", "Wrapping with exceptions available via Math.addExact()", "Always caught", "Platform dependent"],
    correctAnswer: 1,
    explanation: "Java silently wraps, but Math.*Exact() methods throw ArithmeticException on overflow.",
  },
  {
    id: 73,
    topic: "Languages",
    question: "Rust's default integer behavior differs in debug vs release by:",
    options: ["No difference", "Debug panics on overflow, release wraps", "Release panics, debug wraps", "Both always panic"],
    correctAnswer: 1,
    explanation: "Rust catches overflow in debug builds but wraps in release for performance.",
  },
  {
    id: 74,
    topic: "Languages",
    question: "Go handles integer overflow by:",
    options: ["Always panicking", "Wrapping with no runtime check", "Using arbitrary precision", "Compilation error"],
    correctAnswer: 1,
    explanation: "Go integers wrap on overflow with no automatic detection - manual checks required.",
  },
  {
    id: 75,
    topic: "Languages",
    question: "JavaScript Number type is vulnerable because:",
    options: ["It doesn't support integers", "Precision is lost above 2^53 (MAX_SAFE_INTEGER)", "It always overflows", "It uses unsigned only"],
    correctAnswer: 1,
    explanation: "JavaScript uses 64-bit floats which can't exactly represent integers above 2^53.",
  },
];

export default function IntegerOverflowPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("lg"));

  // Navigation State
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("");

  // Section Navigation Items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "what-is-it", label: "What Is It?", icon: <MenuBookIcon /> },
    { id: "vuln-types", label: "Vulnerability Types", icon: <WarningIcon /> },
    { id: "how-it-works", label: "How It Works", icon: <MemoryIcon /> },
    { id: "code-examples", label: "Code Examples", icon: <CodeIcon /> },
    { id: "cve-studies", label: "CVE Case Studies", icon: <HistoryEduIcon /> },
    { id: "detection", label: "Detection Tools", icon: <BuildIcon /> },
    { id: "language-behavior", label: "Language Behavior", icon: <TranslateIcon /> },
    { id: "prevention", label: "Prevention", icon: <ShieldIcon /> },
    { id: "practice", label: "Practice", icon: <ScienceIcon /> },
    { id: "quiz-section", label: "Quiz", icon: <QuizIcon /> },
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

  const pageContext = `Integer Overflows and Underflows Comprehensive Guide - Covers integer overflow, underflow, signed/unsigned mismatches, width truncation, root causes, conversion pitfalls, and boundary testing. Includes real-world CVE examples, detailed code examples with vulnerable and fixed versions, exploitation techniques, detection tools, language-specific behaviors, safe integer libraries, and compiler flags reference.`;

  // Sidebar Navigation Component
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
        borderRadius: 3,
        border: `1px solid ${alpha(ACCENT_COLOR, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha(ACCENT_COLOR, 0.3), borderRadius: 3 },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: ACCENT_COLOR, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(ACCENT_COLOR, 0.1),
              "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR, borderRadius: 3 },
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
                bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.08) },
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
                      color: activeSection === item.id ? ACCENT_COLOR : "text.secondary",
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
    <LearnPageLayout pageTitle="Integer Overflows & Underflows" pageContext={pageContext}>
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
            bgcolor: ACCENT_COLOR,
            "&:hover": { bgcolor: "#d97706" },
            boxShadow: `0 4px 20px ${alpha(ACCENT_COLOR, 0.4)}`,
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
            bgcolor: alpha(ACCENT_COLOR, 0.15),
            color: ACCENT_COLOR,
            "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.25) },
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
              <ListAltIcon sx={{ color: ACCENT_COLOR }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(ACCENT_COLOR, 0.1),
                "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR, borderRadius: 3 },
              }}
            />
          </Box>

          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                  "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.1) },
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
                        color: activeSection === item.id ? ACCENT_COLOR : "text.primary",
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
                    sx={{ height: 20, fontSize: "0.65rem", bgcolor: alpha(ACCENT_COLOR, 0.2), color: ACCENT_COLOR }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz-section")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* ==================== SECTION: Introduction ==================== */}
          <Box id="intro" sx={{ mb: 4 }}>
            <Chip
              component={Link}
              to="/learn"
              icon={<ArrowBackIcon />}
              label="Back to Learning Hub"
              clickable
              variant="outlined"
              sx={{ borderRadius: 2, mb: 2 }}
            />
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
              <Box
                sx={{
                  width: 64,
                  height: 64,
                  borderRadius: 2,
                  bgcolor: alpha("#f59e0b", 0.1),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <CalculateIcon sx={{ fontSize: 36, color: "#f59e0b" }} />
              </Box>
              <Box>
                <Typography variant="h4" sx={{ fontWeight: 800 }}>
                  Integer Overflows & Underflows
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Comprehensive guide to arithmetic boundary vulnerabilities, from the absolute basics to real-world impact.
                </Typography>
              </Box>
            </Box>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Memory Corruption" color="warning" size="small" />
              <Chip label="C/C++" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
              <Chip label="Binary Exploitation" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
              <Chip label="11 Sections" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
            </Box>

            <Alert severity="warning" sx={{ mb: 3 }}>
              <AlertTitle>Defensive Learning Only</AlertTitle>
              This guide focuses on understanding, detecting, and preventing integer vulnerabilities. Practice only on systems you own or have explicit authorization to test.
            </Alert>
            <Typography variant="body1" sx={{ color: "text.secondary", mb: 2 }}>
              If you are new to programming, do not worry. This page starts with how numbers are stored in memory,
              builds up to how overflow and underflow happen, and then shows why these mistakes can turn into security bugs.
              Take it slowly and reread the examples; most confusion comes from how computers store numbers, not from the math itself.
            </Typography>
          </Box>

          {/* ==================== SECTION: What Is It? ==================== */}
          <Paper id="what-is-it" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <MenuBookIcon sx={{ color: "#f59e0b" }} />
              What Are Integer Overflows and Underflows?
            </Typography>

            <Alert severity="success" sx={{ mb: 3 }}>
              <AlertTitle>Beginner Start Here</AlertTitle>
              This section explains the fundamentals in simple terms. No prior programming knowledge required - we'll build up from the basics.
            </Alert>

            <Typography variant="h6" sx={{ color: "#fff", mb: 1 }}>Understanding Bits and Numbers</Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              Before understanding overflow, you need to know how computers store numbers. Computers use <strong>binary (base-2)</strong> - just 0s and 1s called "bits". A group of 8 bits is called a "byte". The more bits you have, the bigger numbers you can represent.
              A simple way to think about it is counting with a fixed number of slots: with 1 bit you can count 0-1, with 2 bits you can count 0-3, with 3 bits you can count 0-7, and so on.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              The key idea is that an integer type has a <strong>fixed width</strong>. If you choose 8 bits, you have exactly 8 "boxes" to store the value.
              The computer will not automatically make the box bigger when the value grows. When the result no longer fits, the extra bits are dropped.
              That is the root of overflow and underflow.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 1.5, bgcolor: "#151c2c", textAlign: "center" }}>
                  <Typography variant="h6" sx={{ color: "#3b82f6" }}>8 bits</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>0 to 255</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>Like age or small counts</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 1.5, bgcolor: "#151c2c", textAlign: "center" }}>
                  <Typography variant="h6" sx={{ color: "#8b5cf6" }}>16 bits</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>0 to 65,535</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>Like network ports</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 1.5, bgcolor: "#151c2c", textAlign: "center" }}>
                  <Typography variant="h6" sx={{ color: "#f59e0b" }}>32 bits</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>0 to ~4 billion</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>Like file sizes</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 1.5, bgcolor: "#151c2c", textAlign: "center" }}>
                  <Typography variant="h6" sx={{ color: "#10b981" }}>64 bits</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>0 to ~18 quintillion</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>Like memory addresses</Typography>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ color: "#fff", mb: 1 }}>What is Overflow?</Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              <strong>Integer overflow</strong> occurs when an arithmetic operation tries to produce a number larger than the maximum value a type can hold.
              Because the type has a fixed number of bits, the extra high bits are thrown away. This makes the result "wrap" back to a smaller number.
              Think of it like an odometer in a car - when it reaches 999,999 and adds 1, it wraps back around to 000,000.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              For unsigned integers, this wrapping is well-defined and predictable: values are computed modulo 2^N (where N is the number of bits).
              For signed integers in C and C++, the language standard says overflow is <strong>undefined behavior</strong>, which means the compiler can assume it never happens
              and may optimize the code in surprising ways.
            </Typography>

            <Paper sx={{ p: 2, bgcolor: "#151c2c", mb: 3, border: "1px solid #3b82f6" }}>
              <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>Concrete Example: 8-bit Overflow</Typography>
              <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                An 8-bit number can only hold values 0-255. What happens when we add 1 to 255?
              </Typography>
              <Box sx={{ fontFamily: "monospace", bgcolor: "grey.900", p: 1.5, borderRadius: 1, mb: 1 }}>
                <Typography variant="body2" sx={{ color: "grey.300" }}>
                  255 in binary: <span style={{ color: "#f59e0b" }}>11111111</span> (all 8 bits are 1)<br />
                  Add 1:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style={{ color: "#f59e0b" }}>00000001</span><br />
                  Result:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style={{ color: "#ef4444" }}>1</span><span style={{ color: "#10b981" }}>00000000</span> = 256 (but that's 9 bits!)<br />
                  Stored:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style={{ color: "#10b981" }}>00000000</span> = <span style={{ color: "#ef4444" }}>0</span> (the 9th bit is lost!)
                </Typography>
              </Box>
              <Typography variant="body2" sx={{ color: "grey.400" }}>
                The extra bit gets discarded because there's no room for it. 255 + 1 = 0. The number "wrapped around".
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ color: "#fff", mb: 1 }}>What is Underflow?</Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              <strong>Integer underflow</strong> is the opposite problem: the result goes below the minimum value the type can store.
              For unsigned integers, subtracting 1 from 0 does not produce -1 (which cannot be represented). Instead, it wraps to the maximum value.
              Underflow can be just as dangerous as overflow, especially when lengths or array indexes become huge by accident.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              Beginners often expect the computer to "throw an error" when this happens, but most low-level languages do not.
              The CPU just drops the extra bits and moves on. That silent behavior is why underflow bugs are common in C and C++ code.
            </Typography>

            <Paper sx={{ p: 2, bgcolor: "#151c2c", mb: 3, border: "1px solid #ef4444" }}>
              <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Concrete Example: 8-bit Underflow</Typography>
              <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                What happens when we subtract 1 from 0 in an unsigned 8-bit number?
              </Typography>
              <Box sx={{ fontFamily: "monospace", bgcolor: "grey.900", p: 1.5, borderRadius: 1, mb: 1 }}>
                <Typography variant="body2" sx={{ color: "grey.300" }}>
                  0 in binary:&nbsp;&nbsp;&nbsp;<span style={{ color: "#f59e0b" }}>00000000</span><br />
                  Subtract 1:&nbsp;&nbsp;&nbsp;&nbsp;We need to "borrow" from a non-existent bit<br />
                  Result:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style={{ color: "#ef4444" }}>11111111</span> = <span style={{ color: "#ef4444" }}>255</span>
                </Typography>
              </Box>
              <Typography variant="body2" sx={{ color: "grey.400" }}>
                Instead of getting -1 (which unsigned numbers can't represent), we get 255 - the maximum value!
              </Typography>
            </Paper>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>The Odometer Analogy</AlertTitle>
              Imagine a counter that can only display numbers 0-99. If you're at 99 and add 1, it wraps to 00 (overflow). If you're at 00 and subtract 1, it wraps to 99 (underflow). Computers have the same limitation, just with larger numbers based on their bit width (8, 16, 32, or 64 bits).
            </Alert>

            <Typography variant="h6" sx={{ color: "#fff", mb: 1 }}>Signed vs. Unsigned Numbers</Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              There are two types of integers in programming. Unsigned types store only non-negative values, while signed types store both positive and negative values.
              Signed numbers use one bit to represent the sign and are typically stored using a system called <strong>two's complement</strong>, which is why the negative range is slightly larger.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ color: "#10b981", fontWeight: 600, mb: 1 }}>Unsigned Integers</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                    Can only hold <strong>positive values and zero</strong>. All bits are used for the number itself.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>uint8_t: 0 to 255</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0 }}>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>uint32_t: 0 to 4,294,967,295</Typography>} />
                    </ListItem>
                  </List>
                  <Alert severity="success" sx={{ mt: 1 }}>
                    <Typography variant="caption">Overflow behavior is well-defined: wraps around</Typography>
                  </Alert>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ color: "#8b5cf6", fontWeight: 600, mb: 1 }}>Signed Integers</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                    Can hold <strong>negative, zero, and positive values</strong>. One bit is used for the sign.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>int8_t: -128 to 127</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0 }}>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>int32_t: ±2.1 billion</Typography>} />
                    </ListItem>
                  </List>
                  <Alert severity="error" sx={{ mt: 1 }}>
                    <Typography variant="caption">Overflow is UNDEFINED BEHAVIOR in C/C++!</Typography>
                  </Alert>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Why is This a Security Problem?</Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              Integer overflows and underflows can lead to serious vulnerabilities because they often affect critical operations like memory management and security checks.
              When a program trusts a calculated size or index, a tiny mistake in arithmetic can turn into a big memory corruption issue.
              Here's how each area can be exploited:
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderLeft: "4px solid #ef4444" }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 600 }}>Memory Allocation</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>Undersized buffers lead to heap/stack overflows</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>
                    Example: Program calculates buffer_size = count × item_size. If count is huge, multiplication overflows to a small number,
                    but the program still tries to write count items - overflowing the tiny buffer.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderLeft: "4px solid #f59e0b" }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 600 }}>Bounds Checking</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>Security checks can be bypassed entirely</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>
                    Example: Code checks "if (user_input &lt; buffer_size)". If user_input is -1 and gets converted to unsigned,
                    it becomes a huge positive number, still passing some checks unexpectedly.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderLeft: "4px solid #8b5cf6" }}>
                  <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 600 }}>Array Indexing</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>Out-of-bounds read/write vulnerabilities</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>
                    Example: array[index] where index is calculated from user input. If the calculation underflows,
                    a "negative" index (which becomes huge) reads/writes memory outside the array.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderLeft: "4px solid #3b82f6" }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 600 }}>Loop Control</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>Infinite loops or incorrect iteration counts</Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>
                    Example: "for(i = 0; i &lt; length; i++)" where length overflowed to a small value.
                    The loop runs fewer times than expected, skipping security processing.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Real-World Impact: A Simple Scenario</Typography>
            <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.3)}`, mb: 2 }}>
              <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                Imagine an image processing program that reads a PNG file. The file header says the image is <strong>65,536 × 65,536 pixels</strong>.
                The program calculates memory needed:
              </Typography>
              <CodeBlock language="c">{`// Attacker-controlled values from image file
uint32_t width = 65536;   // 2^16
uint32_t height = 65536;  // 2^16
uint32_t bytes_per_pixel = 4;

// Calculate buffer size (32-bit arithmetic)
uint32_t buffer_size = width * height * bytes_per_pixel;
// 65536 × 65536 × 4 = 17,179,869,184 (about 17 billion)
// But 32-bit can only hold up to 4 billion!
// Result: 17,179,869,184 mod 2^32 = 0 ← OVERFLOW!

char *buffer = malloc(buffer_size);  // Allocates 0 bytes (or fails)

// Later, the program writes 17 billion bytes to this buffer...
// HEAP OVERFLOW → Remote Code Execution!`}</CodeBlock>
              <Typography variant="body2" sx={{ color: "grey.400" }}>
                This is exactly how many image parsing CVEs work. The attacker crafts malicious dimensions
                that cause overflow, leading to buffer overflow when pixel data is processed.
              </Typography>
            </Paper>
          </Paper>

          {/* ==================== SECTION: Vulnerability Types ==================== */}
          <Paper id="vuln-types" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon sx={{ color: "#ef4444" }} />
              Types of Integer Vulnerabilities
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              Integer vulnerabilities come in several forms, each with different causes and exploitation techniques.
              Understanding these distinctions helps you identify and fix bugs more effectively.
            </Typography>

            <Alert severity="warning" sx={{ mb: 3 }}>
              <AlertTitle>Why These Categories Matter</AlertTitle>
              Different vulnerability types require different prevention strategies. An overflow check won't prevent
              a truncation bug. Knowing the category guides you to the correct fix.
            </Alert>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {vulnTypes.map((v) => (
                <Grid item xs={12} sm={6} key={v.title}>
                  <Paper
                    sx={{
                      p: 2.5,
                      height: "100%",
                      borderRadius: 2,
                      bgcolor: "#151c2c",
                      border: `1px solid ${alpha(v.color, 0.3)}`,
                      "&:hover": { borderColor: v.color },
                    }}
                  >
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: v.color, mb: 1 }}>
                      {v.title}
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                      {v.description}
                    </Typography>
                    <Chip
                      label={v.example}
                      size="small"
                      sx={{ fontFamily: "monospace", bgcolor: alpha(v.color, 0.1), color: v.color }}
                    />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Data Type Limits Reference</Typography>
            <TableContainer component={Paper} sx={{ bgcolor: "#151c2c", mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Type</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Bits</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Signed Range</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Unsigned Range</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dataTypeLimits.map((dt) => (
                    <TableRow key={dt.type}>
                      <TableCell sx={{ fontFamily: "monospace", fontWeight: 600, color: "#3b82f6" }}>{dt.type}</TableCell>
                      <TableCell><Chip label={`${dt.bits} bits`} size="small" /></TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "grey.300" }}>{dt.signed}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "grey.300" }}>{dt.unsigned}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 2 }}>Common Root Causes</Typography>
                  <List dense>
                    {rootCauses.map((item) => (
                      <ListItem key={item} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                        </ListItemIcon>
                        <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 2 }}>Untrusted Integer Sources</Typography>
                  <List dense>
                    {untrustedSources.map((item) => (
                      <ListItem key={item} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                        </ListItemIcon>
                        <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Paper>

          {/* ==================== SECTION: How It Works ==================== */}
          <Paper id="how-it-works" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
              <MemoryIcon sx={{ color: "#3b82f6" }} />
              How Integer Overflow Works
            </Typography>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Understanding the Mechanics</AlertTitle>
              This section shows exactly what happens in memory when overflow and underflow occur.
              Understanding the binary representation helps you predict and prevent these bugs.
            </Alert>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 3 }}>
              <strong>Key concept:</strong> Computers perform arithmetic in binary (base 2). Each integer type has a fixed number of bits,
              and when the result of an operation exceeds that capacity, the extra bits are simply <em>discarded</em>.
              This is called "modular arithmetic" - the result wraps around like a clock going from 12 to 1.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 3 }}>
              Another way to say this is that the CPU only keeps the lowest N bits of the result, where N is the width of the type.
              For an 8-bit number, only the last 8 bits survive. For a 32-bit number, only the last 32 bits survive.
              This "keep only the low bits" rule is simple and fast for hardware, but it means programmers must add checks when values
              could be too large or too small.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Unsigned Overflow (Wrapping)</Typography>
                  <CodeBlock language="c">{`// 8-bit unsigned: max value = 255
uint8_t a = 255;
uint8_t b = a + 1;  // b = 0 (wrapped)

// Binary representation:
// 255 = 11111111
// +1  = 00000001
// Sum = 100000000 (9 bits, high bit lost)
//     = 00000000 = 0`}</CodeBlock>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>Unsigned Underflow (Wrapping)</Typography>
                  <CodeBlock language="c">{`// 8-bit unsigned: min value = 0
uint8_t a = 0;
uint8_t b = a - 1;  // b = 255 (wrapped)

// Binary representation:
// 0   = 00000000
// -1  = borrow from non-existent bit
// Result wraps to 11111111 = 255`}</CodeBlock>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>Signed Overflow (Undefined Behavior!)</Typography>
                  <CodeBlock language="c">{`// 8-bit signed: max = 127, min = -128
int8_t a = 127;
int8_t b = a + 1;  // UNDEFINED BEHAVIOR!

// Common result: b = -128
// But compiler may optimize assuming this never happens!
// 01111111 + 00000001 = 10000000 = -128`}</CodeBlock>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>Two's Complement Representation</Typography>
                  <CodeBlock language="c">{`// 8-bit signed integers use two's complement:
// Positive: 0 to 127  (0x00 to 0x7F)
// Negative: -128 to -1 (0x80 to 0xFF)

// -1 in binary (8-bit): 11111111 = 0xFF
// When cast to unsigned: 255

// This is why (unsigned)(-1) = MAX_VALUE`}</CodeBlock>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Conversion and Promotion Pitfalls</Typography>
            <TableContainer component={Paper} sx={{ bgcolor: "#151c2c", mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Rule</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Example</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Risk</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {conversionPitfalls.map((row) => (
                    <TableRow key={row.rule}>
                      <TableCell sx={{ fontWeight: 600, color: "#fff" }}>{row.rule}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "#3b82f6" }}>{row.example}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{row.risk}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Paper
              sx={{
                p: 3,
                borderRadius: 2,
                background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)}, ${alpha("#f59e0b", 0.05)})`,
                border: `1px solid ${alpha("#ef4444", 0.2)}`,
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>Common Exploitation Scenarios</Typography>
              <Grid container spacing={2}>
                {exploitScenarios.map((scenario, i) => (
                  <Grid item xs={12} sm={6} key={i}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                      <Typography variant="body2" sx={{ color: "grey.300" }}>{scenario}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Paper>

          {/* ==================== SECTION: Code Examples ==================== */}
          <Paper id="code-examples" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon sx={{ color: "#8b5cf6" }} />
              Vulnerable vs. Fixed Code Examples
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              The best way to learn is by seeing real code patterns. Each example below shows:
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#ef4444", 0.1), borderLeft: "3px solid #ef4444" }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444" }}>Vulnerable Code</Typography>
                  <Typography variant="caption" sx={{ color: "grey.400" }}>Code that can be exploited</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#10b981", 0.1), borderLeft: "3px solid #10b981" }}>
                  <Typography variant="subtitle2" sx={{ color: "#10b981" }}>Fixed Code</Typography>
                  <Typography variant="caption" sx={{ color: "grey.400" }}>Safe version of the same code</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#3b82f6", 0.1), borderLeft: "3px solid #3b82f6" }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6" }}>Explanation</Typography>
                  <Typography variant="caption" sx={{ color: "grey.400" }}>Why the bug exists and how the fix works</Typography>
                </Paper>
              </Grid>
            </Grid>

            <Alert severity="warning" sx={{ mb: 3 }}>
              <AlertTitle>Pattern Recognition is Key</AlertTitle>
              These patterns appear again and again in real-world bugs. Once you recognize them,
              you'll spot potential overflows during code review before they become vulnerabilities.
            </Alert>

            {vulnerableCodeExamples.map((example, idx) => (
              <Accordion key={example.name} defaultExpanded={idx === 0} sx={{ bgcolor: "#151c2c", mb: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Chip label={idx + 1} size="small" color="primary" />
                    <Typography fontWeight="bold" sx={{ color: "#fff" }}>{example.name}</Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    {example.explanation}
                  </Typography>

                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                        <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                          <ErrorIcon fontSize="small" /> Vulnerable Code
                        </Typography>
                        <CodeBlock language={example.language}>{example.vulnerable}</CodeBlock>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                        <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                          <CheckCircleIcon fontSize="small" /> Fixed Code
                        </Typography>
                        <CodeBlock language={example.language}>{example.fixed}</CodeBlock>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            ))}

            <Divider sx={{ my: 4 }} />

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Quick Reference: Overflow Check Patterns</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <CodeBlock title="Addition Overflow Check" language="c">{`// Check if a + b would overflow
if (a > SIZE_MAX - b) {
    // Would overflow
    return ERROR;
}
size_t result = a + b;`}</CodeBlock>
              </Grid>
              <Grid item xs={12} md={6}>
                <CodeBlock title="Multiplication Overflow Check" language="c">{`// Check if a * b would overflow
if (b != 0 && a > SIZE_MAX / b) {
    // Would overflow
    return ERROR;
}
size_t result = a * b;`}</CodeBlock>
              </Grid>
              <Grid item xs={12} md={6}>
                <CodeBlock title="Subtraction Underflow Check" language="c">{`// Check if a - b would underflow
if (a < b) {
    // Would underflow
    return ERROR;
}
size_t result = a - b;`}</CodeBlock>
              </Grid>
              <Grid item xs={12} md={6}>
                <CodeBlock title="Using GCC Builtins" language="c">{`// GCC/Clang built-in overflow checks
size_t result;
if (__builtin_add_overflow(a, b, &result)) {
    // Overflow occurred
    return ERROR;
}
// result is safe to use`}</CodeBlock>
              </Grid>
            </Grid>
          </Paper>

          {/* ==================== SECTION: CVE Case Studies ==================== */}
          <Paper id="cve-studies" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <HistoryEduIcon sx={{ color: "#ef4444" }} />
              Real-World CVE Case Studies
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              These aren't just theoretical bugs - integer overflows have caused real security breaches affecting millions of users.
              CVE (Common Vulnerabilities and Exposures) entries document publicly known security flaws. The examples below
              affected browsers, operating systems, and common tools you use every day.
            </Typography>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Learning from History</AlertTitle>
              Each CVE shows a pattern that still appears in new code today. Study these examples to recognize
              the same patterns when you're reviewing or writing code. The CVSS score indicates severity (0-10 scale).
            </Alert>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>How to Read a CVE Entry</Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={4}>
                  <Typography variant="caption" sx={{ color: "grey.400" }}><strong>CVE ID:</strong> Unique identifier (e.g., CVE-2021-21224)</Typography>
                </Grid>
                <Grid item xs={12} sm={4}>
                  <Typography variant="caption" sx={{ color: "grey.400" }}><strong>CVSS Score:</strong> Severity from 0-10 (10 = critical)</Typography>
                </Grid>
                <Grid item xs={12} sm={4}>
                  <Typography variant="caption" sx={{ color: "grey.400" }}><strong>Impact:</strong> What an attacker can achieve</Typography>
                </Grid>
              </Grid>
            </Paper>

            <Grid container spacing={2}>
              {realWorldCVEs.map((cve) => (
                <Grid item xs={12} md={6} key={cve.cve}>
                  <Card variant="outlined" sx={{ height: "100%", bgcolor: "#151c2c" }}>
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6" }}>
                          {cve.cve}
                        </Typography>
                        <Box sx={{ display: "flex", gap: 0.5 }}>
                          <Chip label={cve.year} size="small" variant="outlined" />
                          <Chip
                            label={`CVSS ${cve.cvss}`}
                            size="small"
                            color={parseFloat(cve.cvss) >= 9 ? "error" : parseFloat(cve.cvss) >= 7 ? "warning" : "info"}
                          />
                        </Box>
                      </Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: "#fff" }}>{cve.name}</Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>{cve.description}</Typography>
                      <Alert severity="error" sx={{ mb: 1 }}>
                        <Typography variant="caption"><strong>Impact:</strong> {cve.impact}</Typography>
                      </Alert>
                      <Typography variant="body2" sx={{ fontSize: "0.8rem", color: "grey.400" }}>{cve.details}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* ==================== SECTION: Detection Tools ==================== */}
          <Paper id="detection" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <BuildIcon sx={{ color: "#10b981" }} />
              Detection Tools & Techniques
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              Even experienced developers miss integer overflow bugs. Fortunately, there are tools that can help
              find these bugs automatically. The key is using <strong>multiple complementary approaches</strong> -
              no single tool catches everything.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", textAlign: "center", height: "100%" }}>
                  <Typography variant="h3" sx={{ color: "#3b82f6" }}>1</Typography>
                  <Typography variant="subtitle2" sx={{ color: "#fff" }}>Compile Time</Typography>
                  <Typography variant="caption" sx={{ color: "grey.400" }}>Warnings catch obvious issues before running code</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", textAlign: "center", height: "100%" }}>
                  <Typography variant="h3" sx={{ color: "#8b5cf6" }}>2</Typography>
                  <Typography variant="subtitle2" sx={{ color: "#fff" }}>Static Analysis</Typography>
                  <Typography variant="caption" sx={{ color: "grey.400" }}>Analyze code paths without running the program</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", textAlign: "center", height: "100%" }}>
                  <Typography variant="h3" sx={{ color: "#f59e0b" }}>3</Typography>
                  <Typography variant="subtitle2" sx={{ color: "#fff" }}>Sanitizers</Typography>
                  <Typography variant="caption" sx={{ color: "grey.400" }}>Runtime checks during testing catch actual overflows</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", textAlign: "center", height: "100%" }}>
                  <Typography variant="h3" sx={{ color: "#ef4444" }}>4</Typography>
                  <Typography variant="subtitle2" sx={{ color: "#fff" }}>Fuzzing</Typography>
                  <Typography variant="caption" sx={{ color: "grey.400" }}>Automated testing with boundary values</Typography>
                </Paper>
              </Grid>
            </Grid>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Defense in Depth</AlertTitle>
              Use multiple detection methods together: compiler warnings during development,
              sanitizers during testing, static analysis in CI/CD, and fuzzing for edge cases.
              Each method catches different types of bugs.
            </Alert>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {detectionTools.map((tool) => (
                <Grid item xs={12} md={6} key={tool.name}>
                  <Card variant="outlined" sx={{ height: "100%", bgcolor: "#151c2c" }}>
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                        <Typography variant="subtitle1" fontWeight="bold" sx={{ color: "#3b82f6" }}>{tool.name}</Typography>
                        <Chip label={tool.type} size="small" color="secondary" />
                      </Box>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>{tool.description}</Typography>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", bgcolor: "rgba(0,0,0,0.3)", p: 1, borderRadius: 1, mb: 2, color: "grey.300" }}>
                        {tool.usage}
                      </Typography>
                      <Grid container spacing={1}>
                        <Grid item xs={6}>
                          <Typography variant="caption" sx={{ color: "#10b981", fontWeight: 600 }}>Pros</Typography>
                          <List dense sx={{ py: 0 }}>
                            {tool.pros.map((pro) => (
                              <ListItem key={pro} sx={{ py: 0, px: 0 }}>
                                <ListItemText primary={<Typography variant="caption" sx={{ color: "grey.400" }}>{pro}</Typography>} />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" sx={{ color: "#ef4444", fontWeight: 600 }}>Cons</Typography>
                          <List dense sx={{ py: 0 }}>
                            {tool.cons.map((con) => (
                              <ListItem key={con} sx={{ py: 0, px: 0 }}>
                                <ListItemText primary={<Typography variant="caption" sx={{ color: "grey.400" }}>{con}</Typography>} />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Compiler Flags Reference</Typography>
            {compilerFlags.map((compiler) => (
              <Accordion key={compiler.compiler} sx={{ bgcolor: "#151c2c", mb: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                  <Typography fontWeight="bold" sx={{ color: "#fff" }}>{compiler.compiler}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "grey.400" }}>Flag</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>Description</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {compiler.flags.map((f) => (
                          <TableRow key={f.flag}>
                            <TableCell sx={{ fontFamily: "monospace", fontWeight: 600, color: "#3b82f6" }}>{f.flag}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{f.description}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            ))}
          </Paper>

          {/* ==================== SECTION: Language Behavior ==================== */}
          <Paper id="language-behavior" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <TranslateIcon sx={{ color: "#8b5cf6" }} />
              Language-Specific Behavior
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              One of the most important things to understand is that <strong>different languages handle overflow differently</strong>.
              What's safe in Python might be a critical vulnerability in C. When you switch languages or port code,
              these differences become especially dangerous.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Dangerous: Silent Wrapping/UB</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    C, C++, Go - overflow happens silently. In C/C++, signed overflow is even undefined behavior!
                    Most security vulnerabilities are in these languages.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>Better: Checked on Demand</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    Java, Rust, JavaScript - have checked methods available. Rust panics in debug mode.
                    You need to remember to use the safe APIs.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1 }}>Safest: Arbitrary Precision</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    Python 3 - integers automatically grow to any size. No overflow possible, but can still
                    cause memory exhaustion with huge numbers.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Not All Languages Are Equal</AlertTitle>
              Different programming languages handle integer overflow differently. Understanding these
              differences is crucial when working across languages or porting code. Code that works
              perfectly in Python might crash or be exploitable when translated to C.
            </Alert>

            <TableContainer component={Paper} sx={{ mb: 4, bgcolor: "#151c2c" }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Language</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Overflow Behavior</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Notes</TableCell>
                    <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Mitigations</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {languageBehaviors.map((lang) => (
                    <TableRow key={lang.language}>
                      <TableCell sx={{ fontWeight: 600, color: "#3b82f6" }}>{lang.language}</TableCell>
                      <TableCell sx={{ color: "grey.300" }}>{lang.behavior}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{lang.notes}</TableCell>
                      <TableCell>
                        <List dense sx={{ py: 0 }}>
                          {lang.mitigations.map((m) => (
                            <ListItem key={m} sx={{ py: 0, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 20 }}>
                                <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                              </ListItemIcon>
                              <ListItemText primary={<Typography variant="caption" sx={{ color: "grey.400" }}>{m}</Typography>} />
                            </ListItem>
                          ))}
                        </List>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Alert severity="warning" sx={{ mt: 3 }}>
              <AlertTitle>C/C++ Undefined Behavior Warning</AlertTitle>
              In C/C++, signed integer overflow is <strong>undefined behavior</strong>. This means the compiler
              can assume it never happens and optimize based on that assumption. Code that "works" in testing
              may fail in production with different compiler flags or versions!
            </Alert>
          </Paper>

          {/* ==================== SECTION: Prevention ==================== */}
          <Paper id="prevention" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <ShieldIcon sx={{ color: "#22c55e" }} />
              Prevention & Safe Coding
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              The good news is that integer overflow bugs are preventable! This section covers practical techniques
              you can apply immediately to write safer code. The key principle is: <strong>validate before you calculate</strong>.
            </Typography>

            <Alert severity="success" sx={{ mb: 3 }}>
              <AlertTitle>Prevention is Better Than Detection</AlertTitle>
              Use safe integer libraries, enable compiler warnings, and follow secure coding guidelines
              to prevent integer overflow vulnerabilities before they're introduced.
            </Alert>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>The Three Lines of Defense</Typography>
            <Stepper orientation="vertical" sx={{ mb: 3 }}>
              <Step active>
                <StepLabel>
                  <Typography sx={{ color: "#fff", fontWeight: 600 }}>1. Use Safe Types and Libraries</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    Use types like size_t for sizes, and safe integer libraries like SafeInt or checked arithmetic
                    that detect overflow automatically. This prevents bugs at the source.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography sx={{ color: "#fff", fontWeight: 600 }}>2. Validate Input Before Arithmetic</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    Check that values from untrusted sources (network, files, users) are within reasonable bounds
                    BEFORE using them in calculations. Reject impossibly large or negative values early.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography sx={{ color: "#fff", fontWeight: 600 }}>3. Use Compiler and Runtime Protection</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    Enable compiler warnings (-Wconversion), use sanitizers during testing (-fsanitize=undefined),
                    and consider using languages with built-in overflow checking (Rust, Python).
                  </Typography>
                </StepContent>
              </Step>
            </Stepper>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Safe Integer Libraries</Typography>
            <Grid container spacing={2} sx={{ mb: 4 }}>
              {safeLibraries.map((lib) => (
                <Grid item xs={12} md={6} key={lib.name}>
                  <Card variant="outlined" sx={{ height: "100%", bgcolor: "#151c2c" }}>
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                        <Typography variant="subtitle1" fontWeight="bold" sx={{ color: "#3b82f6" }}>{lib.name}</Typography>
                        <Chip label={lib.language} size="small" />
                      </Box>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>{lib.description}</Typography>
                      <CodeBlock language={lib.language.toLowerCase()}>{lib.example}</CodeBlock>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Best Practices Checklist</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 2 }}>DO</Typography>
                  <List dense>
                    {[
                      "Use size_t for sizes and counts",
                      "Check for overflow BEFORE arithmetic",
                      "Use calloc() instead of malloc(n * size)",
                      "Validate all user-controlled integers",
                      "Use safe integer libraries for critical code",
                      "Enable compiler warnings (-Wconversion)",
                      "Test with boundary values (0, MAX, MAX+1)",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                        </ListItemIcon>
                        <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 2 }}>DON'T</Typography>
                  <List dense>
                    {[
                      "Assume user input fits in your type",
                      "Mix signed and unsigned in comparisons",
                      "Cast without checking range first",
                      "Ignore compiler warnings about conversions",
                      "Use int for array sizes (prefer size_t)",
                      "Subtract unsigned without checking",
                      "Trust network-provided length fields",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <ErrorIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                        </ListItemIcon>
                        <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Paper>

          {/* ==================== SECTION: Practice ==================== */}
          <Paper id="practice" sx={{ p: 3, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#fff", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <ScienceIcon sx={{ color: "#f59e0b" }} />
              Practice & Learning Resources
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              Reading about integer overflow is one thing - actually exploiting a vulnerable program helps cement
              your understanding. These platforms provide <strong>legal, safe environments</strong> specifically
              designed for learning. You can't break anything that matters, so experiment freely!
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1 }}>Recommended Learning Path</Typography>
              <Stepper orientation="horizontal" alternativeLabel sx={{ pt: 1 }}>
                <Step completed><StepLabel><Typography variant="caption" sx={{ color: "grey.400" }}>Read theory (this page)</Typography></StepLabel></Step>
                <Step><StepLabel><Typography variant="caption" sx={{ color: "grey.400" }}>Try pwn.college or Phoenix</Typography></StepLabel></Step>
                <Step><StepLabel><Typography variant="caption" sx={{ color: "grey.400" }}>Solve CTF challenges</Typography></StepLabel></Step>
                <Step><StepLabel><Typography variant="caption" sx={{ color: "grey.400" }}>Review real-world code</Typography></StepLabel></Step>
              </Stepper>
            </Paper>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Hands-On Learning is Essential</AlertTitle>
              The best way to understand integer overflow vulnerabilities is to exploit them yourself
              in controlled environments. Theory only gets you so far - hands-on practice makes the concepts stick.
            </Alert>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Practice Platforms</Typography>
            <Grid container spacing={2} sx={{ mb: 4 }}>
              {practiceResources.map((resource) => (
                <Grid item xs={12} sm={6} md={3} key={resource.name}>
                  <Card variant="outlined" sx={{ height: "100%", bgcolor: "#151c2c" }}>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ color: "#3b82f6" }}>{resource.name}</Typography>
                      <Box sx={{ display: "flex", gap: 0.5, my: 1 }}>
                        <Chip label={resource.type} size="small" />
                        <Chip label={resource.difficulty} size="small" variant="outlined" />
                      </Box>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>{resource.description}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ color: "#fff", mb: 2 }}>Further Reading</Typography>
            <List>
              <ListItem>
                <ListItemIcon><SchoolIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
                <ListItemText
                  primary={<Typography sx={{ color: "#fff" }}>CERT C Secure Coding Standard - INT32-C, INT33-C</Typography>}
                  secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>Official guidelines for safe integer handling in C</Typography>}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><SchoolIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
                <ListItemText
                  primary={<Typography sx={{ color: "#fff" }}>CWE-190: Integer Overflow or Wraparound</Typography>}
                  secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>Common Weakness Enumeration entry with examples</Typography>}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><SchoolIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
                <ListItemText
                  primary={<Typography sx={{ color: "#fff" }}>'Hacking: The Art of Exploitation' by Jon Erickson</Typography>}
                  secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>Classic book covering integer overflow exploitation</Typography>}
                />
              </ListItem>
            </List>
          </Paper>

          {/* Related Learning */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Related Learning</Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              <Chip label="Buffer Overflow" clickable onClick={() => navigate("/learn/buffer-overflow")} sx={{ fontWeight: 600 }} />
              <Chip label="Heap Exploitation" clickable onClick={() => navigate("/learn/heap-exploitation")} sx={{ fontWeight: 600 }} />
              <Chip label="Format String" clickable onClick={() => navigate("/learn/format-string")} sx={{ fontWeight: 600 }} />
              <Chip label="Binary Exploitation" clickable onClick={() => navigate("/learn/binary-exploitation")} sx={{ fontWeight: 600 }} />
            </Box>
          </Paper>

          {/* ==================== SECTION: Quiz ==================== */}
          <Paper
            id="quiz-section"
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
              title="Integer Overflow and Underflow Knowledge Check"
              description="Random 10-question quiz drawn from a 75-question bank covering fundamentals, C/C++ behavior, types, arithmetic, security implications, prevention, testing, and language comparisons."
              questionsPerQuiz={QUIZ_QUESTION_COUNT}
            />
          </Paper>

          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ borderColor: "#f97316", color: "#f97316" }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
