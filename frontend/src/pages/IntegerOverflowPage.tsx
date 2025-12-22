import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
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
  Tabs,
  Tab,
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
import HistoryIcon from "@mui/icons-material/History";
import ShieldIcon from "@mui/icons-material/Shield";
import ErrorIcon from "@mui/icons-material/Error";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import DataObjectIcon from "@mui/icons-material/DataObject";
import { useNavigate } from "react-router-dom";

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

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

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
  { type: "long (64-bit)", signed: "-9,223,372,036,854,775,808 to 9,223,372,036,854,775,807", unsigned: "0 to 18,446,744,073,709,551,615", bits: 64 },
  { type: "size_t (32-bit)", signed: "N/A", unsigned: "0 to 4,294,967,295", bits: 32 },
  { type: "size_t (64-bit)", signed: "N/A", unsigned: "0 to 18,446,744,073,709,551,615", bits: 64 },
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
    cve: "CVE-2014-1266",
    name: "Apple SSL 'goto fail'",
    description: "Integer handling in SSL verification (related vulnerability)",
    impact: "MITM attacks on iOS/macOS SSL connections",
    cvss: "7.4",
    year: 2014,
    details: "While primarily a logic bug, the vulnerability chain involved integer handling issues in certificate verification that allowed attackers to bypass SSL/TLS protections.",
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
    cve: "CVE-2018-16323",
    name: "ImageMagick Memory Corruption",
    description: "Integer overflow in ReadXBMImage function",
    impact: "Denial of service, potential RCE",
    cvss: "6.5",
    year: 2018,
    details: "An integer overflow in width/height calculations led to undersized buffer allocation when processing malicious XBM images.",
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
    // size = count * 4 = 0x100000004 = 4 (truncated to 32-bit!)
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
  {
    name: "Multiplication Overflow in calloc",
    language: "c",
    vulnerable: `// VULNERABLE: Overflow in array allocation
void create_array(uint32_t num_elements) {
    // If num_elements = 0x20000000 (536,870,912)
    // Total = 0x20000000 * 8 = 0x100000000 = 0 (overflow)
    struct large_item *array = malloc(num_elements * sizeof(struct large_item));
    
    // malloc(0) may return valid pointer or NULL depending on implementation
    // Either way, accessing array[i] causes issues
    for (uint32_t i = 0; i < num_elements; i++) {
        init_item(&array[i]);  // CRASH or CORRUPTION
    }
}`,
    fixed: `// FIXED: Use calloc or check overflow
void create_array(uint32_t num_elements) {
    // calloc checks for overflow internally (on modern systems)
    struct large_item *array = calloc(num_elements, sizeof(struct large_item));
    if (!array) {
        return;  // Allocation failed (or overflow detected)
    }
    
    for (uint32_t i = 0; i < num_elements; i++) {
        init_item(&array[i]);
    }
}`,
    explanation: "calloc(n, size) is safer than malloc(n * size) because it checks for multiplication overflow internally.",
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
    cons: ["Requires recompilation", "Only finds executed paths", "Performance impact"],
  },
  {
    name: "Clang Static Analyzer",
    type: "Static Analysis",
    description: "Detects potential integer overflows through code path analysis",
    usage: "scan-build make / clang --analyze",
    pros: ["No runtime overhead", "Finds unexplored paths", "Integrates with IDEs"],
    cons: ["False positives", "May miss complex overflows", "Limited interprocedural analysis"],
  },
  {
    name: "Coverity",
    type: "Commercial Static Analysis",
    description: "Enterprise-grade static analyzer with advanced integer analysis",
    usage: "cov-build / cov-analyze / cov-commit-defects",
    pros: ["Low false positive rate", "Whole-program analysis", "Good reporting"],
    cons: ["Commercial license required", "Setup complexity", "Build integration needed"],
  },
  {
    name: "CodeQL",
    type: "Static Analysis",
    description: "Query-based analysis with pre-built integer overflow queries",
    usage: "codeql database analyze --queries=cpp-security-and-quality.qls",
    pros: ["Free for open source", "Customizable queries", "CI/CD integration"],
    cons: ["Learning curve", "Requires database creation", "Query performance varies"],
  },
  {
    name: "AFL++/LibFuzzer",
    type: "Fuzzing",
    description: "Coverage-guided fuzzers that can trigger integer overflows",
    usage: "afl-fuzz -i input -o output -- ./target @@",
    pros: ["Finds real bugs", "Automated exploration", "Generates test cases"],
    cons: ["Time-intensive", "May miss rare paths", "Needs harness development"],
  },
  {
    name: "Valgrind",
    type: "Dynamic Analysis",
    description: "Memory error detection that can catch overflow consequences",
    usage: "valgrind --tool=memcheck ./program",
    pros: ["No recompilation", "Detailed reports", "Mature tool"],
    cons: ["High overhead (20-50x)", "Detects effects not cause", "Limited to memory errors"],
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
    mitigations: ["Use BigInt for large integers", "Check Number.MAX_SAFE_INTEGER", "Be aware of precision limits"],
  },
];

// Exploitation techniques
const exploitationTechniques = [
  {
    name: "Heap Overflow via Size Calculation",
    difficulty: "Medium",
    steps: [
      "Identify allocation with user-controlled count/size",
      "Calculate overflow value: (MAX_INT / element_size) + 1",
      "Trigger allocation with overflowed (small) size",
      "Write beyond allocated buffer to corrupt heap metadata",
      "Leverage heap corruption for code execution",
    ],
    example: "count * sizeof(struct) overflows, malloc returns small buffer, memcpy corrupts heap",
  },
  {
    name: "Stack Buffer Overflow via Loop Bounds",
    difficulty: "Easy",
    steps: [
      "Find loop with user-controlled iteration count",
      "Identify integer overflow in bounds check",
      "Craft input that bypasses check but causes large iteration",
      "Loop writes past stack buffer, overwrites return address",
      "Control execution flow via ROP/JOP",
    ],
    example: "if (len < MAX) check passes due to signed comparison, loop iterates 2^32 times",
  },
  {
    name: "Arbitrary Write via Array Index",
    difficulty: "Hard",
    steps: [
      "Find array access with user-controlled index",
      "Identify signed-to-unsigned conversion",
      "Calculate negative index that becomes large unsigned",
      "Use relative offset to target specific memory location",
      "Write arbitrary value to arbitrary address",
    ],
    example: "array[user_index] where user_index=-100 accesses memory before array",
  },
  {
    name: "Type Confusion via Width Truncation",
    difficulty: "Medium",
    steps: [
      "Identify 64-bit to 32-bit truncation in size handling",
      "Craft value: (target_small_value) + 0x100000000",
      "Truncation produces small allocation size",
      "Use full 64-bit value in subsequent operations",
      "Exploit size mismatch for overflow",
    ],
    example: "64-bit size=0x100000010, truncated 32-bit=0x10, alloc 16 bytes, copy 4GB",
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
    link: "https://github.com/dcleblanc/SafeInt",
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
    link: "https://github.com/jhu-information-security-institute/safe_iop",
  },
  {
    name: "Boost.SafeNumerics",
    language: "C++",
    description: "Boost library for guaranteed correct integer arithmetic",
    example: `using safe_int = boost::safe_numerics::safe<int>;
safe_int x = INT_MAX;
x + 1;  // Throws std::overflow_error`,
    link: "https://www.boost.org/doc/libs/release/libs/safe_numerics/doc/html/index.html",
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
    link: "https://doc.rust-lang.org/std/primitive.u32.html#method.checked_add",
  },
];

// CTF/Practice challenges
const practiceResources = [
  {
    name: "pwn.college Integer Exploitation",
    type: "Educational Platform",
    difficulty: "Beginner to Advanced",
    description: "Structured curriculum with integer overflow challenges",
    url: "https://pwn.college/",
  },
  {
    name: "OverTheWire: Narnia/Behemoth",
    type: "Wargames",
    difficulty: "Intermediate",
    description: "Classic Linux exploitation including integer bugs",
    url: "https://overthewire.org/wargames/",
  },
  {
    name: "Exploit Education: Phoenix",
    type: "VM-based Learning",
    difficulty: "Beginner to Intermediate",
    description: "Integer overflow challenges with increasing difficulty",
    url: "https://exploit.education/phoenix/",
  },
  {
    name: "Hack The Box",
    type: "CTF Platform",
    difficulty: "Varies",
    description: "Various machines and challenges involving integer bugs",
    url: "https://www.hackthebox.eu/",
  },
  {
    name: "CTFtime Archive",
    type: "CTF Writeups",
    difficulty: "Varies",
    description: "Search for 'integer overflow' in past CTF writeups",
    url: "https://ctftime.org/writeups",
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
      { flag: "-fsanitize=integer", description: "Additional integer sanitizer checks" },
      { flag: "-Wconversion", description: "Warn on implicit conversions that may lose data" },
      { flag: "-Wsign-conversion", description: "Warn on sign conversion issues" },
      { flag: "-Warith-conversion", description: "Warn on arithmetic conversions" },
    ],
  },
  {
    compiler: "Clang",
    flags: [
      { flag: "-fsanitize=integer", description: "Comprehensive integer sanitizer" },
      { flag: "-fsanitize=unsigned-integer-overflow", description: "Detect unsigned overflow (not UB but often bug)" },
      { flag: "-fsanitize=implicit-conversion", description: "Detect problematic implicit conversions" },
      { flag: "-Wshorten-64-to-32", description: "Warn on 64-to-32 bit truncation" },
      { flag: "-Wimplicit-int-conversion", description: "Warn on implicit integer conversions" },
    ],
  },
  {
    compiler: "MSVC",
    flags: [
      { flag: "/RTCc", description: "Runtime check for data truncation" },
      { flag: "/sdl", description: "Enable additional security checks" },
      { flag: "/W4", description: "Enable high warning level (includes conversion warnings)" },
      { flag: "/analyze", description: "Enable static code analysis" },
    ],
  },
];

export default function IntegerOverflowPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `Integer Overflows and Underflows Comprehensive Guide - Covers integer overflow, underflow, signed/unsigned mismatches, width truncation, root causes, conversion pitfalls, and boundary testing. Includes real-world CVE examples (CVE-2021-21224, CVE-2016-0728, CVE-2020-0796 SMBGhost), detailed code examples with vulnerable and fixed versions, exploitation techniques, detection tools (sanitizers, static analysis, fuzzing), language-specific behaviors (C/C++, Java, Python, Rust, Go, JavaScript), safe integer libraries (SafeInt, Boost.SafeNumerics), compiler flags reference, and practice resources. Explains exploitation scenarios including buffer size calculations, loop bounds, memory allocation, and array indexing.`;

  return (
    <LearnPageLayout pageTitle="Integer Overflows & Underflows" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
            Back to Learning Hub
          </Button>
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
                Comprehensive guide to arithmetic boundary vulnerabilities
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Memory Corruption" color="warning" size="small" />
            <Chip label="C/C++" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
            <Chip label="Binary Exploitation" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
            <Chip label="8 Sections" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
          </Box>
        </Box>

        {/* Tabs */}
        <Paper sx={{ mb: 3 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ borderBottom: 1, borderColor: "divider" }}
          >
            <Tab icon={<SchoolIcon />} label="Fundamentals" />
            <Tab icon={<CodeIcon />} label="Code Examples" />
            <Tab icon={<BugReportIcon />} label="CVE Case Studies" />
            <Tab icon={<SecurityIcon />} label="Exploitation" />
            <Tab icon={<BuildIcon />} label="Detection Tools" />
            <Tab icon={<DataObjectIcon />} label="Language Behavior" />
            <Tab icon={<ShieldIcon />} label="Prevention" />
            <Tab icon={<TerminalIcon />} label="Practice" />
          </Tabs>
        </Paper>

        {/* Tab 0: Fundamentals */}
        <TabPanel value={tabValue} index={0}>
          <Typography variant="h5" gutterBottom>Understanding Integer Overflows & Underflows</Typography>
          
          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>What is Integer Overflow?</AlertTitle>
            Integer overflow occurs when an arithmetic operation produces a value outside the representable range 
            of the data type. In languages like C/C++, these wrap around silently, leading to unexpected behavior 
            that can be exploited for security vulnerabilities.
          </Alert>

          {/* Vulnerability Types */}
          <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>🎯 Vulnerability Types</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {vulnTypes.map((v) => (
              <Grid item xs={12} sm={6} key={v.title}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 2,
                    border: `1px solid ${alpha(v.color, 0.2)}`,
                    "&:hover": { borderColor: v.color },
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: v.color, mb: 1 }}>
                    {v.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
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

          {/* Data Type Limits */}
          <Typography variant="h6" gutterBottom>📊 Data Type Limits Reference</Typography>
          <TableContainer component={Paper} sx={{ mb: 4 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Bits</strong></TableCell>
                  <TableCell><strong>Signed Range</strong></TableCell>
                  <TableCell><strong>Unsigned Range</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataTypeLimits.map((dt) => (
                  <TableRow key={dt.type}>
                    <TableCell><Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>{dt.type}</Typography></TableCell>
                    <TableCell><Chip label={`${dt.bits} bits`} size="small" /></TableCell>
                    <TableCell><Typography variant="body2" sx={{ fontFamily: "monospace" }}>{dt.signed}</Typography></TableCell>
                    <TableCell><Typography variant="body2" sx={{ fontFamily: "monospace" }}>{dt.unsigned}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Typography variant="h6" gutterBottom>Common Root Causes and Sources</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 2 }}>Root Causes</Typography>
                <List dense>
                  {rootCauses.map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
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
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          {/* How Overflow Happens */}
          <Typography variant="h6" gutterBottom>🔄 How Overflow Works</Typography>
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
// 01111111 + 00000001 = 10000000 = -128 (two's complement)`}</CodeBlock>
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

          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
            <Typography variant="h6" gutterBottom>Conversion and Promotion Pitfalls (C/C++)</Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: "action.hover" }}>
                    <TableCell><strong>Rule</strong></TableCell>
                    <TableCell><strong>Example</strong></TableCell>
                    <TableCell><strong>Risk</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {conversionPitfalls.map((row) => (
                    <TableRow key={row.rule}>
                      <TableCell><Typography variant="body2" sx={{ fontWeight: 600 }}>{row.rule}</Typography></TableCell>
                      <TableCell><Typography variant="body2" sx={{ fontFamily: "monospace" }}>{row.example}</Typography></TableCell>
                      <TableCell><Typography variant="body2" color="text.secondary">{row.risk}</Typography></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Exploitation Scenarios */}
          <Paper
            sx={{
              p: 3,
              mb: 4,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)}, ${alpha("#f59e0b", 0.05)})`,
              border: `1px solid ${alpha("#ef4444", 0.2)}`,
            }}
          >
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>💥 Common Exploitation Scenarios</Typography>
            <Grid container spacing={2}>
              {exploitScenarios.map((scenario, i) => (
                <Grid item xs={12} sm={6} key={i}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    <Typography variant="body2">{scenario}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Vulnerable Patterns */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon sx={{ color: "#8b5cf6" }} /> Vulnerable Code Patterns to Watch For
            </Typography>
            <Grid container spacing={2}>
              {codePatterns.map((p) => (
                <Grid item xs={12} sm={6} key={p.pattern}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                    <Chip label={p.pattern} size="small" sx={{ fontFamily: "monospace", fontWeight: 600 }} />
                    <Typography variant="caption" color="text.secondary">- {p.risk}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.05) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                  Boundary Value Testing Checklist
                </Typography>
                <List dense>
                  {boundaryValues.map((item) => (
                    <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.05) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                  Safe Size Calculation Workflow
                </Typography>
                <Stepper orientation="vertical">
                  {safeSizingWorkflow.map((step) => (
                    <Step key={step.title} active completed={false}>
                      <StepLabel>
                        <Typography variant="body2">{step.title}</Typography>
                      </StepLabel>
                      <StepContent>
                        <Typography variant="body2" color="text.secondary">{step.detail}</Typography>
                      </StepContent>
                    </Step>
                  ))}
                </Stepper>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 1: Code Examples */}
        <TabPanel value={tabValue} index={1}>
          <Typography variant="h5" gutterBottom>Vulnerable vs. Fixed Code Examples</Typography>
          
          <Alert severity="warning" sx={{ mb: 3 }}>
            <AlertTitle>Learning from Examples</AlertTitle>
            Each example shows a vulnerable pattern, the fixed version, and explains why the vulnerability exists.
            Understanding these patterns helps identify similar bugs in real codebases.
          </Alert>

          {vulnerableCodeExamples.map((example, idx) => (
            <Accordion key={example.name} defaultExpanded={idx === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={idx + 1} size="small" color="primary" />
                  <Typography fontWeight="bold">{example.name}</Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" paragraph>
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

          <Typography variant="h6" gutterBottom>Quick Reference: Overflow Check Patterns</Typography>
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
        </TabPanel>

        {/* Tab 2: CVE Case Studies */}
        <TabPanel value={tabValue} index={2}>
          <Typography variant="h5" gutterBottom>Real-World CVE Case Studies</Typography>
          
          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>Learning from History</AlertTitle>
            These CVEs demonstrate how integer overflows have been exploited in real software, 
            from browsers to operating systems. Understanding past vulnerabilities helps prevent future ones.
          </Alert>

          <Grid container spacing={2}>
            {realWorldCVEs.map((cve) => (
              <Grid item xs={12} md={6} key={cve.cve}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "primary.main" }}>
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
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>{cve.name}</Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>{cve.description}</Typography>
                    <Alert severity="error" sx={{ mb: 1 }}>
                      <Typography variant="caption"><strong>Impact:</strong> {cve.impact}</Typography>
                    </Alert>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{cve.details}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" gutterBottom>CVE-2020-0796 (SMBGhost) Deep Dive</Typography>
          <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
            <Typography variant="body2" paragraph>
              SMBGhost is one of the most impactful integer overflow vulnerabilities discovered. It affected Windows 10 
              SMBv3 compression handling and was wormable (could spread without user interaction).
            </Typography>
            <CodeBlock title="Simplified Vulnerability Pattern" language="c">{`// Vulnerable code pattern in srv2.sys
ULONG OriginalCompressedSegmentSize;  // 32-bit, attacker controlled
ULONG Offset;                          // 32-bit, attacker controlled

// Integer overflow in size calculation!
ULONG TotalSize = OriginalCompressedSegmentSize + Offset;

// If OriginalCompressedSegmentSize = 0xFFFFFFFF and Offset = 0x10
// TotalSize = 0xFFFFFFFF + 0x10 = 0x0F (overflow!)

// Allocates tiny buffer
Buffer = ExAllocatePoolWithTag(TotalSize, ...);

// Decompresses much more data than buffer can hold
RtlDecompressBuffer(Buffer, OriginalCompressedSegmentSize, ...);  // OVERFLOW!`}</CodeBlock>
            <Alert severity="info" sx={{ mt: 2 }}>
              <strong>Key Lesson:</strong> Always validate size fields from untrusted network input, especially 
              in kernel code where exploitation leads to complete system compromise.
            </Alert>
          </Paper>
        </TabPanel>

        {/* Tab 3: Exploitation */}
        <TabPanel value={tabValue} index={3}>
          <Typography variant="h5" gutterBottom>Exploitation Techniques</Typography>
          
          <Alert severity="warning" sx={{ mb: 3 }}>
            <AlertTitle>Educational Purpose Only</AlertTitle>
            Understanding exploitation techniques is crucial for security professionals. 
            Only practice on systems you own or have explicit permission to test.
          </Alert>

          {exploitationTechniques.map((tech, idx) => (
            <Accordion key={tech.name} defaultExpanded={idx === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                  <BugReportIcon color="error" />
                  <Typography fontWeight="bold" sx={{ flex: 1 }}>{tech.name}</Typography>
                  <Chip 
                    label={tech.difficulty} 
                    size="small" 
                    color={tech.difficulty === "Easy" ? "success" : tech.difficulty === "Medium" ? "warning" : "error"} 
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Stepper orientation="vertical">
                  {tech.steps.map((step, i) => (
                    <Step key={i} active completed={false}>
                      <StepLabel>
                        <Typography variant="body2">{step}</Typography>
                      </StepLabel>
                    </Step>
                  ))}
                </Stepper>
                <Alert severity="info" sx={{ mt: 2 }}>
                  <strong>Example:</strong> {tech.example}
                </Alert>
              </AccordionDetails>
            </Accordion>
          ))}

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" gutterBottom>Exploitation Workflow Example</Typography>
          <CodeBlock title="Heap Overflow via Integer Overflow" language="c">{`// Target: Vulnerable function
void process_items(uint16_t count) {
    // Overflow: count=0x4001, count*16=0x40010=0x10 (truncated)
    struct item *items = malloc(count * sizeof(struct item));
    for (int i = 0; i < count; i++) {
        read_item(&items[i]);  // Writes past allocation!
    }
}

// Attacker's approach:
// 1. Calculate overflow value:
//    - sizeof(struct item) = 16 bytes
//    - Want malloc(16) but loop 16385 times
//    - 16385 * 16 = 262160 = 0x40010
//    - Truncated to 16-bit: 0x40010 & 0xFFFF = 0x10 = 16

// 2. Send count = 16385 (0x4001)
// 3. malloc(16) called, but loop writes 262160 bytes
// 4. Heap metadata corrupted
// 5. Craft next allocation to achieve arbitrary write
// 6. Overwrite function pointer or GOT entry
// 7. Gain code execution`}</CodeBlock>

          <Typography variant="h6" gutterBottom sx={{ mt: 4 }}>Useful Values for Exploitation</Typography>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Max Value (Hex)</strong></TableCell>
                  <TableCell><strong>Useful Overflow Inputs</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell>uint8_t</TableCell>
                  <TableCell>0xFF (255)</TableCell>
                  <TableCell>256 (wraps to 0), 257 (wraps to 1)</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>uint16_t</TableCell>
                  <TableCell>0xFFFF (65535)</TableCell>
                  <TableCell>65536 (0), 0x10000 + target</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>uint32_t</TableCell>
                  <TableCell>0xFFFFFFFF</TableCell>
                  <TableCell>0x100000000 + target, SIZE_MAX / n + 1</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>int32_t (signed)</TableCell>
                  <TableCell>0x7FFFFFFF (2147483647)</TableCell>
                  <TableCell>-1 (becomes large unsigned), INT_MIN</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        {/* Tab 4: Detection Tools */}
        <TabPanel value={tabValue} index={4}>
          <Typography variant="h5" gutterBottom>Detection Tools & Techniques</Typography>
          
          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>Defense in Depth</AlertTitle>
            Use multiple detection methods together: compiler warnings during development, 
            sanitizers during testing, static analysis in CI/CD, and fuzzing for edge cases.
          </Alert>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {detectionTools.map((tool) => (
              <Grid item xs={12} md={6} key={tool.name}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold" color="primary">{tool.name}</Typography>
                      <Chip label={tool.type} size="small" color="secondary" />
                    </Box>
                    <Typography variant="body2" color="text.secondary" paragraph>{tool.description}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", bgcolor: "action.hover", p: 1, borderRadius: 1, mb: 2 }}>
                      {tool.usage}
                    </Typography>
                    <Grid container spacing={1}>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="success.main" fontWeight="bold">✓ Pros</Typography>
                        <List dense sx={{ py: 0 }}>
                          {tool.pros.map((pro) => (
                            <ListItem key={pro} sx={{ py: 0, px: 0 }}>
                              <ListItemText primary={<Typography variant="caption">{pro}</Typography>} />
                            </ListItem>
                          ))}
                        </List>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="error.main" fontWeight="bold">✗ Cons</Typography>
                        <List dense sx={{ py: 0 }}>
                          {tool.cons.map((con) => (
                            <ListItem key={con} sx={{ py: 0, px: 0 }}>
                              <ListItemText primary={<Typography variant="caption">{con}</Typography>} />
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

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Compiler Flags Reference</Typography>
          {compilerFlags.map((compiler) => (
            <Accordion key={compiler.compiler}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">{compiler.compiler}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell><strong>Flag</strong></TableCell>
                        <TableCell><strong>Description</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {compiler.flags.map((f) => (
                        <TableRow key={f.flag}>
                          <TableCell><Typography sx={{ fontFamily: "monospace", fontWeight: 600 }}>{f.flag}</Typography></TableCell>
                          <TableCell><Typography variant="body2">{f.description}</Typography></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          ))}

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>UBSan in Action</Typography>
          <CodeBlock title="Example UBSan Output" language="bash">{`$ gcc -fsanitize=undefined,integer -o test test.c
$ ./test

test.c:15:22: runtime error: signed integer overflow: 
2147483647 + 1 cannot be represented in type 'int'

test.c:23:18: runtime error: unsigned integer overflow: 
0 - 1 cannot be represented in type 'unsigned int'

test.c:31:15: runtime error: implicit conversion from type 'int' 
of value -1 (32-bit, signed) to type 'unsigned int' changed the 
value to 4294967295 (32-bit, unsigned)`}</CodeBlock>
        </TabPanel>

        {/* Tab 5: Language Behavior */}
        <TabPanel value={tabValue} index={5}>
          <Typography variant="h5" gutterBottom>Language-Specific Behavior</Typography>
          
          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>Not All Languages Are Equal</AlertTitle>
            Different programming languages handle integer overflow differently. Understanding these 
            differences is crucial when working across languages or porting code.
          </Alert>

          <TableContainer component={Paper} sx={{ mb: 4 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Language</strong></TableCell>
                  <TableCell><strong>Overflow Behavior</strong></TableCell>
                  <TableCell><strong>Notes</strong></TableCell>
                  <TableCell><strong>Mitigations</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {languageBehaviors.map((lang) => (
                  <TableRow key={lang.language}>
                    <TableCell>
                      <Typography fontWeight="bold" color="primary">{lang.language}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{lang.behavior}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">{lang.notes}</Typography>
                    </TableCell>
                    <TableCell>
                      <List dense sx={{ py: 0 }}>
                        {lang.mitigations.map((m) => (
                          <ListItem key={m} sx={{ py: 0, px: 0 }}>
                            <ListItemIcon sx={{ minWidth: 20 }}>
                              <CheckCircleIcon sx={{ fontSize: 14, color: "success.main" }} />
                            </ListItemIcon>
                            <ListItemText primary={<Typography variant="caption">{m}</Typography>} />
                          </ListItem>
                        ))}
                      </List>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>Rust's Approach</Typography>
              <CodeBlock title="Rust Checked Arithmetic" language="rust">{`// Debug mode: panics on overflow
let x: u8 = 255;
let y = x + 1;  // PANIC in debug!

// Release mode: wraps silently (for performance)
// Use explicit methods for safety:

// Option-returning (safe)
let result = x.checked_add(1);  // Returns None

// Wrapping (explicit intent)
let result = x.wrapping_add(1);  // Returns 0

// Saturating (clamps to max/min)
let result = x.saturating_add(1);  // Returns 255

// Overflowing (returns tuple)
let (result, overflow) = x.overflowing_add(1);
// result = 0, overflow = true`}</CodeBlock>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>Java's Approach</Typography>
              <CodeBlock title="Java Math.exact Methods" language="java">{`// Regular arithmetic wraps silently
int a = Integer.MAX_VALUE;
int b = a + 1;  // Wraps to Integer.MIN_VALUE

// Math.exact methods throw ArithmeticException
try {
    int safe = Math.addExact(a, 1);
} catch (ArithmeticException e) {
    System.out.println("Overflow detected!");
}

// Available methods:
// Math.addExact(int, int)
// Math.subtractExact(int, int)
// Math.multiplyExact(int, int)
// Math.incrementExact(int)
// Math.decrementExact(int)
// Math.negateExact(int)
// Math.toIntExact(long)  // Checks truncation`}</CodeBlock>
            </Grid>
          </Grid>

          <Alert severity="warning" sx={{ mt: 3 }}>
            <AlertTitle>C/C++ Undefined Behavior Warning</AlertTitle>
            In C/C++, signed integer overflow is <strong>undefined behavior</strong>. This means the compiler 
            can assume it never happens and optimize based on that assumption. Code that "works" in testing 
            may fail in production with different compiler flags or versions!
          </Alert>
          
          <CodeBlock title="Undefined Behavior Example" language="c">{`// This function may be optimized away entirely!
int check_overflow(int x) {
    if (x + 1 < x) {  // Overflow check
        return 1;  // "Overflow occurred"
    }
    return 0;  // "No overflow"
}

// Compiler reasoning:
// "Signed overflow is UB, so x + 1 >= x always"
// "Therefore the if-condition is always false"
// "Optimize to: return 0;"

// Use -fwrapv to disable this optimization,
// or use unsigned types for defined wrapping behavior.`}</CodeBlock>
        </TabPanel>

        {/* Tab 6: Prevention */}
        <TabPanel value={tabValue} index={6}>
          <Typography variant="h5" gutterBottom>Prevention & Safe Coding</Typography>
          
          <Alert severity="success" sx={{ mb: 3 }}>
            <AlertTitle>Prevention is Better Than Detection</AlertTitle>
            Use safe integer libraries, enable compiler warnings, and follow secure coding guidelines 
            to prevent integer overflow vulnerabilities before they're introduced.
          </Alert>

          <Typography variant="h6" gutterBottom>Safe Integer Libraries</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {safeLibraries.map((lib) => (
              <Grid item xs={12} md={6} key={lib.name}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold" color="primary">{lib.name}</Typography>
                      <Chip label={lib.language} size="small" />
                    </Box>
                    <Typography variant="body2" color="text.secondary" paragraph>{lib.description}</Typography>
                    <CodeBlock language={lib.language.toLowerCase()}>{lib.example}</CodeBlock>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Best Practices Checklist</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 2 }}>✅ DO</Typography>
                <List dense>
                  {[
                    "Use size_t for sizes and counts",
                    "Check for overflow BEFORE arithmetic",
                    "Use calloc() instead of malloc(n * size)",
                    "Validate all user-controlled integers",
                    "Use safe integer libraries for critical code",
                    "Enable compiler warnings (-Wconversion)",
                    "Use static analysis in CI/CD pipeline",
                    "Prefer unsigned for non-negative values",
                    "Document integer assumptions in code",
                    "Test with boundary values (0, MAX, MAX+1)",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 2 }}>❌ DON'T</Typography>
                <List dense>
                  {[
                    "Assume user input fits in your type",
                    "Mix signed and unsigned in comparisons",
                    "Cast without checking range first",
                    "Ignore compiler warnings about conversions",
                    "Use int for array sizes (prefer size_t)",
                    "Subtract unsigned without checking",
                    "Trust network-provided length fields",
                    "Rely on undefined behavior 'working'",
                    "Skip overflow checks for 'trusted' data",
                    "Assume multiplication won't overflow",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <ErrorIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Recommended Compiler Settings</Typography>
          <CodeBlock title="GCC/Clang Security Flags" language="bash">{`# Development build (catch bugs early)
CFLAGS="-Wall -Wextra -Wconversion -Wsign-conversion -Werror \\
        -fsanitize=undefined,integer -ftrapv"

# Testing build (thorough checking)
CFLAGS="-Wall -Wextra -fsanitize=address,undefined,integer \\
        -fno-omit-frame-pointer -g"

# Release build (defined behavior for signed)
CFLAGS="-Wall -Wextra -O2 -fwrapv -D_FORTIFY_SOURCE=2"

# Hardened release
CFLAGS="-Wall -Wextra -O2 -fwrapv -D_FORTIFY_SOURCE=2 \\
        -fstack-protector-strong -pie -fPIE"`}</CodeBlock>
        </TabPanel>

        {/* Tab 7: Practice */}
        <TabPanel value={tabValue} index={7}>
          <Typography variant="h5" gutterBottom>Practice & Learning Resources</Typography>
          
          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>Hands-On Learning</AlertTitle>
            The best way to understand integer overflow vulnerabilities is to exploit them yourself 
            in controlled environments. These resources provide safe, legal practice opportunities.
          </Alert>

          <Typography variant="h6" gutterBottom>Practice Platforms</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {practiceResources.map((resource) => (
              <Grid item xs={12} sm={6} md={4} key={resource.name}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Typography variant="subtitle1" fontWeight="bold" color="primary">{resource.name}</Typography>
                    <Box sx={{ display: "flex", gap: 0.5, my: 1 }}>
                      <Chip label={resource.type} size="small" />
                      <Chip label={resource.difficulty} size="small" variant="outlined" />
                    </Box>
                    <Typography variant="body2" color="text.secondary" paragraph>{resource.description}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                      {resource.url}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Practice Challenge: Find the Bug</Typography>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="body2" paragraph>
              Each code snippet below contains an integer overflow vulnerability. 
              Try to identify the bug before revealing the answer.
            </Typography>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Challenge 1: Memory Allocation</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="c">{`void read_records(FILE *f) {
    uint16_t count;
    fread(&count, sizeof(count), 1, f);
    
    struct record *records = malloc(count * sizeof(struct record));
    fread(records, sizeof(struct record), count, f);
    
    // Process records...
}`}</CodeBlock>
                <Alert severity="error" sx={{ mt: 2 }}>
                  <strong>Bug:</strong> If sizeof(struct record) &gt; 4 and count is large (e.g., 0x4000), 
                  the multiplication can overflow. Also, count is 16-bit but may be used as 32-bit implicitly.
                </Alert>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Challenge 2: Length Validation</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="c">{`#define MAX_DATA_LEN 1024

int process_packet(uint8_t *packet, int packet_len) {
    int header_len = packet[0];
    int data_len = packet_len - header_len;
    
    if (data_len > MAX_DATA_LEN) {
        return -1;  // Too large
    }
    
    memcpy(buffer, packet + header_len, data_len);
    return 0;
}`}</CodeBlock>
                <Alert severity="error" sx={{ mt: 2 }}>
                  <strong>Bug:</strong> If header_len &gt; packet_len, data_len becomes negative. 
                  The comparison data_len &gt; MAX_DATA_LEN passes (negative &lt; 1024), 
                  but memcpy interprets the negative as a huge positive size_t!
                </Alert>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Challenge 3: Array Bounds</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="c">{`#define ARRAY_SIZE 100
int global_array[ARRAY_SIZE];

int get_element(int index) {
    if (index < ARRAY_SIZE) {
        return global_array[index];
    }
    return -1;
}`}</CodeBlock>
                <Alert severity="error" sx={{ mt: 2 }}>
                  <strong>Bug:</strong> No check for negative index! If index = -10, 
                  the comparison -10 &lt; 100 is true, but global_array[-10] accesses 
                  memory before the array (underflow/out-of-bounds read).
                </Alert>
              </AccordionDetails>
            </Accordion>
          </Paper>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Further Reading</Typography>
          <List>
            <ListItem>
              <ListItemIcon><SchoolIcon color="primary" /></ListItemIcon>
              <ListItemText 
                primary="CERT C Secure Coding Standard - INT32-C, INT33-C" 
                secondary="Official guidelines for safe integer handling in C"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><SchoolIcon color="primary" /></ListItemIcon>
              <ListItemText 
                primary="CWE-190: Integer Overflow or Wraparound" 
                secondary="Common Weakness Enumeration entry with examples"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><SchoolIcon color="primary" /></ListItemIcon>
              <ListItemText 
                primary="OWASP Integer Overflow" 
                secondary="Web security perspective on integer vulnerabilities"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><SchoolIcon color="primary" /></ListItemIcon>
              <ListItemText 
                primary="'Hacking: The Art of Exploitation' by Jon Erickson" 
                secondary="Classic book covering integer overflow exploitation"
              />
            </ListItem>
          </List>
        </TabPanel>

        {/* Related Learning */}
        <Paper sx={{ p: 3, mt: 4, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Buffer Overflow ->" clickable onClick={() => navigate("/learn/buffer-overflow")} sx={{ fontWeight: 600 }} />
            <Chip label="Heap Exploitation ->" clickable onClick={() => navigate("/learn/heap-exploitation")} sx={{ fontWeight: 600 }} />
            <Chip label="Format String ->" clickable onClick={() => navigate("/learn/format-string")} sx={{ fontWeight: 600 }} />
            <Chip label="Binary Exploitation ->" clickable onClick={() => navigate("/learn/binary-exploitation")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}


