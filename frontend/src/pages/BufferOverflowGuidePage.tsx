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
import { Link } from "react-router-dom";
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

export default function BufferOverflowGuidePage() {
  const theme = useTheme();
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
      </Box>
    </Box>
    </LearnPageLayout>
  );
}
