import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  Card,
  CardContent,
  alpha,
  Divider,
  Alert,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SearchIcon from "@mui/icons-material/Search";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SchoolIcon from "@mui/icons-material/School";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

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

const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({
  code,
  language = "bash",
  title,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        bgcolor: "#0d1117",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(249, 115, 22, 0.2)",
        overflow: "hidden",
      }}
    >
      {title && (
        <Box sx={{ px: 2, py: 1, bgcolor: "rgba(249, 115, 22, 0.1)", borderBottom: "1px solid rgba(249, 115, 22, 0.2)" }}>
          <Typography variant="subtitle2" sx={{ color: "#f97316", fontWeight: 600 }}>{title}</Typography>
        </Box>
      )}
      <Box sx={{ position: "absolute", top: title ? 40 : 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: alpha("#f97316", 0.2), color: "#f97316", fontSize: "0.7rem" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: copied ? "#f97316" : "#888" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          pt: 3,
          overflow: "auto",
          fontFamily: "'Fira Code', 'Consolas', monospace",
          fontSize: "0.8rem",
          color: "#e6edf3",
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const BinaryAnalysisGuidePage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const binaryFormats = [
    { format: "PE (Portable Executable)", os: "Windows", ext: ".exe, .dll, .sys", description: "Windows executables, libraries, and drivers" },
    { format: "ELF (Executable & Linkable)", os: "Linux/Unix", ext: ".so, (no ext)", description: "Linux executables, shared libraries" },
    { format: "Mach-O", os: "macOS/iOS", ext: ".dylib, .app", description: "Apple platform binaries" },
  ];

  const suspiciousImports = [
    { category: "Process Injection", functions: "VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, NtQueueApcThread", risk: "Critical" },
    { category: "Keylogging", functions: "SetWindowsHookEx, GetAsyncKeyState, GetKeyState", risk: "High" },
    { category: "Network", functions: "WSAStartup, socket, connect, send, recv, InternetOpen", risk: "Medium" },
    { category: "Crypto (Potential)", functions: "CryptAcquireContext, CryptEncrypt, CryptDecrypt", risk: "Medium" },
    { category: "Anti-Debug", functions: "IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess", risk: "High" },
    { category: "File Operations", functions: "CreateFile, WriteFile, DeleteFile, MoveFile", risk: "Low" },
    { category: "Registry", functions: "RegOpenKey, RegSetValue, RegCreateKey", risk: "Medium" },
  ];

  const vulnCategories = [
    { type: "Buffer Overflow", description: "Writing beyond allocated memory bounds", indicators: "strcpy, sprintf, gets, strcat, memcpy without bounds checking", severity: "Critical" },
    { type: "Format String", description: "Uncontrolled format specifiers in printf-like functions", indicators: "printf(user_input), sprintf without format, syslog", severity: "Critical" },
    { type: "Use-After-Free", description: "Accessing memory after it's been freed", indicators: "free() followed by pointer dereference, reuse of freed objects", severity: "Critical" },
    { type: "Integer Overflow", description: "Arithmetic operations exceeding type limits", indicators: "malloc(n * size) without overflow check, wraparound in loops", severity: "High" },
    { type: "Command Injection", description: "Executing shell commands with user input", indicators: "system(), popen(), exec* with concatenated strings, WinExec", severity: "Critical" },
    { type: "Path Traversal", description: "Accessing files outside intended directory", indicators: "open(), fopen() with user-controlled paths, '../' sequences", severity: "High" },
    { type: "Hardcoded Credentials", description: "Embedded passwords, API keys, or secrets", indicators: "Readable strings: password=, api_key=, secret, bearer token", severity: "High" },
    { type: "Race Condition (TOCTOU)", description: "Time-of-check to time-of-use vulnerabilities", indicators: "access() followed by open(), stat() then file operation", severity: "Medium" },
    { type: "Double Free", description: "Freeing memory that has already been freed", indicators: "Multiple free() calls on same pointer, missing NULL assignment", severity: "Critical" },
    { type: "Null Pointer Dereference", description: "Using pointer without checking for NULL", indicators: "Dereference after malloc without check, return value ignored", severity: "Medium" },
    { type: "Crypto Weakness", description: "Use of weak or deprecated cryptographic algorithms", indicators: "MD5, SHA1 for passwords, DES, hardcoded keys, weak PRNG", severity: "High" },
    { type: "Heap Overflow", description: "Writing beyond heap-allocated buffer", indicators: "malloc + strcpy/memcpy without size validation", severity: "Critical" },
  ];

  const vrAgentFeatures = [
    { feature: "Unified Binary Scan (11 Phases)", description: "Complete analysis with real-time streaming progress: static analysis, Ghidra decompilation, AI summaries, pattern scanning, CVE lookup, sensitive data scan, vulnerability hunting, AI verification, attack surface mapping, emulation, and report generation", icon: <PlayArrowIcon />, color: "#22c55e" },
    { feature: "4-Tab Results View", description: "AI-generated reports: What Does This Binary Do?, Security Findings with CWE references, Architecture Diagram (Mermaid), and Attack Surface Map (exploitable entry points)", icon: <VisibilityIcon />, color: "#3b82f6" },
    { feature: "Agentic Malware Analysis (6 AI Agents)", description: "Autonomous multi-agent system: Orchestrator (workflow coordination), Static Analysis (binary structure), Dynamic Analysis (runtime monitoring), Behavioral (pattern recognition), Unpacking (packer/crypter handling), Evasion Detection (anti-analysis techniques). MITRE ATT&CK mapping included", icon: <AutoAwesomeIcon />, color: "#dc2626" },
    { feature: "Malware Detection Engine", description: "YARA rules (Ransomware, RAT, Backdoor, Infostealer, Cryptominer), packer/crypter detection, C2 beacon detection (HTTP/DNS/TCP), persistence mechanisms (Registry/Services/Tasks), privilege escalation (DLL hijacking, token manipulation), lateral movement (Pass-the-Hash, RDP, WMI)", icon: <SecurityIcon />, color: "#ea580c" },
    { feature: "Frida Dynamic Instrumentation", description: "Runtime binary hooking with API call tracing, network/filesystem/registry monitoring, crypto operation detection, anti-evasion capabilities, sandboxed execution with artifact collection", icon: <BugReportIcon />, color: "#f97316" },
    { feature: "Agentic Binary Fuzzer", description: "AI-driven fuzzing campaigns with autonomous decision-making: intelligent crash triage with root cause analysis, automated exploit generation, ROP gadget finding, mitigation bypass suggestions, campaign management (start/pause/resume/stop)", icon: <BugReportIcon />, color: "#f59e0b" },
    { feature: "AI Vulnerability Hunter", description: "Multi-pass autonomous hunting: Pass 1 (Reconnaissance), Pass 2 (AI Triage), Pass 3+ (Deep Analysis). Detects buffer overflows, format strings, use-after-free, integer overflows, command injection, path traversal, race conditions, crypto weaknesses", icon: <BugReportIcon />, color: "#ef4444" },
    { feature: "AI Decompiler Enhancement", description: "Transform Ghidra output into readable code: intelligent variable renaming (var_14 → encryptionKey), inline security annotations, data structure reconstruction, complexity scoring", icon: <AutoAwesomeIcon />, color: "#8b5cf6" },
    { feature: "Symbolic Execution & Taint Analysis", description: "Track user input through execution paths: identify taint sources (argv, stdin, recv), propagate through transformations, detect when tainted data reaches dangerous sinks (strcpy, system, eval)", icon: <AccountTreeIcon />, color: "#f59e0b" },
    { feature: "Natural Language Search", description: "Semantic search across decompiled code: 'Find authentication code', 'Show network functions', 'Where is the encryption key derived?' - AI understands intent, not just keywords", icon: <SearchIcon />, color: "#06b6d4" },
    { feature: "PoC Exploit Generation", description: "Generate working exploit code in Python/C with shellcode support. Includes prerequisites, usage instructions, expected outcomes, safety notes, and evasion techniques", icon: <CodeIcon />, color: "#ec4899" },
    { feature: "AI Chat", description: "Interactive Q&A about vulnerabilities, exploitation techniques, remediation strategies. Full context awareness of the analysis results", icon: <AutoAwesomeIcon />, color: "#a855f7" },
    { feature: "Attack Simulation Mode", description: "Step-by-step visualization of how an exploit works: register/memory state at each phase, attacker-controlled values highlighted, mitigation bypass analysis", icon: <BugReportIcon />, color: "#f43f5e" },
    { feature: "Emulation Analysis (Unicorn)", description: "Lightweight CPU emulation to detect runtime behaviors: anti-debug techniques, self-modifying code, unpacking routines, evasion detection", icon: <MemoryIcon />, color: "#14b8a6" },
    { feature: "ROP Gadget Finder", description: "Automatic discovery of Return-Oriented Programming gadgets for exploit development: pop/ret chains, stack pivots, syscall gadgets", icon: <BuildIcon />, color: "#f97316" },
    { feature: "Binary Diff", description: "Compare two binaries to identify patched vulnerabilities, added security features, or code changes between versions", icon: <SearchIcon />, color: "#6366f1" },
    { feature: "Report Export", description: "Generate comprehensive reports in Markdown, PDF, or DOCX format with executive summary, all findings, and remediation guidance", icon: <CodeIcon />, color: "#84cc16" },
    { feature: "Notes & Annotations", description: "Take notes linked to specific vulnerabilities, export analysis documentation, collaborate with team members", icon: <CodeIcon />, color: "#a78bfa" },
    { feature: "Entropy Analysis", description: "Detect packed/encrypted sections by analyzing byte distribution. High entropy (>7.0) indicates encryption or compression", icon: <StorageIcon />, color: "#0ea5e9" },
    { feature: "Legitimacy Detection", description: "Reduces false positives for known software: checks Authenticode signatures, version info, publisher names, security mitigations", icon: <CheckCircleIcon />, color: "#10b981" },
  ];

  const quickStartSteps = [
    {
      label: "Upload Your Binary",
      description: "Navigate to the Reverse Engineering Hub and select 'Binary Analysis'. Upload a PE (.exe, .dll) or ELF binary file. Maximum file size is 500MB.",
    },
    {
      label: "Run Unified Scan (11 Phases)",
      description: "Click 'Run Unified Scan' to start the comprehensive analysis. Watch real-time progress through 11 phases: Static Analysis → Ghidra Decompilation → AI Summaries → Pattern Scanning → CVE Lookup → Sensitive Data Discovery → AI Vulnerability Hunt → Unified Verification → Attack Surface Mapping → Emulation Analysis → Report Generation.",
    },
    {
      label: "Explore 4-Tab Results",
      description: "Review results in four AI-generated tabs: (1) What Does This Binary Do - purpose summary and capabilities, (2) Security Findings - vulnerabilities with CWE references and remediation, (3) Architecture Diagram - Mermaid visualization of binary structure, (4) Attack Surface Map - exploitable entry points and attack vectors.",
    },
    {
      label: "Deep Dive with AI Tools",
      description: "Use AI Decompiler Enhancement to make code readable, Natural Language Search to find specific functionality ('show authentication code'), and Symbolic Execution to trace tainted data paths from input to dangerous sinks.",
    },
    {
      label: "Generate PoC Exploits",
      description: "For confirmed vulnerabilities, generate working proof-of-concept exploits in Python or C. The AI provides complete code with usage instructions, prerequisites, and safety warnings.",
    },
    {
      label: "Simulate Attacks",
      description: "Use Attack Simulation Mode to visualize exploitation step-by-step. See register/memory state changes, understand mitigation bypass techniques, and identify detection opportunities.",
    },
    {
      label: "Export Report & Notes",
      description: "Generate comprehensive reports in Markdown, PDF, or DOCX format. Take notes linked to specific findings and export full documentation for your team.",
    },
  ];

  const pageContext = `This page is the VRAgent Binary Analysis Guide covering:
- PE and ELF file format analysis
- 11-phase Unified Binary Scan with real-time progress
- Agentic Malware Analysis with 6 AI agents (Orchestrator, Static, Dynamic, Behavioral, Unpacking, Evasion)
- Malware Detection Engine: YARA rules, packer detection, C2 beacons, persistence mechanisms
- Frida dynamic instrumentation with API hooking and runtime monitoring
- Agentic Binary Fuzzer with intelligent crash triage and exploit generation
- AI Vulnerability Hunter with multi-pass autonomous analysis
- Ghidra decompilation and AI code enhancement
- Pattern-based vulnerability scanning (80+ patterns)
- CVE lookup via OSV.dev and NVD
- Sensitive data discovery (40+ patterns)
- AI verification to eliminate false positives
- Symbolic execution and taint analysis
- Attack surface mapping and entry point detection
- PoC exploit generation in Python/C
- Attack simulation mode for exploitation visualization
- Emulation analysis with Unicorn engine
- Natural language code search
- ROP gadget finding and mitigation bypass suggestions
- Binary diff for patch analysis
- Report export in Markdown, PDF, DOCX formats
- Notes and annotation management
- Legitimacy detection for known software`;

  return (
    <LearnPageLayout pageTitle="Binary Analysis Guide" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
      <Container maxWidth="lg">
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 2, color: "#f97316", borderColor: "#f97316" }}
          />
          
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f97316", 0.1) }}>
              <MemoryIcon sx={{ fontSize: 48, color: "#f97316" }} />
            </Box>
            <Box>
              <Typography variant="h3" sx={{ fontWeight: 800, color: "white" }}>
                Binary Analysis Guide
              </Typography>
              <Typography variant="h6" sx={{ color: "grey.400" }}>
                PE/ELF Analysis & Vulnerability Hunting for Beginners
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
            <Alert severity="info" sx={{ bgcolor: alpha("#3b82f6", 0.1), flex: 1 }}>
              <Typography variant="body2">
                <strong>New to binary analysis?</strong> This guide will teach you the fundamentals of analyzing executables,
                finding vulnerabilities, and using VRAgent's AI-powered tools to accelerate your workflow.
              </Typography>
            </Alert>
            <Button
              variant="contained"
              size="large"
              startIcon={<MemoryIcon />}
              onClick={() => navigate("/reverse")}
              sx={{ bgcolor: "#f97316", "&:hover": { bgcolor: "#ea580c" }, alignSelf: "center", whiteSpace: "nowrap" }}
            >
              Launch Binary Analyzer
            </Button>
          </Box>
        </Box>

        {/* Tabs */}
        <Paper sx={{ bgcolor: "#111118", borderRadius: 3, mb: 3 }}>
          <Tabs
            value={tabValue}
            onChange={handleTabChange}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: 1,
              borderColor: "divider",
              "& .MuiTab-root": { color: "grey.400", fontWeight: 600 },
              "& .Mui-selected": { color: "#f97316" },
              "& .MuiTabs-indicator": { bgcolor: "#f97316" },
            }}
          >
            <Tab icon={<SchoolIcon />} label="Getting Started" />
            <Tab icon={<MemoryIcon />} label="Binary Formats" />
            <Tab icon={<SearchIcon />} label="What to Look For" />
            <Tab icon={<BugReportIcon />} label="Vulnerability Types" />
            <Tab icon={<BuildIcon />} label="VRAgent Tools" />
            <Tab icon={<TipsAndUpdatesIcon />} label="Tips & Tricks" />
          </Tabs>
        </Paper>

        {/* Tab 0: Getting Started */}
        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🎯 What is Binary Analysis?
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Binary analysis is the process of examining compiled executable files to understand what they do,
                  find security vulnerabilities, and identify malicious behavior. Unlike source code review, you're
                  working with machine code that has been compiled from the original source, requiring specialized
                  tools and techniques to understand the program's behavior.
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  VRAgent combines traditional reverse engineering tools (Ghidra decompilation, Capstone disassembly, 
                  Unicorn emulation) with AI-powered analysis (vulnerability hunting, code enhancement, semantic search) 
                  to provide comprehensive binary security assessment in a single unified workflow.
                </Typography>
                <Grid container spacing={2} sx={{ mt: 2 }}>
                  {[
                    { title: "Security Research", desc: "Find zero-days in closed-source software", icon: "🔍" },
                    { title: "Malware Analysis", desc: "Understand malware behavior and capabilities", icon: "🦠" },
                    { title: "Vulnerability Assessment", desc: "Test applications before deployment", icon: "🛡️" },
                    { title: "CTF Competitions", desc: "Solve reverse engineering challenges", icon: "🏆" },
                    { title: "Patch Analysis", desc: "Understand what security patches fix", icon: "🔧" },
                    { title: "Compliance Auditing", desc: "Verify third-party software security", icon: "📋" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={4} lg={2} key={item.title}>
                      <Card sx={{ bgcolor: alpha("#f97316", 0.05), border: "1px solid rgba(249, 115, 22, 0.2)", height: "100%" }}>
                        <CardContent sx={{ textAlign: "center", p: 1.5 }}>
                          <Typography sx={{ fontSize: 28, mb: 0.5 }}>{item.icon}</Typography>
                          <Typography sx={{ color: "white", fontWeight: 600, fontSize: "0.85rem", mb: 0.25 }}>{item.title}</Typography>
                          <Typography variant="caption" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#f97316", mb: 3, fontWeight: 700 }}>
                  🚀 Quick Start with VRAgent
                </Typography>
                <Stepper orientation="vertical" sx={{ 
                  "& .MuiStepLabel-label": { color: "grey.300" },
                  "& .MuiStepLabel-label.Mui-active": { color: "#f97316" },
                  "& .MuiStepIcon-root": { color: "grey.700" },
                  "& .MuiStepIcon-root.Mui-active": { color: "#f97316" },
                  "& .MuiStepIcon-root.Mui-completed": { color: "#22c55e" },
                }}>
                  {quickStartSteps.map((step, index) => (
                    <Step key={step.label} active expanded>
                      <StepLabel>
                        <Typography sx={{ color: "white", fontWeight: 600 }}>{step.label}</Typography>
                      </StepLabel>
                      <StepContent>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>{step.description}</Typography>
                      </StepContent>
                    </Step>
                  ))}
                </Stepper>

                <Box sx={{ mt: 3, textAlign: "center" }}>
                  <Button
                    variant="contained"
                    size="large"
                    startIcon={<PlayArrowIcon />}
                    onClick={() => navigate("/reverse")}
                    sx={{ bgcolor: "#f97316", "&:hover": { bgcolor: "#ea580c" }, px: 4, py: 1.5 }}
                  >
                    Launch Binary Analyzer Now
                  </Button>
                </Box>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  ⚡ 11-Phase Unified Scan Pipeline
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  The Unified Binary Scan runs 11 analysis phases with real-time streaming progress. Each phase builds on previous results for comprehensive coverage:
                </Typography>
                <Grid container spacing={1}>
                  {[
                    { phase: "1", name: "Static Analysis", desc: "Extract metadata, strings, imports, exports, secrets", color: "#22c55e" },
                    { phase: "2", name: "Ghidra Decompilation", desc: "Headless decompiler exports up to 5000 functions", color: "#3b82f6" },
                    { phase: "3", name: "AI Function Summaries", desc: "Gemini summarizes decompiled functions", color: "#8b5cf6" },
                    { phase: "4", name: "AI Security Summary", desc: "Overall security assessment and purpose analysis", color: "#a855f7" },
                    { phase: "5", name: "Pattern Vulnerability Scan", desc: "80+ vulnerability patterns (CWE-classified)", color: "#f59e0b" },
                    { phase: "6", name: "CVE Lookup", desc: "Query OSV.dev and NVD for library CVEs", color: "#06b6d4" },
                    { phase: "7", name: "Sensitive Data Discovery", desc: "40+ patterns for secrets, credentials, API keys", color: "#ec4899" },
                    { phase: "8", name: "AI Vulnerability Hunt", desc: "Multi-pass autonomous deep analysis", color: "#ef4444" },
                    { phase: "9", name: "AI Verification", desc: "Eliminate false positives, detect attack chains", color: "#14b8a6" },
                    { phase: "10", name: "Attack Surface Mapping", desc: "Entry points, attack vectors, risk assessment", color: "#f43f5e" },
                    { phase: "11", name: "Report Generation", desc: "4 AI reports: purpose, findings, architecture, attack surface", color: "#84cc16" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={4} lg={3} key={item.phase}>
                      <Box sx={{ 
                        p: 1.5, 
                        bgcolor: alpha(item.color, 0.1), 
                        borderRadius: 2, 
                        border: `1px solid ${alpha(item.color, 0.3)}`,
                        height: "100%"
                      }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                          <Chip 
                            label={item.phase} 
                            size="small" 
                            sx={{ 
                              bgcolor: item.color, 
                              color: "white", 
                              fontWeight: 700, 
                              minWidth: 28, 
                              height: 22 
                            }} 
                          />
                          <Typography sx={{ color: item.color, fontWeight: 700, fontSize: "0.85rem" }}>{item.name}</Typography>
                        </Box>
                        <Typography variant="caption" sx={{ color: "grey.500", lineHeight: 1.3 }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
                <Alert severity="info" sx={{ mt: 2, bgcolor: alpha("#3b82f6", 0.1) }}>
                  <Typography variant="body2">
                    <strong>Time Estimates:</strong> Unified Scan provides real-time progress with elapsed time and estimated remaining time. 
                    Typical scan: 2-5 minutes depending on binary size and complexity.
                  </Typography>
                </Alert>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 1: Binary Formats */}
        <TabPanel value={tabValue} index={1}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  📦 Common Binary Formats
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Format</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Operating System</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Extensions</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {binaryFormats.map((row) => (
                        <TableRow key={row.format}>
                          <TableCell sx={{ color: "white", fontWeight: 600 }}>{row.format}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.os}</TableCell>
                          <TableCell><Chip label={row.ext} size="small" sx={{ bgcolor: alpha("#f97316", 0.2), color: "#f97316" }} /></TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.description}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🪟 PE File Structure (Windows)
                </Typography>
                <List dense>
                  {[
                    { section: "DOS Header", desc: "Legacy header with 'MZ' signature" },
                    { section: "PE Header", desc: "File characteristics, machine type" },
                    { section: "Optional Header", desc: "Entry point, image base, subsystem" },
                    { section: "Section Headers", desc: ".text, .data, .rdata, .rsrc definitions" },
                    { section: ".text", desc: "Executable code" },
                    { section: ".data", desc: "Initialized global variables" },
                    { section: ".rdata", desc: "Read-only data, imports, exports" },
                    { section: ".rsrc", desc: "Resources (icons, strings, dialogs)" },
                  ].map((item) => (
                    <ListItem key={item.section} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        <StorageIcon sx={{ color: "#f97316", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Typography sx={{ color: "#f97316", fontFamily: "monospace", fontSize: "0.85rem" }}>{item.section}</Typography>}
                        secondary={<Typography sx={{ color: "grey.500", fontSize: "0.75rem" }}>{item.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🐧 ELF File Structure (Linux)
                </Typography>
                <List dense>
                  {[
                    { section: "ELF Header", desc: "Magic bytes (0x7F ELF), architecture, type" },
                    { section: "Program Headers", desc: "Segments for runtime loading" },
                    { section: "Section Headers", desc: "Sections for linking and debugging" },
                    { section: ".text", desc: "Executable code" },
                    { section: ".rodata", desc: "Read-only data (strings, constants)" },
                    { section: ".data", desc: "Initialized global variables" },
                    { section: ".bss", desc: "Uninitialized data" },
                    { section: ".symtab", desc: "Symbol table (if not stripped)" },
                    { section: ".dynsym", desc: "Dynamic symbols for shared libs" },
                  ].map((item) => (
                    <ListItem key={item.section} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        <StorageIcon sx={{ color: "#f97316", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Typography sx={{ color: "#f97316", fontFamily: "monospace", fontSize: "0.85rem" }}>{item.section}</Typography>}
                        secondary={<Typography sx={{ color: "grey.500", fontSize: "0.75rem" }}>{item.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <CodeBlock
                title="Quick Binary Inspection Commands"
                language="bash"
                code={`# Check file type
file suspicious.exe
file program

# PE analysis (Windows)
# VRAgent handles this automatically!

# ELF analysis (Linux)
readelf -h program          # ELF header
readelf -S program          # Sections
readelf -s program          # Symbols
objdump -d program          # Disassembly

# Extract strings
strings -n 8 binary         # Strings >= 8 chars
strings -e l binary         # Unicode (UTF-16LE)`}
              />
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 2: What to Look For */}
        <TabPanel value={tabValue} index={2}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🔍 Suspicious Import Functions
                </Typography>
                <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha("#f59e0b", 0.1) }}>
                  These imports don't always indicate malware, but they warrant closer inspection. Legitimate software uses them too!
                </Alert>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Category</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Functions</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Risk</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {suspiciousImports.map((row) => (
                        <TableRow key={row.category}>
                          <TableCell sx={{ color: "white", fontWeight: 600 }}>{row.category}</TableCell>
                          <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.8rem" }}>{row.functions}</TableCell>
                          <TableCell>
                            <Chip 
                              label={row.risk} 
                              size="small" 
                              sx={{ 
                                bgcolor: row.risk === "Critical" ? alpha("#ef4444", 0.2) : 
                                         row.risk === "High" ? alpha("#f97316", 0.2) : 
                                         row.risk === "Medium" ? alpha("#eab308", 0.2) : alpha("#22c55e", 0.2),
                                color: row.risk === "Critical" ? "#ef4444" : 
                                       row.risk === "High" ? "#f97316" : 
                                       row.risk === "Medium" ? "#eab308" : "#22c55e"
                              }} 
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🔤 Interesting Strings to Find
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                  VRAgent's Sensitive Data Discovery scans for 40+ patterns automatically. Key categories:
                </Typography>
                <List dense>
                  {[
                    { pattern: "http://, https://", desc: "URLs - C2 servers, update checks, data exfiltration" },
                    { pattern: "password, passwd, pwd, secret", desc: "Hardcoded credentials and secrets" },
                    { pattern: "api_key, apikey, bearer, token", desc: "Embedded API keys and auth tokens" },
                    { pattern: "AWS_ACCESS, AZURE_, GCP_", desc: "Cloud provider credentials" },
                    { pattern: ".exe, .dll, .bat, .ps1, .vbs", desc: "Dropped/downloaded files" },
                    { pattern: "cmd.exe, powershell, /bin/sh", desc: "Command execution indicators" },
                    { pattern: "HKEY_, RegOpenKey, RegSetValue", desc: "Registry persistence/modifications" },
                    { pattern: "SELECT, INSERT, DROP, UNION", desc: "SQL queries (potential injection)" },
                    { pattern: "BEGIN RSA, PRIVATE KEY, -----", desc: "Embedded cryptographic keys" },
                    { pattern: "/etc/passwd, /etc/shadow", desc: "Linux credential file access" },
                    { pattern: "\\\\\\\\, \\\\PIPE\\\\, SMB", desc: "Network share and SMB activity" },
                    { pattern: "base64, rot13, xor", desc: "Encoding/obfuscation indicators" },
                  ].map((item) => (
                    <ListItem key={item.pattern} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        <SearchIcon sx={{ color: "#f97316", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Typography sx={{ color: "#f97316", fontFamily: "monospace", fontSize: "0.85rem" }}>{item.pattern}</Typography>}
                        secondary={<Typography sx={{ color: "grey.500", fontSize: "0.75rem" }}>{item.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🚩 Red Flags in Binaries
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                  VRAgent's Entropy Analysis and Obfuscation Detection automatically identify these patterns:
                </Typography>
                <List dense>
                  {[
                    { flag: "High entropy sections (>7.0)", desc: "Packed, encrypted, or compressed code" },
                    { flag: "Small .text, large .data/.rsrc", desc: "Code unpacked at runtime from data" },
                    { flag: "No or few imports", desc: "Dynamic API resolution or heavy packing" },
                    { flag: "VirtualProtect on .text", desc: "Self-modifying code, runtime decryption" },
                    { flag: "Anti-debug API calls", desc: "IsDebuggerPresent, NtQueryInformationProcess, timing checks" },
                    { flag: "Anti-VM detection", desc: "CPUID checks, VM artifacts, hypervisor detection" },
                    { flag: "Obfuscated strings", desc: "XOR'd, base64, or stack-constructed strings" },
                    { flag: "Unusual section names", desc: "UPX0, .enigma, .vmp, .themida (packer signatures)" },
                    { flag: "Missing Rich header (PE)", desc: "Stripped or tampered compilation metadata" },
                    { flag: "TLS callbacks present", desc: "Code execution before main() - common in malware" },
                    { flag: "Overlay data present", desc: "Data appended after PE - often encrypted payloads" },
                    { flag: "Process hollowing APIs", desc: "NtUnmapViewOfSection, ZwWriteVirtualMemory" },
                  ].map((item) => (
                    <ListItem key={item.flag} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        <WarningIcon sx={{ color: "#ef4444", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Typography sx={{ color: "#ef4444", fontSize: "0.85rem" }}>{item.flag}</Typography>}
                        secondary={<Typography sx={{ color: "grey.500", fontSize: "0.75rem" }}>{item.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 3: Vulnerability Types */}
        <TabPanel value={tabValue} index={3}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🐛 Common Binary Vulnerabilities
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  VRAgent's AI Vulnerability Hunter automatically detects these issues and provides detailed remediation guidance.
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Vulnerability</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Description</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>What to Look For</TableCell>
                        <TableCell sx={{ color: "#f97316", fontWeight: 700 }}>Severity</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {vulnCategories.map((row) => (
                        <TableRow key={row.type}>
                          <TableCell sx={{ color: "white", fontWeight: 600 }}>{row.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.description}</TableCell>
                          <TableCell sx={{ color: "grey.500", fontFamily: "monospace", fontSize: "0.8rem" }}>{row.indicators}</TableCell>
                          <TableCell>
                            <Chip 
                              label={row.severity} 
                              size="small" 
                              sx={{ 
                                bgcolor: row.severity === "Critical" ? alpha("#ef4444", 0.2) : alpha("#f97316", 0.2),
                                color: row.severity === "Critical" ? "#ef4444" : "#f97316"
                              }} 
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Accordion sx={{ bgcolor: "#111118", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#f97316" }} />}>
                  <Typography sx={{ color: "#f97316", fontWeight: 700 }}>📚 Buffer Overflow Deep Dive</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                    Buffer overflows occur when a program writes data beyond the allocated buffer size, potentially overwriting adjacent memory including return addresses.
                  </Typography>
                  <CodeBlock
                    title="Vulnerable C Code Example"
                    language="c"
                    code={`void vulnerable_function(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // No bounds checking!
    // If user_input > 64 bytes, overflow occurs
}

// Safe alternative
void safe_function(char *user_input) {
    char buffer[64];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';  // Ensure null termination
}`}
                  />
                  <Alert severity="info" sx={{ mt: 2, bgcolor: alpha("#3b82f6", 0.1) }}>
                    <Typography variant="body2">
                      <strong>VRAgent Detection:</strong> The AI Vulnerability Hunter identifies these patterns and shows you the exact location,
                      provides a CVSS score, and generates remediation recommendations.
                    </Typography>
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: "#111118", "&:before": { display: "none" }, mt: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#f97316" }} />}>
                  <Typography sx={{ color: "#f97316", fontWeight: 700 }}>📚 Format String Vulnerability Deep Dive</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                    Format string bugs allow attackers to read or write arbitrary memory by injecting format specifiers like %s, %x, %n into user-controlled strings.
                  </Typography>
                  <CodeBlock
                    title="Vulnerable vs Safe Printf"
                    language="c"
                    code={`// VULNERABLE - user controls format string
char *user_input = "%x %x %x %x";
printf(user_input);  // Leaks stack memory!

// Even worse - write arbitrary memory
char *evil = "%n";  // Writes to memory!
printf(evil);

// SAFE - format string is fixed
printf("%s", user_input);  // User input is just data`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: "#111118", "&:before": { display: "none" }, mt: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#f97316" }} />}>
                  <Typography sx={{ color: "#f97316", fontWeight: 700 }}>📚 Use-After-Free Deep Dive</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                    Use-after-free occurs when memory is accessed after being freed. If an attacker can control the freed memory contents, they may achieve code execution.
                  </Typography>
                  <CodeBlock
                    title="Use-After-Free Example"
                    language="c"
                    code={`struct Data {
    void (*callback)(void);
    char buffer[100];
};

struct Data *data = malloc(sizeof(struct Data));
data->callback = safe_function;

free(data);  // Memory freed

// ... later, if attacker allocates same memory ...
data->callback();  // Calls attacker-controlled function!

// FIX: Set pointer to NULL after free
free(data);
data = NULL;`}
                  />
                </AccordionDetails>
              </Accordion>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 4: VRAgent Tools */}
        <TabPanel value={tabValue} index={4}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3, fontWeight: 700 }}>
                🛠️ VRAgent Binary Analysis Features
              </Typography>
              <Grid container spacing={2}>
                {vrAgentFeatures.map((feature) => (
                  <Grid item xs={12} sm={6} md={3} key={feature.feature}>
                    <Card sx={{ bgcolor: "#111118", height: "100%", border: `1px solid ${alpha(feature.color, 0.3)}`, "&:hover": { borderColor: feature.color } }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                          <Typography sx={{ color: "white", fontWeight: 700, fontSize: "0.9rem" }}>{feature.feature}</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{feature.description}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  📊 Unified Results Interface (4 AI-Generated Tabs)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  After the 11-phase unified scan completes, VRAgent presents results in an intuitive 4-tab interface with AI-generated reports:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { tab: "1. What Does This Binary Do?", desc: "AI-generated comprehensive summary: binary purpose, detected capabilities (network, crypto, file operations), functionality breakdown, suspicious behaviors with severity ratings, data handling analysis, and confidence score", color: "#22c55e", icon: "📄" },
                    { tab: "2. Security Findings", desc: "All verified vulnerabilities from pattern scan, CVE lookup, sensitive data scan, and AI vulnerability hunt. Each finding includes: severity, CWE ID, CVSS estimate, function location, technical details, proof-of-concept hints, and remediation guidance", color: "#ef4444", icon: "🔒" },
                    { tab: "3. Architecture Diagram", desc: "Auto-generated Mermaid diagram showing: binary structure, component relationships, function call hierarchy, data flow paths, library dependencies, and module interactions", color: "#3b82f6", icon: "🏗️" },
                    { tab: "4. Attack Surface Map", desc: "Visual attack tree showing: all entry points (main, exported functions, network handlers), attack vectors with exploitation difficulty ratings, paths to dangerous sinks, and prioritized targets for testing", color: "#8b5cf6", icon: "🎯" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} key={item.tab}>
                      <Box sx={{ p: 2, bgcolor: alpha(item.color, 0.1), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.3)}`, height: "100%" }}>
                        <Typography sx={{ color: item.color, fontWeight: 700, mb: 0.5 }}>{item.icon} {item.tab}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  ✨ AI Decompiler Enhancement - How It Works
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  VRAgent's AI takes raw disassembly and transforms it into readable, annotated code:
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <CodeBlock
                      title="Before: Raw Disassembly"
                      language="asm"
                      code={`sub_401000:
  push    ebp
  mov     ebp, esp
  sub     esp, 0x40
  mov     eax, [ebp+8]
  push    eax
  lea     ecx, [ebp-0x40]
  push    ecx
  call    strcpy
  add     esp, 8
  leave
  ret`}
                    />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <CodeBlock
                      title="After: AI Enhanced"
                      language="c"
                      code={`// FUNCTION: copy_user_input
// PURPOSE: Copies input string to local buffer
// ⚠️ VULNERABILITY: Buffer overflow - no bounds check
void copy_user_input(char *input) {
    char local_buffer[64];  // Stack buffer
    
    // DANGEROUS: strcpy has no length limit
    // Attacker can overflow with >64 bytes
    strcpy(local_buffer, input);
    
    // FIX: Use strncpy(local_buffer, input, 63)
}`}
                    />
                  </Grid>
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  🎯 Symbolic Execution - Understanding Data Flow
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Symbolic execution tracks how user input flows through the program to identify exploitable paths:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { step: "1. Source Identification", desc: "Find where user input enters (read, recv, argv, getenv, fgets, scanf)", color: "#22c55e" },
                    { step: "2. Taint Propagation", desc: "Track how tainted data spreads through assignments, function calls, and operations", color: "#3b82f6" },
                    { step: "3. Path Constraints", desc: "Record conditions needed to reach each code path (if argc >= 2, if len > 256)", color: "#8b5cf6" },
                    { step: "4. Sink Detection", desc: "Alert when tainted data reaches dangerous sinks (strcpy, system, eval, SQL queries)", color: "#ef4444" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={3} key={item.step}>
                      <Box sx={{ p: 2, bgcolor: alpha(item.color, 0.1), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.3)}` }}>
                        <Typography sx={{ color: item.color, fontWeight: 700, mb: 0.5 }}>{item.step}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                  🔥 AI Vulnerability Hunter - Multi-Pass Autonomous Analysis
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  The AI Vulnerability Hunter performs autonomous multi-pass analysis to find deep vulnerabilities that pattern matching misses:
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, border: "1px solid rgba(34, 197, 94, 0.3)", height: "100%" }}>
                      <Typography sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>Pass 1: Reconnaissance</Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        • Ghidra decompilation of target functions
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        • Identify dangerous function calls (strcpy, system, etc.)
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        • Map attack surface and entry points
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, border: "1px solid rgba(59, 130, 246, 0.3)", height: "100%" }}>
                      <Typography sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>Pass 2: AI Triage</Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        • AI prioritizes highest-risk targets
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        • Considers context, data flow, and exploitability
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        • Selects functions for deep analysis
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.1), borderRadius: 2, border: "1px solid rgba(239, 68, 68, 0.3)", height: "100%" }}>
                      <Typography sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>Pass 3+: Deep Analysis</Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        • Thorough vulnerability analysis per target
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        • CWE classification and CVSS scoring
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        • PoC hints and exploitation steps
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
                <Box sx={{ mt: 2, p: 2, bgcolor: alpha("#f97316", 0.1), borderRadius: 2, border: "1px solid rgba(249, 115, 22, 0.3)" }}>
                  <Typography variant="body2" sx={{ color: "#f97316", fontWeight: 600 }}>
                    Vulnerability Categories Detected:
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    Buffer Overflow • Format String • Use-After-Free • Integer Overflow • Command Injection • Path Traversal • Race Condition • Crypto Weakness • Double Free • Null Pointer Dereference
                  </Typography>
                </Box>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f43f5e", mb: 2, fontWeight: 700 }}>
                  ⚔️ Attack Simulation Mode - Visualize Exploitation
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  For each vulnerability, see exactly how an attacker would exploit it with step-by-step register and memory state visualization:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { phase: "Setup", desc: "Attacker crafts malicious input (e.g., 264-byte buffer + target address)", color: "#6366f1" },
                    { phase: "Trigger", desc: "Vulnerable function called - buffer overflow begins", color: "#f59e0b" },
                    { phase: "Corruption", desc: "Memory state changes - return address overwritten", color: "#ef4444" },
                    { phase: "Control", desc: "Attacker gains control of RIP/EIP register", color: "#ec4899" },
                    { phase: "Payload", desc: "ROP chain or shellcode execution begins", color: "#8b5cf6" },
                    { phase: "Execution", desc: "Arbitrary code execution achieved", color: "#ef4444" },
                  ].map((item, idx) => (
                    <Grid item xs={6} sm={4} md={2} key={item.phase}>
                      <Box sx={{ p: 1.5, bgcolor: alpha(item.color, 0.1), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.3)}`, textAlign: "center" }}>
                        <Typography sx={{ color: item.color, fontWeight: 700, fontSize: "0.8rem" }}>Step {idx + 1}</Typography>
                        <Typography sx={{ color: "white", fontWeight: 600, fontSize: "0.85rem" }}>{item.phase}</Typography>
                        <Typography variant="caption" sx={{ color: "grey.500", display: "block" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
                <Alert severity="info" sx={{ mt: 2, bgcolor: alpha("#3b82f6", 0.1) }}>
                  <Typography variant="body2">
                    <strong>Attack Simulation also shows:</strong> Exploit primitives achieved, mitigation bypass techniques, detection opportunities, and real-world CVE examples of similar attacks.
                  </Typography>
                </Alert>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#ec4899", mb: 2, fontWeight: 700 }}>
                  💣 PoC Exploit Generation
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  For confirmed vulnerabilities, VRAgent generates working proof-of-concept exploits:
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ p: 2, bgcolor: alpha("#ec4899", 0.1), borderRadius: 2, border: "1px solid rgba(236, 72, 153, 0.3)" }}>
                      <Typography sx={{ color: "#ec4899", fontWeight: 700, mb: 1 }}>Exploit Options</Typography>
                      <List dense sx={{ py: 0 }}>
                        {[
                          "Language: Python (recommended), C, or raw shellcode",
                          "Platform: Linux, Windows, or both",
                          "Include shellcode generation for advanced exploits",
                          "Batch generation for multiple vulnerabilities",
                        ].map((item, i) => (
                          <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ color: "#ec4899", fontSize: 14 }} />
                            </ListItemIcon>
                            <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.400" }}>{item}</Typography>} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ p: 2, bgcolor: alpha("#ec4899", 0.1), borderRadius: 2, border: "1px solid rgba(236, 72, 153, 0.3)" }}>
                      <Typography sx={{ color: "#ec4899", fontWeight: 700, mb: 1 }}>Generated PoC Includes</Typography>
                      <List dense sx={{ py: 0 }}>
                        {[
                          "Fully commented working exploit code",
                          "Prerequisites and environment setup",
                          "Step-by-step usage instructions",
                          "Expected outcome and limitations",
                          "Safety warnings and legal notes",
                          "Evasion techniques (if applicable)",
                        ].map((item, i) => (
                          <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CodeIcon sx={{ color: "#ec4899", fontSize: 14 }} />
                            </ListItemIcon>
                            <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.400" }}>{item}</Typography>} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#14b8a6", mb: 2, fontWeight: 700 }}>
                  🔬 Emulation Analysis (Unicorn Engine)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Lightweight CPU emulation reveals runtime behaviors without executing the binary:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { capability: "Anti-Debug Detection", desc: "Identify IsDebuggerPresent, timing checks, int3 traps", icon: "🛡️" },
                    { capability: "Anti-VM Detection", desc: "Detect CPUID checks, VM artifacts, hypervisor detection", icon: "💻" },
                    { capability: "Unpacking Analysis", desc: "Trace self-modifying code and unpacking routines", icon: "📦" },
                    { capability: "String Recovery", desc: "Extract runtime-decrypted strings and configuration", icon: "🔤" },
                    { capability: "API Hook Points", desc: "Identify interesting functions for Frida hooking", icon: "🎣" },
                    { capability: "Malicious Patterns", desc: "Detect shellcode, process injection, persistence", icon: "⚠️" },
                  ].map((item) => (
                    <Grid item xs={6} md={4} key={item.capability}>
                      <Box sx={{ p: 2, bgcolor: alpha("#14b8a6", 0.1), borderRadius: 2, border: "1px solid rgba(20, 184, 166, 0.3)" }}>
                        <Typography sx={{ fontSize: "1.5rem", mb: 0.5 }}>{item.icon}</Typography>
                        <Typography sx={{ color: "#14b8a6", fontWeight: 700, fontSize: "0.9rem" }}>{item.capability}</Typography>
                        <Typography variant="caption" sx={{ color: "grey.500" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Divider sx={{ my: 2, borderColor: "grey.800" }} />

            <Grid item xs={12}>
              <Box sx={{ textAlign: "center" }}>
                <Button
                  variant="contained"
                  size="large"
                  startIcon={<MemoryIcon />}
                  onClick={() => navigate("/reverse")}
                  sx={{ bgcolor: "#f97316", "&:hover": { bgcolor: "#ea580c" }, px: 4, py: 1.5 }}
                >
                  Launch Binary Analyzer
                </Button>
              </Box>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 5: Tips & Tricks */}
        <TabPanel value={tabValue} index={5}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  ✅ Best Practices
                </Typography>
                <List>
                  {[
                    "Always work in an isolated VM for unknown binaries",
                    "Run Unified Scan first for comprehensive automated analysis",
                    "Check entropy to detect packed/encrypted sections early",
                    "Use AI Verification to filter false positives before deep diving",
                    "For legitimate software, review legitimacy indicators to avoid noise",
                    "Use Natural Language Search instead of manual code browsing",
                    "Run Symbolic Execution to prove vulnerability reachability",
                    "Generate PoCs to validate findings before reporting",
                    "Use Attack Simulation to understand exploitation difficulty",
                    "Document findings with Notes - link notes to specific vulns",
                    "Export comprehensive reports for stakeholder communication",
                    "For packed binaries, run Emulation Analysis to trace unpacking",
                  ].map((tip, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{tip}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                  ⚠️ Common Mistakes to Avoid
                </Typography>
                <List>
                  {[
                    "Running untrusted binaries on your main machine",
                    "Skipping AI Verification - leads to chasing false positives",
                    "Ignoring packed/obfuscated sections - run Entropy Analysis first",
                    "Assuming all suspicious imports are malicious (check legitimacy)",
                    "Not checking for anti-debugging before dynamic analysis",
                    "Focusing only on main() - use Attack Surface Map to find all entry points",
                    "Ignoring error handling code (often contains vulnerabilities)",
                    "Reporting unverified findings without PoC validation",
                    "Not documenting your analysis workflow with Notes",
                    "Skipping Symbolic Execution for complex vulnerabilities",
                    "Trusting AI output blindly - always verify with manual review",
                    "Ignoring CVE lookup results for library vulnerabilities",
                  ].map((mistake, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <WarningIcon sx={{ color: "#ef4444", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{mistake}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2, fontWeight: 700 }}>
                  💡 Pro Tips for VRAgent
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { tip: "AI Chat Deep Dive", desc: "Ask 'What are the most critical vulnerabilities?' or 'How would an attacker exploit the buffer overflow in process_input?' for contextual AI analysis" },
                    { tip: "Natural Language Search", desc: "Search semantically: 'find authentication bypass', 'show encryption routines', 'where is user data parsed' - AI understands intent" },
                    { tip: "Combine Tools", desc: "Pattern Scan → AI Verification → Symbolic Trace → PoC Generation: verify findings are real, then prove exploitability" },
                    { tip: "Attack Simulation", desc: "Use Attack Simulation to visualize the complete exploitation chain before writing your own exploit" },
                    { tip: "Smart Rename", desc: "Use AI Smart Rename to automatically suggest meaningful function names based on behavior analysis" },
                    { tip: "Export Everything", desc: "Generate PDF/DOCX reports with executive summary, all findings, architecture diagrams, and remediation guidance" },
                    { tip: "Legitimacy Detection", desc: "For signed software, VRAgent auto-filters false positives using Authenticode, version info, and publisher data" },
                    { tip: "Emulation for Packed Binaries", desc: "Use Emulation Analysis to trace unpacking routines and extract decrypted strings/payloads" },
                    { tip: "Binary Diff", desc: "Compare two versions of a binary to identify security patches and understand what changed" },
                    { tip: "ROP Gadget Finder", desc: "For exploitation, use ROP Gadget Finder to discover useful gadgets for return-oriented programming chains" },
                    { tip: "Entropy Check First", desc: "Run Entropy Analysis to detect packed/encrypted sections before spending time on static analysis" },
                    { tip: "Take Notes", desc: "Use the built-in Notes feature to document findings - notes link to specific vulnerabilities for easy reference" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={4} key={item.tip}>
                      <Box sx={{ p: 2, bgcolor: alpha("#f97316", 0.05), borderRadius: 2, border: "1px solid rgba(249, 115, 22, 0.2)" }}>
                        <Typography sx={{ color: "#f97316", fontWeight: 700, mb: 0.5 }}>{item.tip}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                  📚 Additional Learning Resources
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "Practical Binary Analysis", url: "https://practicalbinaryanalysis.com/", desc: "Book on binary analysis fundamentals" },
                    { name: "Reverse Engineering 101", url: "https://malwareunicorn.org/workshops/re101.html", desc: "Free RE workshop by Malware Unicorn" },
                    { name: "CTF Time", url: "https://ctftime.org/", desc: "Practice with RE CTF challenges" },
                    { name: "Nightmare", url: "https://guyinatuxedo.github.io/", desc: "Free binary exploitation course" },
                  ].map((resource) => (
                    <Grid item xs={12} sm={6} md={3} key={resource.name}>
                      <Button
                        fullWidth
                        variant="outlined"
                        href={resource.url}
                        target="_blank"
                        sx={{ 
                          borderColor: "rgba(59, 130, 246, 0.5)", 
                          color: "#3b82f6",
                          textAlign: "left",
                          display: "block",
                          py: 1.5,
                          "&:hover": { borderColor: "#3b82f6", bgcolor: alpha("#3b82f6", 0.1) }
                        }}
                      >
                        <Typography sx={{ fontWeight: 600 }}>{resource.name}</Typography>
                        <Typography variant="caption" sx={{ color: "grey.400" }}>{resource.desc}</Typography>
                      </Button>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

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
    </Box>
    </LearnPageLayout>
  );
};

export default BinaryAnalysisGuidePage;
