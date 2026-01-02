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
    { type: "Buffer Overflow", description: "Writing beyond allocated memory bounds", indicators: "strcpy, sprintf, gets, strcat without bounds checking", severity: "Critical" },
    { type: "Format String", description: "Uncontrolled format specifiers in printf-like functions", indicators: "printf(user_input), sprintf without format", severity: "Critical" },
    { type: "Use-After-Free", description: "Accessing memory after it's been freed", indicators: "free() followed by pointer dereference", severity: "Critical" },
    { type: "Integer Overflow", description: "Arithmetic operations exceeding type limits", indicators: "malloc(n * size) without overflow check", severity: "High" },
    { type: "Command Injection", description: "Executing shell commands with user input", indicators: "system(), popen(), exec* with concatenated strings", severity: "Critical" },
    { type: "Hardcoded Credentials", description: "Embedded passwords, API keys, or secrets", indicators: "Readable strings: password=, api_key=, secret", severity: "High" },
  ];

  const vrAgentFeatures = [
    { feature: "Unified Binary Scan", description: "One-click comprehensive security analysis with real-time progress", icon: <PlayArrowIcon />, color: "#22c55e" },
    { feature: "4-Tab Results View", description: "AI summary, Security Findings, Architecture Diagram, and Attack Surface Map", icon: <VisibilityIcon />, color: "#3b82f6" },
    { feature: "AI Vulnerability Hunter", description: "AI-powered detection of memory corruption, injection, and logic flaws", icon: <BugReportIcon />, color: "#ef4444" },
    { feature: "AI Decompiler Enhancement", description: "Transform assembly into readable, annotated code", icon: <AutoAwesomeIcon />, color: "#8b5cf6" },
    { feature: "Symbolic Execution", description: "Track data flow, constraints, and reachability to dangerous sinks", icon: <AccountTreeIcon />, color: "#f59e0b" },
    { feature: "Natural Language Search", description: "Find code by describing what it does in plain English", icon: <SearchIcon />, color: "#06b6d4" },
    { feature: "PoC Generation", description: "Automatically generate proof-of-concept exploit code", icon: <CodeIcon />, color: "#ec4899" },
    { feature: "AI Chat", description: "Ask questions about the binary and get detailed explanations", icon: <AutoAwesomeIcon />, color: "#a855f7" },
  ];

  const quickStartSteps = [
    {
      label: "Upload Your Binary",
      description: "Navigate to the Reverse Engineering Hub and select 'Binary Analysis'. Upload a PE (.exe, .dll) or ELF binary file.",
    },
    {
      label: "Run Unified Scan",
      description: "Click 'Run Unified Scan' for comprehensive AI-powered security analysis with real-time progress tracking.",
    },
    {
      label: "Explore 4-Tab Results",
      description: "Review results in four tabs: What Does This Binary Do (AI summary), Security Findings, Architecture Diagram, and Attack Surface Map.",
    },
    {
      label: "Review Security Findings",
      description: "Check detected vulnerabilities sorted by severity. Each finding includes CWE references and AI-generated remediation guidance.",
    },
    {
      label: "Use AI Chat",
      description: "Ask questions about the binary using the AI Chat feature. Get explanations of specific functions or attack scenarios.",
    },
    {
      label: "Export Report",
      description: "Generate comprehensive reports in Markdown, PDF, or DOCX format with all findings and AI analysis.",
    },
  ];

  const pageContext = `This page is the VRAgent Binary Analysis Guide covering PE and ELF file formats, executable structure analysis, suspicious imports detection, buffer overflows, format string vulnerabilities, use-after-free bugs, integer overflows, AI-powered vulnerability discovery, and automated decompilation with vulnerability scoring.`;

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
                  working with machine code that has been compiled from the original source.
                </Typography>
                <Grid container spacing={2} sx={{ mt: 2 }}>
                  {[
                    { title: "Security Research", desc: "Find vulnerabilities in closed-source software", icon: "🔍" },
                    { title: "Malware Analysis", desc: "Understand how malware works and what it does", icon: "🦠" },
                    { title: "Vulnerability Assessment", desc: "Test applications before deployment", icon: "🛡️" },
                    { title: "CTF Competitions", desc: "Solve reverse engineering challenges", icon: "🏆" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={3} key={item.title}>
                      <Card sx={{ bgcolor: alpha("#f97316", 0.05), border: "1px solid rgba(249, 115, 22, 0.2)", height: "100%" }}>
                        <CardContent sx={{ textAlign: "center" }}>
                          <Typography sx={{ fontSize: 32, mb: 1 }}>{item.icon}</Typography>
                          <Typography sx={{ color: "white", fontWeight: 600, mb: 0.5 }}>{item.title}</Typography>
                          <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
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
                <List dense>
                  {[
                    { pattern: "http://, https://", desc: "URLs - C2 servers, update checks" },
                    { pattern: "password, passwd, pwd", desc: "Hardcoded credentials" },
                    { pattern: "api_key, apikey, secret", desc: "Embedded API keys" },
                    { pattern: ".exe, .dll, .bat, .ps1", desc: "Dropped files" },
                    { pattern: "cmd.exe, powershell", desc: "Command execution" },
                    { pattern: "HKEY_, Registry", desc: "Registry operations" },
                    { pattern: "SELECT, INSERT, DROP", desc: "SQL queries" },
                    { pattern: "BEGIN RSA, PRIVATE KEY", desc: "Embedded keys" },
                    { pattern: "/etc/passwd, /etc/shadow", desc: "Linux credential files" },
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
                <List dense>
                  {[
                    { flag: "High entropy sections", desc: "Packed or encrypted code (>7.0 entropy)" },
                    { flag: "Small .text, large .data", desc: "Code might be unpacked at runtime" },
                    { flag: "No imports", desc: "Dynamic resolution or packing" },
                    { flag: "Self-modifying code", desc: "VirtualProtect + write to .text" },
                    { flag: "Anti-debug checks", desc: "IsDebuggerPresent, timing checks" },
                    { flag: "Obfuscated strings", desc: "XOR'd or base64 encoded strings" },
                    { flag: "Unusual section names", desc: "UPX0, .enigma, .vmp (packers)" },
                    { flag: "Missing Rich header", desc: "Stripped or tampered PE" },
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
                  📊 Unified Results Interface (4 Tabs)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  After scanning, VRAgent presents results in an intuitive 4-tab interface:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { tab: "1. What Does This Binary Do?", desc: "AI-generated summary of the binary's purpose, capabilities, and behavior in plain English", color: "#22c55e", icon: "📄" },
                    { tab: "2. Security Findings", desc: "All detected vulnerabilities with severity ratings, CWE references, and remediation guidance", color: "#ef4444", icon: "🔒" },
                    { tab: "3. Architecture Diagram", desc: "Auto-generated Mermaid diagram showing binary structure and component relationships", color: "#3b82f6", icon: "🏗️" },
                    { tab: "4. Attack Surface Map", desc: "Visual attack tree showing all exploitable entry points and potential attack vectors", color: "#8b5cf6", icon: "🎯" },
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
                    { step: "1. Source Identification", desc: "Find where user input enters (read, recv, argv)", color: "#22c55e" },
                    { step: "2. Taint Propagation", desc: "Track how tainted data spreads through variables", color: "#3b82f6" },
                    { step: "3. Path Constraints", desc: "Record conditions needed to reach each code path", color: "#8b5cf6" },
                    { step: "4. Sink Detection", desc: "Identify dangerous functions reached by tainted data", color: "#ef4444" },
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
                    "Start with static analysis before running the binary",
                    "Use the AI Quick Analysis first for an overview",
                    "Check entropy to detect packed/encrypted sections",
                    "Look at strings before diving into disassembly",
                    "Use Natural Language Search to find specific functionality",
                    "Take notes using the built-in annotation feature",
                    "Export reports for documentation and sharing",
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
                    "Ignoring packed/obfuscated sections",
                    "Assuming all imports are malicious",
                    "Not checking for anti-debugging techniques",
                    "Skipping the strings analysis",
                    "Focusing only on main() - check all entry points",
                    "Ignoring error handling code (often vulnerable)",
                    "Not documenting your analysis process",
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
                    { tip: "Use AI Chat", desc: "Ask 'What does this function do?' or 'Is this function vulnerable?' for instant AI analysis" },
                    { tip: "Natural Language Search", desc: "Try queries like 'find authentication code' or 'show network functions'" },
                    { tip: "Combine Tools", desc: "Run Symbolic Execution after finding a vulnerability to prove exploitability" },
                    { tip: "Generate PoCs", desc: "Let AI create proof-of-concept code for vulnerabilities you find" },
                    { tip: "Export Everything", desc: "Generate PDF reports for clients or team documentation" },
                    { tip: "Use Hex View", desc: "Check raw bytes when AI analysis seems wrong - trust but verify" },
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
