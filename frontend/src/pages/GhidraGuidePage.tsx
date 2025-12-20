import React, { useState } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  Tabs,
  Tab,
  Alert,
  AlertTitle,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  alpha,
  useTheme,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import SpeedIcon from "@mui/icons-material/Speed";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import FunctionsIcon from "@mui/icons-material/Functions";
import SettingsIcon from "@mui/icons-material/Settings";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import LearnPageLayout from "../components/LearnPageLayout";

// TabPanel component
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

// Code block component with copy
interface CodeBlockProps {
  title?: string;
  children: string;
}

function CodeBlock({ title, children }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const theme = useTheme();

  const handleCopy = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        mt: 2,
        mb: 2,
        overflow: "hidden",
        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
      }}
    >
      {title && (
        <Box
          sx={{
            px: 2,
            py: 1,
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            borderBottom: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Typography variant="caption" fontWeight="bold" color="primary">
            {title}
          </Typography>
          <Tooltip title={copied ? "Copied!" : "Copy"}>
            <IconButton size="small" onClick={handleCopy}>
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      )}
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          overflow: "auto",
          bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#f8f9fa",
          fontSize: "0.85rem",
          fontFamily: "monospace",
          "& code": { fontFamily: "inherit" },
        }}
      >
        <code>{children}</code>
      </Box>
    </Paper>
  );
}

// Data arrays for expandable content
const ghidraWindows = [
  {
    name: "Listing View",
    shortcut: "L",
    description: "Main disassembly view showing assembly instructions with addresses, bytes, and comments",
  },
  {
    name: "Decompiler",
    shortcut: "Ctrl+E",
    description: "Converts assembly to pseudo-C code, making it easier to understand program logic",
  },
  {
    name: "Function Graph",
    shortcut: "Space (in Listing)",
    description: "Visual control flow graph showing basic blocks and their connections",
  },
  {
    name: "Symbol Tree",
    shortcut: "Ctrl+Shift+E",
    description: "Browse all functions, labels, classes, namespaces, and data types",
  },
  {
    name: "Data Type Manager",
    shortcut: "Ctrl+Shift+T",
    description: "Manage structs, enums, unions, and typedefs for better type analysis",
  },
  {
    name: "Bytes View",
    shortcut: "",
    description: "Raw hex dump of the binary with highlighting for selected regions",
  },
  {
    name: "Program Trees",
    shortcut: "",
    description: "View memory segments, sections, and organizational structure",
  },
];

const keyboardShortcuts = [
  { shortcut: "G", action: "Go to address/label" },
  { shortcut: "L", action: "Edit label/rename symbol" },
  { shortcut: "T", action: "Set data type" },
  { shortcut: ";", action: "Add comment (EOL)" },
  { shortcut: "Ctrl+;", action: "Add plate comment" },
  { shortcut: "D", action: "Define data at cursor" },
  { shortcut: "C", action: "Clear code/data definition" },
  { shortcut: "F", action: "Create function" },
  { shortcut: "X", action: "Show cross-references (XRefs)" },
  { shortcut: "N", action: "Next occurrence of selected text" },
  { shortcut: "Ctrl+Shift+F", action: "Search for strings" },
  { shortcut: "Ctrl+B", action: "Search for bytes" },
  { shortcut: "Alt+Left", action: "Go back in navigation history" },
  { shortcut: "Alt+Right", action: "Go forward in navigation history" },
];

const analysisFeatures = [
  {
    feature: "Auto Analysis",
    description: "Automatic disassembly, function detection, and type propagation",
    category: "Core",
  },
  {
    feature: "Decompilation",
    description: "High-quality C-like decompilation with variable recovery",
    category: "Core",
  },
  {
    feature: "Cross-References",
    description: "Track all references to/from any address, function, or data",
    category: "Navigation",
  },
  {
    feature: "Type Propagation",
    description: "Automatically propagate types through code analysis",
    category: "Analysis",
  },
  {
    feature: "Script Manager",
    description: "Java and Python scripting for automation and custom analysis",
    category: "Extensibility",
  },
  {
    feature: "Version Tracking",
    description: "Compare different versions of binaries to track changes",
    category: "Advanced",
  },
  {
    feature: "Collaborative Mode",
    description: "Multi-user analysis with Ghidra Server for team projects",
    category: "Advanced",
  },
  {
    feature: "PDB Support",
    description: "Load Windows debug symbols for better function/type names",
    category: "Symbols",
  },
];

const commonTasks = [
  {
    task: "Find main() or entry point",
    steps: ["Open Symbol Tree", "Look under 'Functions' for 'main' or 'entry'", "Or use Go To (G) and type 'main'"],
  },
  {
    task: "Rename a function",
    steps: ["Click on function name", "Press L (Label)", "Enter new meaningful name", "Press Enter"],
  },
  {
    task: "Add a comment",
    steps: ["Position cursor at instruction", "Press ; for end-of-line comment", "Or Ctrl+; for plate comment above"],
  },
  {
    task: "Follow a cross-reference",
    steps: ["Select function/variable", "Press X to see all XRefs", "Double-click to navigate"],
  },
  {
    task: "Define a structure",
    steps: ["Open Data Type Manager", "Right-click Archive → New → Structure", "Add fields with types and names"],
  },
  {
    task: "Search for strings",
    steps: ["Search → For Strings", "Set minimum length", "Filter results as needed"],
  },
];

const supportedProcessors = [
  { arch: "x86/x64", desc: "Intel/AMD desktop and server processors", common: true },
  { arch: "ARM/ARM64", desc: "Mobile devices, embedded systems, Apple Silicon", common: true },
  { arch: "MIPS", desc: "Networking equipment, older consoles, embedded", common: true },
  { arch: "PowerPC", desc: "Game consoles (Wii, Xbox 360), older Macs", common: false },
  { arch: "SPARC", desc: "Oracle/Sun servers and workstations", common: false },
  { arch: "AVR", desc: "Arduino and other microcontrollers", common: false },
  { arch: "68000", desc: "Classic Motorola processors, retro systems", common: false },
  { arch: "RISC-V", desc: "Open-source ISA, growing embedded use", common: false },
];

// Extended data arrays for detailed content
const analysisOptions = [
  { analyzer: "Aggressive Instruction Finder", desc: "Finds code that wasn't found through normal means", when: "Firmware, packed binaries" },
  { analyzer: "ASCII Strings", desc: "Finds and defines ASCII string data", when: "Always recommended" },
  { analyzer: "Create Address Tables", desc: "Searches for tables of addresses (vtables, etc.)", when: "C++ binaries, firmware" },
  { analyzer: "Data Reference", desc: "Creates data references from pointer tables", when: "Always recommended" },
  { analyzer: "Decompiler Parameter ID", desc: "Uses decompiler to identify function parameters", when: "After initial analysis" },
  { analyzer: "Demangler", desc: "Demangles C++ symbol names to readable form", when: "C++ binaries" },
  { analyzer: "Embedded Media", desc: "Finds embedded images, audio, etc.", when: "GUI applications" },
  { analyzer: "External Entry References", desc: "Creates refs to external entry points", when: "DLLs, shared libraries" },
  { analyzer: "Function Start Search", desc: "Looks for function prologues", when: "Stripped binaries" },
  { analyzer: "GCC Exception Handlers", desc: "Analyzes GCC exception handling structures", when: "Linux C++ binaries" },
  { analyzer: "Non-Returning Functions", desc: "Identifies functions that don't return (exit, abort)", when: "Always recommended" },
  { analyzer: "Stack", desc: "Analyzes stack frames and local variables", when: "Always recommended" },
  { analyzer: "Windows x86 PE Exception Handling", desc: "Analyzes SEH/VEH handlers", when: "Windows PE binaries" },
  { analyzer: "Windows x86 PE RTTI Analyzer", desc: "Recovers C++ RTTI type information", when: "Windows C++ binaries" },
];

const decompilerOptions = [
  { option: "Simplify predication", desc: "Simplifies conditional expressions" },
  { option: "Simplify register pairs", desc: "Combines register pairs into single variables" },
  { option: "Eliminate dead code", desc: "Removes code that doesn't affect output" },
  { option: "Max function size", desc: "Limit on decompiled function size (default 50MB)" },
  { option: "Analysis.Decompiler timeout", desc: "Timeout for decompilation (default 30s)" },
  { option: "Prototype evaluation", desc: "How to handle unknown function signatures" },
];

const dataTypeCategories = [
  { category: "BuiltIn", desc: "Primitive types (byte, word, dword, qword, float, etc.)", example: "dword, float, pointer" },
  { category: "Structures", desc: "User-defined composite types with named fields", example: "struct Person { char* name; int age; }" },
  { category: "Unions", desc: "Types where all fields share the same memory", example: "union { int i; float f; }" },
  { category: "Enums", desc: "Named integer constants", example: "enum Color { RED=0, GREEN=1, BLUE=2 }" },
  { category: "Typedefs", desc: "Aliases for existing types", example: "typedef unsigned long DWORD" },
  { category: "Function Definitions", desc: "Function pointer types with signatures", example: "int (*callback)(void*, int)" },
  { category: "Arrays", desc: "Fixed-size sequences of elements", example: "char[256], int[10]" },
  { category: "Pointers", desc: "References to other data types", example: "char*, DWORD*, struct Person*" },
];

const functionCallConventions = [
  { convention: "__cdecl", platform: "x86 Windows/Linux", desc: "Caller cleans stack, args right-to-left", registers: "EAX return" },
  { convention: "__stdcall", platform: "x86 Windows API", desc: "Callee cleans stack, args right-to-left", registers: "EAX return" },
  { convention: "__fastcall", platform: "x86", desc: "First 2 args in ECX/EDX, rest on stack", registers: "ECX, EDX, EAX return" },
  { convention: "__thiscall", platform: "x86 C++", desc: "Like cdecl but 'this' in ECX", registers: "ECX=this, EAX return" },
  { convention: "x64 Windows", platform: "x64 Windows", desc: "First 4 args in RCX,RDX,R8,R9", registers: "Shadow space required" },
  { convention: "System V AMD64", platform: "x64 Linux/Mac", desc: "First 6 args in RDI,RSI,RDX,RCX,R8,R9", registers: "Red zone (128 bytes)" },
  { convention: "ARM AAPCS", platform: "ARM 32-bit", desc: "First 4 args in R0-R3, rest on stack", registers: "R0 return, LR=return addr" },
  { convention: "ARM64", platform: "AArch64", desc: "First 8 args in X0-X7", registers: "X0 return, X30=LR" },
];

const patternRecognition = [
  { pattern: "Switch Table", desc: "Jump table for switch statements", indicators: "JMP [base + reg*4], table of addresses" },
  { pattern: "Virtual Function Table", desc: "C++ vtable for polymorphism", indicators: "Array of function pointers, RTTI nearby" },
  { pattern: "String XOR Decode", desc: "Obfuscated strings using XOR", indicators: "Loop with XOR, single key byte" },
  { pattern: "Stack Canary", desc: "Buffer overflow protection", indicators: "Check value against __stack_chk_fail" },
  { pattern: "PIC/PIE Code", desc: "Position-independent code", indicators: "GOT/PLT usage, RIP-relative addressing" },
  { pattern: "Tail Call", desc: "Optimized function call at return", indicators: "JMP instead of CALL+RET" },
  { pattern: "Loop Unrolling", desc: "Compiler optimization", indicators: "Repeated similar instructions" },
  { pattern: "Inline Function", desc: "Compiler-inlined code", indicators: "No CALL, duplicated code patterns" },
];

const scriptCategories = [
  { category: "Analysis", scripts: ["AnalyzeStackReferences", "CreateStructure", "FindPotentialDecompilerProblems"] },
  { category: "Data", scripts: ["ApplyDataArchive", "CreateArrayFromSelection", "DefineDataAt"] },
  { category: "Functions", scripts: ["FindFunctionsWithNoCallers", "FixupNoReturnFunctions", "SplitFunction"] },
  { category: "Memory", scripts: ["AddMemoryBlock", "MergeMemoryBlocks", "SplitMemoryBlock"] },
  { category: "Program", scripts: ["ComparePrograms", "DiffPrograms", "VersionTrackingDiff"] },
  { category: "Search", scripts: ["FindByteSequence", "FindInstructionPattern", "SearchForStringReferences"] },
  { category: "Selection", scripts: ["MakeSelection", "SelectByFlowFrom", "SelectByFlowTo"] },
  { category: "Headless", scripts: ["ExportCSV", "GenerateFunctionReport", "HeadlessAnalyzer"] },
];

const malwareAnalysisTips = [
  { tip: "Use a VM", desc: "Always analyze malware in an isolated virtual machine with snapshots" },
  { tip: "Check imports", desc: "Look at imported functions - networking, crypto, registry APIs are suspicious" },
  { tip: "Find C2 addresses", desc: "Search for IP addresses, URLs, and domain strings" },
  { tip: "Identify packing", desc: "High entropy sections, few imports, or known packer signatures indicate packing" },
  { tip: "Look for anti-analysis", desc: "IsDebuggerPresent, VM detection, timing checks" },
  { tip: "String decryption", desc: "Find XOR loops or crypto functions that decode strings at runtime" },
  { tip: "API hashing", desc: "Malware often resolves APIs by hash - look for hash constants" },
  { tip: "Persistence mechanisms", desc: "Registry keys, scheduled tasks, service creation" },
];

const ghidraExtensions = [
  { name: "ghidra-nsis", desc: "Support for NSIS installer scripts", category: "Loader" },
  { name: "ghidra-firmware-utils", desc: "Analysis tools for firmware (UEFI, etc.)", category: "Analysis" },
  { name: "GhiHorn", desc: "Binary analysis using SMT solvers", category: "Analysis" },
  { name: "ghidra-findcrypt", desc: "Identify cryptographic constants", category: "Analysis" },
  { name: "ret-sync", desc: "Sync Ghidra with debuggers (x64dbg, WinDbg)", category: "Integration" },
  { name: "ghidra-scripts", desc: "Community script collections", category: "Scripts" },
  { name: "Ghidra2Dwarf", desc: "Export Ghidra analysis to DWARF format", category: "Export" },
  { name: "ghidra-nodejs", desc: "Node.js analysis support", category: "Loader" },
];

const GhidraGuidePage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const navigate = useNavigate();
  const theme = useTheme();

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const pageContext = `Ghidra Reverse Engineering Guide - Complete NSA-developed reverse engineering tool reference. Covers: installation and project setup, code browser interface, disassembly and decompilation, function analysis and renaming, cross-references (XREFs), data types and structures, Python scripting (Ghidra API), Java scripting, headless analysis, memory mapping, symbol management, function graphs, patch diffing, debugging integration, keyboard shortcuts, and community extensions. Essential for malware analysis, vulnerability research, and binary reverse engineering.`;

  return (
    <LearnPageLayout pageTitle="Ghidra Reverse Engineering Guide" pageContext={pageContext}>
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <IconButton onClick={() => navigate("/learn")} sx={{ color: "primary.main" }}>
            <ArrowBackIcon />
          </IconButton>
          <MemoryIcon sx={{ fontSize: 40, color: "primary.main" }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Ghidra Reverse Engineering Guide
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              NSA's powerful open-source software reverse engineering framework
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Introduction Section */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 2 }}>
        <Typography variant="h5" gutterBottom color="primary" fontWeight="bold">
          What is Ghidra?
        </Typography>
        
        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>Ghidra</strong> (pronounced "GEE-dra") is a free, open-source software reverse engineering (SRE) tool 
          developed by the National Security Agency (NSA). Released to the public in 2019, Ghidra has quickly become 
          one of the most popular tools for analyzing compiled programs - competing directly with expensive commercial 
          tools like IDA Pro that can cost thousands of dollars.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>What does "reverse engineering" mean?</strong> When programmers write code, they use human-readable 
          languages like C, Python, or Java. This code is then <em>compiled</em> into machine code (binary) that computers 
          can execute. Reverse engineering is the process of taking that compiled binary and working backwards to understand 
          what it does - essentially trying to reconstruct the original logic and behavior of the program.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>Why would you need to do this?</strong> There are many legitimate reasons:
        </Typography>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { icon: <BugReportIcon />, title: "Malware Analysis", desc: "Understanding how viruses, ransomware, and other threats work to develop defenses" },
            { icon: <SecurityIcon />, title: "Vulnerability Research", desc: "Finding security bugs in software when source code isn't available" },
            { icon: <BuildIcon />, title: "Legacy Software", desc: "Maintaining or updating old programs where the original source code is lost" },
            { icon: <SchoolIcon />, title: "Learning", desc: "Understanding how compilers work and how high-level code becomes machine instructions" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.title}>
              <Card variant="outlined" sx={{ height: "100%" }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, color: "primary.main" }}>
                    {item.icon}
                    <Typography variant="subtitle2" fontWeight="bold">{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Alert severity="info" sx={{ mt: 2 }}>
          <AlertTitle>Ghidra vs IDA Pro</AlertTitle>
          Ghidra is often compared to IDA Pro, the industry standard for reverse engineering. While IDA Pro has 
          decades of refinement, Ghidra offers comparable features for free, has excellent decompilation, and 
          supports collaborative analysis. For most tasks, Ghidra is an excellent choice.
        </Alert>
      </Paper>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 2 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: "divider", px: 2 }}
        >
          <Tab icon={<PlayArrowIcon />} label="Getting Started" />
          <Tab icon={<AccountTreeIcon />} label="Interface" />
          <Tab icon={<SearchIcon />} label="Analysis" />
          <Tab icon={<CodeIcon />} label="Scripting" />
          <Tab icon={<LightbulbIcon />} label="Tips & Tricks" />
        </Tabs>

        {/* Tab 0: Getting Started */}
        <TabPanel value={tabValue} index={0}>
          <Typography variant="h5" gutterBottom>Getting Started with Ghidra</Typography>

          <Alert severity="success" sx={{ mb: 3 }}>
            <AlertTitle>Prerequisites</AlertTitle>
            Ghidra requires Java 17+ (JDK) to run. Download from adoptium.net or use your package manager.
          </Alert>

          <Typography variant="h6" gutterBottom>Installation</Typography>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Windows Installation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem><ListItemText primary="1. Install Java JDK 17+ from adoptium.net" secondary="Download the Windows x64 MSI installer for easiest setup" /></ListItem>
                <ListItem><ListItemText primary="2. Set JAVA_HOME environment variable" secondary="System Properties → Environment Variables → New System Variable" /></ListItem>
                <ListItem><ListItemText primary="3. Download Ghidra from ghidra-sre.org" secondary="Always download from the official NSA GitHub releases" /></ListItem>
                <ListItem><ListItemText primary="4. Extract ZIP to a permanent location" secondary="e.g., C:\\Tools\\ghidra_11.0_PUBLIC" /></ListItem>
                <ListItem><ListItemText primary="5. Run ghidraRun.bat to start" secondary="First run may prompt for JDK location" /></ListItem>
              </List>
              <CodeBlock title="PowerShell - Verify Java">{`# Check Java version
java -version

# Should show: openjdk version "17.x.x" or higher
# If not found, verify JAVA_HOME is set and in PATH`}</CodeBlock>
            </AccordionDetails>
          </Accordion>
          
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Linux Installation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Ubuntu/Debian">{`# Install Java 17
sudo apt update
sudo apt install openjdk-17-jdk

# Verify installation
java -version

# Download latest Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip

# Extract
unzip ghidra_11.0_PUBLIC_20231222.zip

# Run Ghidra
cd ghidra_11.0_PUBLIC
./ghidraRun`}</CodeBlock>
              <CodeBlock title="Fedora/RHEL/CentOS">{`# Install Java 17
sudo dnf install java-17-openjdk-devel

# Set JAVA_HOME (add to ~/.bashrc)
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk

# Download and extract Ghidra same as above
./ghidraRun`}</CodeBlock>
              <CodeBlock title="Arch Linux">{`# Install from AUR (includes Java)
yay -S ghidra

# Or install Java manually
sudo pacman -S jdk17-openjdk

# Then download Ghidra manually`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">macOS Installation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Using Homebrew">{`# Install Java 17
brew install openjdk@17

# Link Java
sudo ln -sfn /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-17.jdk

# Add to shell profile
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
export JAVA_HOME=$(/usr/libexec/java_home -v 17)

# Download Ghidra from github.com/NationalSecurityAgency/ghidra/releases
# Extract and run
./ghidraRun`}</CodeBlock>
              <Alert severity="warning" sx={{ mt: 2 }}>
                <AlertTitle>Apple Silicon (M1/M2/M3) Note</AlertTitle>
                Ghidra runs natively on Apple Silicon. For best performance, ensure you're using an ARM64 
                version of Java. Rosetta 2 emulation also works but may be slower.
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Creating Your First Project</Typography>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Project Setup Steps</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="1. File → New Project" 
                    secondary="Choose 'Non-Shared Project' for local work or 'Shared Project' for team collaboration" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="2. Select project directory and name" 
                    secondary="Projects store analysis data, so keep them organized by target or engagement" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="3. File → Import File (or drag and drop)" 
                    secondary="Select your binary (EXE, ELF, DLL, firmware, etc.)" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="4. Review the import dialog" 
                    secondary="Ghidra auto-detects format - verify language/compiler if known" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="5. Double-click the file to open in CodeBrowser" 
                    secondary="This is where the actual analysis happens" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary='6. Click "Yes" to Auto-Analyze' 
                    secondary="Let Ghidra perform initial analysis (can take seconds to minutes depending on size)" 
                  />
                </ListItem>
              </List>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Analysis Options Configuration</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                When Ghidra prompts for auto-analysis, you can customize which analyzers run. 
                Click "Analyze Options" to see the full list. Here are the key ones:
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Analyzer</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                      <TableCell><strong>Recommended When</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {analysisOptions.slice(0, 8).map((row) => (
                      <TableRow key={row.analyzer}>
                        <TableCell><Typography variant="body2" fontWeight="bold">{row.analyzer}</Typography></TableCell>
                        <TableCell><Typography variant="body2">{row.desc}</Typography></TableCell>
                        <TableCell><Chip label={row.when} size="small" variant="outlined" /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Loading Debug Symbols (PDB)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                If you have PDB files (Windows debug symbols), Ghidra can load them to provide function names, 
                types, and variable information. This dramatically improves analysis quality.
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="1. File → Load PDB File" secondary="Select the matching .pdb file" /></ListItem>
                <ListItem><ListItemText primary="2. Configure Symbol Server" secondary="Edit → Tool Options → Symbol Servers" /></ListItem>
                <ListItem><ListItemText primary="3. Microsoft Symbol Server" secondary="https://msdl.microsoft.com/download/symbols" /></ListItem>
              </List>
              <CodeBlock title="Symbol Server Path (Tool Options)">{`# Microsoft Symbol Server
srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols

# Local symbol cache
C:\\Symbols

# For Linux/Mac, use your home directory
srv*/home/user/.symbols*https://msdl.microsoft.com/download/symbols`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Supported File Formats</Typography>
          <Grid container spacing={2}>
            {[
              { format: "PE/COFF", desc: "Windows executables (.exe, .dll, .sys, .ocx)", icon: "🪟" },
              { format: "ELF", desc: "Linux/Unix executables and libraries (.so)", icon: "🐧" },
              { format: "Mach-O", desc: "macOS/iOS executables and frameworks", icon: "🍎" },
              { format: "DEX/APK", desc: "Android Dalvik bytecode and APK packages", icon: "🤖" },
              { format: "Raw Binary", desc: "Firmware, ROM dumps, bare metal code", icon: "💾" },
              { format: "Java Class", desc: "Java bytecode (.class, .jar files)", icon: "☕" },
              { format: "COFF", desc: "Object files from various compilers", icon: "📦" },
              { format: "Intel HEX", desc: "Firmware and microcontroller programs", icon: "🔧" },
              { format: "Motorola S-Record", desc: "Embedded system firmware files", icon: "📟" },
              { format: "PE .NET", desc: "C#/VB.NET managed executables", icon: "🔷" },
              { format: "WebAssembly", desc: "WASM binary modules", icon: "🌐" },
              { format: "MSI/CAB", desc: "Windows installer packages (via plugin)", icon: "📥" },
            ].map((item) => (
              <Grid item xs={6} sm={4} md={2} key={item.format}>
                <Card variant="outlined" sx={{ textAlign: "center", py: 2, height: "100%" }}>
                  <Typography variant="h4">{item.icon}</Typography>
                  <Typography variant="subtitle2" fontWeight="bold">{item.format}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>{item.desc}</Typography>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Understanding the Project Window</Typography>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Project Window Components</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {[
                  { name: "Active Project", desc: "Currently open project with all imported files" },
                  { name: "Tool Chest", desc: "Launch CodeBrowser or other analysis tools" },
                  { name: "File Icons", desc: "Green checkmark = analyzed, Red X = import failed" },
                  { name: "Right-Click Menu", desc: "Delete, rename, export, version history" },
                  { name: "Folders", desc: "Organize binaries within the project" },
                  { name: "Recent Projects", desc: "Quick access to previously opened projects" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={4} key={item.name}>
                    <Card variant="outlined">
                      <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
                        <Typography variant="subtitle2" fontWeight="bold" color="primary">{item.name}</Typography>
                        <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        </TabPanel>

        {/* Tab 1: Interface */}
        <TabPanel value={tabValue} index={1}>
          <Typography variant="h5" gutterBottom>Ghidra Interface Overview</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            The CodeBrowser is Ghidra's main analysis window. It contains multiple synchronized views 
            that update together as you navigate through the binary. Master the interface to analyze efficiently.
          </Alert>

          <Typography variant="h6" gutterBottom>Main Windows</Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Window</strong></TableCell>
                  <TableCell><strong>Shortcut</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ghidraWindows.map((row) => (
                  <TableRow key={row.name}>
                    <TableCell>
                      <Typography fontWeight="bold" color="primary">{row.name}</Typography>
                    </TableCell>
                    <TableCell>
                      {row.shortcut && <Chip label={row.shortcut} size="small" variant="outlined" />}
                    </TableCell>
                    <TableCell>{row.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Understanding the Listing View</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Listing View is where you'll spend most of your time. It shows disassembled instructions 
                with addresses, bytes, mnemonics, and operands. Here's how to read it:
              </Typography>
              <CodeBlock title="Listing View Columns">{`Address    | Bytes      | Label      | Mnemonic | Operands            | Comment
-----------+------------+------------+----------+---------------------+------------------
00401000   | 55         |            | PUSH     | EBP                 |
00401001   | 8b ec      |            | MOV      | EBP,ESP             |
00401003   | 83 ec 08   |            | SUB      | ESP,0x8             |
00401006   | c7 45 fc   | main:      | MOV      | dword ptr [EBP-4],0 | local variable
           | 00 00 00 00|            |          |                     |

Color coding (default theme):
- Blue: References to other code locations
- Green: References to data
- Purple: Strings
- Orange: Immediates/constants
- Gray: Comments`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Understanding the Decompiler View</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Decompiler shows C-like pseudocode. Click in the Listing to sync, or vice versa. 
                Variables are automatically named (local_4, param_1) but can be renamed.
              </Typography>
              <CodeBlock title="Decompiler Features">{`// Hover over variables to see type info
// Right-click for context menu options:
// - Rename Variable (L)
// - Retype Variable (Ctrl+L)
// - Set Equate - name a constant
// - Find References
// - Edit Function Signature

// Example decompiled function:
int __cdecl check_password(char *input) {
    int result;
    char *expected = "secret123";
    
    result = strcmp(input, expected);  // Double-click to navigate
    if (result == 0) {
        return 1;  // Success
    }
    return 0;
}`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Symbol Tree Navigation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Symbol Tree organizes all symbols in the program hierarchically:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Imports" secondary="Functions called from external libraries (DLLs, .so files)" /></ListItem>
                <ListItem><ListItemText primary="Exports" secondary="Functions/data exposed to other modules" /></ListItem>
                <ListItem><ListItemText primary="Functions" secondary="All identified functions in the binary" /></ListItem>
                <ListItem><ListItemText primary="Labels" secondary="Named locations that aren't functions" /></ListItem>
                <ListItem><ListItemText primary="Classes" secondary="C++ classes (if RTTI or debug info available)" /></ListItem>
                <ListItem><ListItemText primary="Namespaces" secondary="C++ namespaces and scopes" /></ListItem>
              </List>
              <Alert severity="success" sx={{ mt: 2 }}>
                <strong>Pro Tip:</strong> Use the filter box at the top to quickly find functions. 
                Type partial names like "crypt" to find all crypto-related functions.
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Keyboard Shortcuts</Typography>
          <Typography paragraph color="text.secondary">
            Mastering keyboard shortcuts dramatically speeds up analysis. These are the essential ones:
          </Typography>
          <Grid container spacing={2}>
            {keyboardShortcuts.map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.shortcut}>
                <Card variant="outlined">
                  <CardContent sx={{ py: 1, "&:last-child": { pb: 1 } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Chip label={item.shortcut} color="primary" size="small" sx={{ fontFamily: "monospace", minWidth: 80 }} />
                      <Typography variant="body2">{item.action}</Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Additional Useful Shortcuts</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {[
                  { key: "Ctrl+Shift+E", action: "Open/focus Symbol Tree" },
                  { key: "Ctrl+E", action: "Open/focus Decompiler" },
                  { key: "Ctrl+D", action: "Add bookmark" },
                  { key: "Ctrl+G", action: "Go to program memory" },
                  { key: "P", action: "Make pointer at cursor" },
                  { key: "Y", action: "Define function signature" },
                  { key: "[", action: "Create array" },
                  { key: "Ctrl+L", action: "Retype variable (Decompiler)" },
                  { key: "M", action: "Add marker" },
                  { key: "Ctrl+Shift+G", action: "Script Manager" },
                  { key: "F2", action: "Create function at cursor" },
                  { key: "Delete", action: "Clear code/data" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={4} key={item.key}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Chip label={item.key} size="small" variant="outlined" sx={{ fontFamily: "monospace", minWidth: 100 }} />
                      <Typography variant="body2">{item.action}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Common Tasks</Typography>
          <Grid container spacing={2}>
            {commonTasks.map((item) => (
              <Grid item xs={12} md={6} key={item.task}>
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">{item.task}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {item.steps.map((step, idx) => (
                        <ListItem key={idx}>
                          <ListItemText primary={`${idx + 1}. ${step}`} />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Data Types & Structures</Typography>
          <Typography paragraph color="text.secondary">
            Understanding and defining data types is crucial for clean decompiler output.
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Category</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Example</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataTypeCategories.map((row) => (
                  <TableRow key={row.category}>
                    <TableCell><Typography fontWeight="bold" color="primary">{row.category}</Typography></TableCell>
                    <TableCell>{row.desc}</TableCell>
                    <TableCell><code style={{ fontSize: "0.85rem" }}>{row.example}</code></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Creating Custom Structures</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Custom structures dramatically improve code readability. Here's how to create them:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="1. Open Data Type Manager (Window → Data Type Manager)" /></ListItem>
                <ListItem><ListItemText primary="2. Right-click your program's archive → New → Structure" /></ListItem>
                <ListItem><ListItemText primary="3. Name the structure (e.g., 'NetworkPacket')" /></ListItem>
                <ListItem><ListItemText primary="4. Add fields with types and names" /></ListItem>
                <ListItem><ListItemText primary="5. Apply to data by selecting bytes and pressing T" /></ListItem>
              </List>
              <CodeBlock title="Example: Creating a File Header Structure">{`// Before: Raw bytes in decompiler
void process_file(byte *data) {
    if (*(uint *)data == 0x4d5a) {  // What is 0x4d5a?
        uint size = *(uint *)(data + 4);
        // ...
    }
}

// After: With custom structure applied
struct FileHeader {
    char magic[2];      // offset 0
    ushort reserved;    // offset 2  
    uint fileSize;      // offset 4
    uint flags;         // offset 8
    uint dataOffset;    // offset 12
};

void process_file(FileHeader *header) {
    if (header->magic[0] == 'M' && header->magic[1] == 'Z') {
        uint size = header->fileSize;  // Much clearer!
        // ...
    }
}`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Calling Conventions</Typography>
          <Typography paragraph color="text.secondary">
            Understanding calling conventions helps you interpret function parameters and return values correctly.
          </Typography>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Convention</strong></TableCell>
                  <TableCell><strong>Platform</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Key Registers</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {functionCallConventions.map((row) => (
                  <TableRow key={row.convention}>
                    <TableCell><Typography fontWeight="bold" fontFamily="monospace">{row.convention}</Typography></TableCell>
                    <TableCell><Chip label={row.platform} size="small" variant="outlined" /></TableCell>
                    <TableCell><Typography variant="body2">{row.desc}</Typography></TableCell>
                    <TableCell><Typography variant="caption" fontFamily="monospace">{row.registers}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        {/* Tab 2: Analysis */}
        <TabPanel value={tabValue} index={2}>
          <Typography variant="h5" gutterBottom>Analysis Features</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>Auto-Analysis</AlertTitle>
            When you first open a binary, Ghidra offers to run Auto-Analysis. This performs disassembly, 
            function detection, and type propagation automatically. You can always re-run specific analyzers 
            later from Analysis → Auto Analyze or Analysis → One Shot.
          </Alert>

          <Typography variant="h6" gutterBottom>Key Features</Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Feature</strong></TableCell>
                  <TableCell><strong>Category</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {analysisFeatures.map((row) => (
                  <TableRow key={row.feature}>
                    <TableCell>
                      <Typography fontWeight="bold">{row.feature}</Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={row.category} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>{row.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Complete Analyzer Reference</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Ghidra includes many analyzers for different purposes. Here's when to enable them:
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Analyzer</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                      <TableCell><strong>Use When</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {analysisOptions.map((row) => (
                      <TableRow key={row.analyzer}>
                        <TableCell><Typography variant="body2" fontWeight="bold">{row.analyzer}</Typography></TableCell>
                        <TableCell><Typography variant="body2">{row.desc}</Typography></TableCell>
                        <TableCell><Chip label={row.when} size="small" variant="outlined" /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Supported Processors</Typography>
          <Grid container spacing={2}>
            {supportedProcessors.map((proc) => (
              <Grid item xs={12} sm={6} md={3} key={proc.arch}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold">{proc.arch}</Typography>
                      {proc.common && <Chip label="Common" size="small" color="success" />}
                    </Box>
                    <Typography variant="body2" color="text.secondary">{proc.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>The Decompiler</Typography>
          <Typography paragraph>
            Ghidra's decompiler converts assembly code into readable C-like pseudocode. This is one of its 
            most powerful features, making it much easier to understand program logic without reading assembly.
          </Typography>
          <CodeBlock title="Example: Assembly vs Decompiled">{`; Original Assembly (x86)
push    ebp
mov     ebp, esp
sub     esp, 8
mov     dword ptr [ebp-4], 0
mov     dword ptr [ebp-8], 0Ah
mov     eax, [ebp-8]
add     eax, [ebp-4]
mov     esp, ebp
pop     ebp
ret

// Ghidra Decompiled Output
int example_function(void) {
    int local_4 = 0;
    int local_8 = 10;
    return local_8 + local_4;
}`}</CodeBlock>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Decompiler Options & Tuning</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Configure decompiler behavior in Edit → Tool Options → Decompiler:
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Option</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {decompilerOptions.map((row) => (
                      <TableRow key={row.option}>
                        <TableCell><Typography fontWeight="bold" fontFamily="monospace">{row.option}</Typography></TableCell>
                        <TableCell>{row.desc}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Pattern Recognition</Typography>
          <Typography paragraph color="text.secondary">
            Learning to recognize common patterns helps you understand code faster:
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Pattern</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Indicators</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {patternRecognition.map((row) => (
                  <TableRow key={row.pattern}>
                    <TableCell><Typography fontWeight="bold" color="primary">{row.pattern}</Typography></TableCell>
                    <TableCell>{row.desc}</TableCell>
                    <TableCell><Typography variant="body2" fontFamily="monospace">{row.indicators}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Identifying Virtual Function Tables (vtables)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="C++ vtable Structure">{`// A vtable is an array of function pointers
// Used by C++ for virtual method dispatch

// In memory, it looks like:
vtable_Base:
  .quad Base::method1     ; offset 0
  .quad Base::method2     ; offset 8
  .quad Base::method3     ; offset 16

// Object layout:
struct Base {
    void** __vfptr;       ; Pointer to vtable (offset 0)
    int member_a;         ; offset 8
    int member_b;         ; offset 12
};

// Virtual call pattern (x64):
mov     rax, [rcx]        ; Load vtable ptr from object
call    [rax+0x10]        ; Call vtable[2] (method3)

// To analyze:
// 1. Find arrays of function pointers (Search → Memory → Address Tables)
// 2. Enable RTTI analyzer for Windows C++
// 3. Use RecoverClassesFromRTTI script
// 4. Create struct for object layout`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">String Decryption Patterns</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Common XOR String Decryption">{`// Malware often encrypts strings to avoid detection
// Common patterns:

// Single-byte XOR (most common)
void decrypt_xor(char *str, int len, char key) {
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Rolling XOR (each byte uses different key)
void decrypt_rolling(char *str, int len) {
    char key = 0x41;
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
        key = (key + 1) & 0xFF;  // Or key ^= str[i]
    }
}

// What to look for:
// 1. Loop iterating over data
// 2. XOR instruction inside loop
// 3. Constant byte value used in XOR
// 4. Result used with string functions

// To decrypt manually:
// 1. Select encrypted bytes
// 2. Right-click → Copy Special → Byte String
// 3. XOR with key in Python/CyberChef
// 4. Add decrypted string as comment`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Cross-References (XRefs)</Typography>
          <Typography paragraph>
            Cross-references are essential for understanding code flow. Press X on any symbol to see all references:
          </Typography>
          <Grid container spacing={2}>
            {[
              { type: "Call", desc: "Function is called from this location", icon: "→" },
              { type: "Read", desc: "Data is read at this location", icon: "R" },
              { type: "Write", desc: "Data is written at this location", icon: "W" },
              { type: "Address", desc: "Address is taken (pointer)", icon: "&" },
              { type: "Jump", desc: "Code jumps to this location", icon: "J" },
              { type: "Offset", desc: "Used as offset calculation", icon: "+" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.type}>
                <Card variant="outlined">
                  <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Chip label={item.icon} size="small" color="primary" sx={{ fontFamily: "monospace" }} />
                      <Typography fontWeight="bold">{item.type}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Working with Function Graphs</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Function Graph (View → Function Graph or press Space in Listing) shows control flow visually:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Green edges" secondary="Conditional jump taken (true branch)" /></ListItem>
                <ListItem><ListItemText primary="Red edges" secondary="Conditional jump not taken (false branch)" /></ListItem>
                <ListItem><ListItemText primary="Blue edges" secondary="Unconditional jumps" /></ListItem>
                <ListItem><ListItemText primary="Purple blocks" secondary="Entry point" /></ListItem>
                <ListItem><ListItemText primary="Pink blocks" secondary="Exit points (RET instructions)" /></ListItem>
              </List>
              <Alert severity="success" sx={{ mt: 2 }}>
                <strong>Tip:</strong> Use View → Function Call Graph to see how functions call each other 
                across the entire program. Great for understanding program architecture.
              </Alert>
            </AccordionDetails>
          </Accordion>
        </TabPanel>

        {/* Tab 3: Scripting */}
        <TabPanel value={tabValue} index={3}>
          <Typography variant="h5" gutterBottom>Ghidra Scripting</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            Ghidra supports Java and Python (Jython) scripting for automation and custom analysis. 
            Scripts can access all of Ghidra's APIs to automate repetitive tasks, batch process files, 
            or add custom functionality.
          </Alert>

          <Typography variant="h6" gutterBottom>Running Scripts</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem>
                  <ListItemIcon><FunctionsIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Window → Script Manager (Ctrl+Shift+G)" 
                    secondary="Browse, run, and manage scripts" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><FunctionsIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Script Directories" 
                    secondary="~/ghidra_scripts (user) and ghidra/Ghidra/Features/*/ghidra_scripts (built-in)" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SettingsIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Script Parameters" 
                    secondary="Use @param annotations for user input" 
                  />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Alert severity="success">
                <AlertTitle>Python vs Java</AlertTitle>
                <List dense sx={{ py: 0 }}>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="Python: Easier syntax, faster prototyping" /></ListItem>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="Java: Better IDE support, type safety, performance" /></ListItem>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="Both have full API access" /></ListItem>
                </List>
              </Alert>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Script Categories</Typography>
          <Grid container spacing={2}>
            {scriptCategories.map((cat) => (
              <Grid item xs={12} sm={6} md={4} key={cat.category}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>
                      {cat.category}
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {cat.scripts.map((script) => (
                        <Chip key={script} label={script} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Python Script Examples</Typography>
          
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Find All Strings</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="find_strings.py">{`# @category Analysis
# @description Find all defined strings in the binary
# @author VRAgent

from ghidra.program.model.data import StringDataType

program = currentProgram
listing = program.getListing()

print("=== Strings Found ===")
count = 0

for data in listing.getDefinedData(True):
    if data.hasStringValue():
        addr = data.getAddress()
        value = data.getValue()
        print("{}: {}".format(addr, value))
        count += 1

print("\\nTotal strings found: {}".format(count))`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Find Suspicious API Calls</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="find_suspicious_apis.py">{`# @category Security
# @description Find potentially dangerous API imports
# @author VRAgent

suspicious_apis = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "LoadLibrary",
    "GetProcAddress", "ShellExecute", "WinExec", "CreateProcess",
    "RegSetValueEx", "InternetOpen", "URLDownloadToFile",
    "CryptDecrypt", "CryptEncrypt", "socket", "connect", "send", "recv"
]

program = currentProgram
symbol_table = program.getSymbolTable()

print("=== Suspicious API Calls ===\\n")

for api in suspicious_apis:
    symbols = symbol_table.getSymbols(api)
    for sym in symbols:
        refs = getReferencesTo(sym.getAddress())
        if refs:
            print("[!] {} found:".format(api))
            for ref in refs:
                func = getFunctionContaining(ref.getFromAddress())
                func_name = func.getName() if func else "unknown"
                print("    Called from {} at {}".format(func_name, ref.getFromAddress()))
            print()`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">XOR Decryption Helper</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="xor_decrypt_selection.py">{`# @category Crypto
# @description XOR decrypt selected bytes and show result
# @keybinding Ctrl+Shift+X
# @author VRAgent

from ghidra.program.model.mem import MemoryAccessException

# Get user input for XOR key
key_str = askString("XOR Key", "Enter XOR key (hex, e.g., 0x41 or 41):")
key = int(key_str, 16) if key_str.startswith("0x") else int(key_str, 16)

# Get current selection
selection = currentSelection
if not selection:
    popup("Please select bytes to decrypt")
else:
    start = selection.getMinAddress()
    end = selection.getMaxAddress()
    length = end.subtract(start) + 1
    
    # Read bytes
    memory = currentProgram.getMemory()
    encrypted = []
    addr = start
    for i in range(length):
        encrypted.append(memory.getByte(addr) & 0xFF)
        addr = addr.add(1)
    
    # Decrypt
    decrypted = ''.join([chr(b ^ key) for b in encrypted])
    
    # Show result
    print("=== XOR Decryption ===")
    print("Address: {} - {}".format(start, end))
    print("Key: 0x{:02X}".format(key))
    print("Decrypted: {}".format(decrypted))
    
    # Optionally add as comment
    if askYesNo("Add Comment", "Add decrypted string as comment?"):
        setEOLComment(start, "Decrypted: " + decrypted)`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Export Functions to CSV</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="export_functions.py">{`# @category Export
# @description Export all functions to CSV with details
# @author VRAgent

import csv
import os

# Ask for output file
output_file = askFile("Save CSV", "Save")
if output_file:
    fm = currentProgram.getFunctionManager()
    
    with open(str(output_file), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Address', 'Size', 'CallingConvention', 'Parameters', 'IsThunk'])
        
        for func in fm.getFunctions(True):
            name = func.getName()
            addr = str(func.getEntryPoint())
            size = func.getBody().getNumAddresses()
            cc = func.getCallingConventionName()
            params = func.getParameterCount()
            is_thunk = func.isThunk()
            
            writer.writerow([name, addr, size, cc, params, is_thunk])
    
    print("Exported {} functions to {}".format(fm.getFunctionCount(), output_file))`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Batch Rename Functions by Pattern</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="rename_by_string.py">{`# @category Refactoring  
# @description Rename functions based on strings they reference
# @author VRAgent

from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()
renamed_count = 0

for func in fm.getFunctions(True):
    # Skip already named functions
    if not func.getName().startswith("FUN_"):
        continue
    
    # Look for string references in function
    body = func.getBody()
    refs = getReferencesFrom(func.getEntryPoint())
    
    for ref in refs:
        data = getDataAt(ref.getToAddress())
        if data and data.hasStringValue():
            string_val = str(data.getValue())
            # Clean string for function name
            if len(string_val) > 3 and len(string_val) < 30:
                clean_name = "fn_" + string_val.replace(" ", "_").replace(".", "_")[:20]
                try:
                    func.setName(clean_name, SourceType.USER_DEFINED)
                    print("Renamed {} to {}".format(func.getEntryPoint(), clean_name))
                    renamed_count += 1
                except:
                    pass
                break

print("\\nRenamed {} functions".format(renamed_count))`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Headless Analysis</Typography>
          <Typography paragraph>
            Run Ghidra scripts without the GUI for batch processing:
          </Typography>
          <CodeBlock title="Headless Mode Commands">{`# Basic headless analysis
./analyzeHeadless /path/to/project ProjectName \\
    -import /path/to/binary \\
    -postScript MyScript.py

# With script arguments
./analyzeHeadless /path/to/project ProjectName \\
    -import /path/to/binary \\
    -scriptPath /my/scripts \\
    -postScript analyze.py "arg1" "arg2"

# Process existing project
./analyzeHeadless /path/to/project ProjectName \\
    -process binary_name \\
    -noanalysis \\
    -postScript export_data.py

# Batch import multiple files
./analyzeHeadless /path/to/project BatchProject \\
    -import /malware/samples/ \\
    -recursive \\
    -postScript triage.py`}</CodeBlock>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Useful Built-in Scripts</Typography>
          <Grid container spacing={2}>
            {[
              { name: "FindCrypt", desc: "Detect cryptographic constants (AES S-box, DES, etc.)" },
              { name: "FunctionID", desc: "Identify known library functions by signature" },
              { name: "RecoverClassesFromRTTI", desc: "Recover C++ class hierarchies from RTTI" },
              { name: "SearchStringReferences", desc: "Find all cross-references to strings" },
              { name: "PropagateExternalParameters", desc: "Apply known function signatures" },
              { name: "FindPotentialDecompilerProblems", desc: "Identify decompilation issues" },
              { name: "ResolveX86orX64LinuxSyscalls", desc: "Name Linux system calls" },
              { name: "ComputeChecksum", desc: "Calculate checksums of binary sections" },
            ].map((script) => (
              <Grid item xs={12} sm={6} md={4} key={script.name}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle2" fontWeight="bold" color="primary">{script.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{script.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        {/* Tab 4: Tips & Tricks */}
        <TabPanel value={tabValue} index={4}>
          <Typography variant="h5" gutterBottom>Tips & Best Practices</Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>Workflow Tips</Typography>
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Rename Everything</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    As you understand functions and variables, rename them with descriptive names. 
                    This makes the decompiled code much more readable.
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="L" secondary="Rename any symbol/label" /></ListItem>
                    <ListItem><ListItemText primary="Use prefixes" secondary="fn_, sub_, dat_, str_ for organization" /></ListItem>
                    <ListItem><ListItemText primary="Be descriptive" secondary="'parse_network_packet' > 'FUN_00401234'" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Use Comments Liberally</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Add comments to document your findings. Future you (or teammates) will thank you.
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary=";" secondary="End-of-line comment" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+;" secondary="Plate comment (multi-line above)" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+Enter" secondary="Pre-comment in decompiler" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Start from Strings</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Strings are your entry point into understanding code:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Search → For Strings" secondary="Find all strings" /></ListItem>
                    <ListItem><ListItemText primary="Look for error messages" secondary="Often reveal function purpose" /></ListItem>
                    <ListItem><ListItemText primary="URLs, IPs, filenames" secondary="Network/file operations" /></ListItem>
                    <ListItem><ListItemText primary="Press X on string" secondary="Find all code using it" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Define Data Types</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Create structs for data structures. Proper typing dramatically improves decompiler output.
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Window → Data Type Manager" secondary="Create/edit types" /></ListItem>
                    <ListItem><ListItemText primary="T" secondary="Apply type at cursor" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+L (decompiler)" secondary="Retype variable" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>Performance Tips</Typography>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Increase Memory</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Edit support/launch.properties to increase heap size for large binaries:
                  </Typography>
                  <CodeBlock title="launch.properties">{`# Default is usually 1G - increase for large binaries
MAXMEM=4G

# For very large firmware images
MAXMEM=8G

# Also consider:
VMARG=-XX:+UseG1GC`}</CodeBlock>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Selective Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    For very large binaries, skip auto-analysis initially:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Import without analysis" secondary="Click 'No' on auto-analyze prompt" /></ListItem>
                    <ListItem><ListItemText primary="Manual disassembly" secondary="D to disassemble at cursor" /></ListItem>
                    <ListItem><ListItemText primary="One-shot analysis" secondary="Analyze → One Shot for specific regions" /></ListItem>
                    <ListItem><ListItemText primary="Select and analyze" secondary="Highlight region, then analyze selection" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Use Bookmarks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Bookmark (Ctrl+D) interesting locations as you explore:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Categories" secondary="TODO, Interesting, Vuln, Crypto, C2" /></ListItem>
                    <ListItem><ListItemText primary="Window → Bookmarks" secondary="View all bookmarks" /></ListItem>
                    <ListItem><ListItemText primary="Double-click" secondary="Navigate to bookmark" /></ListItem>
                    <ListItem><ListItemText primary="Export" secondary="Save bookmarks to share analysis" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Navigation History</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Use navigation history to move through your analysis:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Alt+Left" secondary="Go back in history" /></ListItem>
                    <ListItem><ListItemText primary="Alt+Right" secondary="Go forward in history" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+M" secondary="Add marker at current location" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+J" secondary="Show marker navigation" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Malware Analysis Tips</Typography>
          <Alert severity="warning" sx={{ mb: 3 }}>
            <AlertTitle>Safety First!</AlertTitle>
            Always analyze malware in an isolated virtual machine with snapshots. Never run malware on your host system.
          </Alert>
          
          <Grid container spacing={2}>
            {malwareAnalysisTips.map((tip, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Typography variant="subtitle2" fontWeight="bold" color="primary">{tip.tip}</Typography>
                    <Typography variant="body2" color="text.secondary">{tip.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Common Malware Anti-Analysis Techniques</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Anti-Analysis Detection Patterns">{`// IsDebuggerPresent - Direct check
if (IsDebuggerPresent()) ExitProcess(0);

// NtGlobalFlag - PEB flag check
PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
if (peb->NtGlobalFlag & 0x70) ExitProcess(0);  // Heap flags set by debugger

// Timing check - Sleep difference
DWORD start = GetTickCount();
Sleep(1000);
if (GetTickCount() - start < 900) ExitProcess(0);  // Sleep skipped by debugger

// VM Detection - Registry keys
RegOpenKey(HKLM, "SOFTWARE\\VMware, Inc.\\VMware Tools", &key);
RegOpenKey(HKLM, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", &key);

// VM Detection - Known processes
if (FindProcess("vmtoolsd.exe") || FindProcess("VBoxService.exe")) ExitProcess(0);

// What to look for:
// - Calls to IsDebuggerPresent, CheckRemoteDebuggerPresent
// - Access to PEB structure
// - GetTickCount, QueryPerformanceCounter timing checks
// - Registry queries for VM software
// - CPUID checks for hypervisor`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Ghidra Extensions</Typography>
          <Typography paragraph color="text.secondary">
            Extend Ghidra's functionality with community plugins and extensions:
          </Typography>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Extension</strong></TableCell>
                  <TableCell><strong>Category</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ghidraExtensions.map((ext) => (
                  <TableRow key={ext.name}>
                    <TableCell><Typography fontWeight="bold" color="primary">{ext.name}</Typography></TableCell>
                    <TableCell><Chip label={ext.category} size="small" variant="outlined" /></TableCell>
                    <TableCell>{ext.desc}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Installing Extensions</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem><ListItemText primary="1. Download extension ZIP" secondary="From GitHub releases or build from source" /></ListItem>
                <ListItem><ListItemText primary="2. File → Install Extensions" secondary="In Ghidra Project window (not CodeBrowser)" /></ListItem>
                <ListItem><ListItemText primary="3. Click + and select ZIP" secondary="Or extract to Ghidra/Extensions folder" /></ListItem>
                <ListItem><ListItemText primary="4. Restart Ghidra" secondary="Extensions load on startup" /></ListItem>
              </List>
              <Alert severity="info" sx={{ mt: 2 }}>
                <strong>Building Extensions:</strong> Use gradle with Ghidra's build system. 
                Set GHIDRA_INSTALL_DIR environment variable and run <code>gradle buildExtension</code>
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Ghidra Server (Team Collaboration)</Typography>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Setting Up Ghidra Server</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Ghidra Server enables team collaboration with shared projects and version control:
              </Typography>
              <CodeBlock title="Server Setup (Linux)">{`# Navigate to server directory
cd $GHIDRA_HOME/server

# Initialize repository (first time only)
./svrAdmin -add myrepository

# Add users
./svrAdmin -add username --p

# Start server
./ghidraSvr start

# Default port: 13100
# Configure firewall accordingly`}</CodeBlock>
              <Alert severity="info" sx={{ mt: 2 }}>
                <strong>Connecting:</strong> In Ghidra, File → New Project → Shared Project → 
                Enter server address and credentials. Projects sync automatically.
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Learning Resources</Typography>
          <Grid container spacing={2}>
            {[
              { resource: "Official Ghidra Docs", desc: "Help → Contents in Ghidra", type: "Built-in", color: "success" },
              { resource: "Ghidra Courses (NSA)", desc: "docs/GhidraClass in installation folder", type: "Free", color: "success" },
              { resource: "r/ReverseEngineering", desc: "Active community for RE discussion", type: "Community", color: "info" },
              { resource: "Ghidra Ninja (YouTube)", desc: "Video tutorials and walkthroughs", type: "Video", color: "primary" },
              { resource: "crackmes.one", desc: "Practice reversing challenges", type: "Practice", color: "warning" },
              { resource: "Practical Malware Analysis", desc: "Classic RE book, applicable to Ghidra", type: "Book", color: "secondary" },
              { resource: "RPISEC Modern Binary Exploitation", desc: "Free course with RE components", type: "Course", color: "success" },
              { resource: "MalwareTech Challenges", desc: "Beginner-friendly malware RE exercises", type: "Practice", color: "warning" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.resource}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Chip label={item.type} size="small" color={item.color as any} sx={{ mb: 1 }} />
                    <Typography variant="subtitle2" fontWeight="bold">{item.resource}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Quick Reference Card</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>Navigation</Typography>
                  <List dense disablePadding>
                    {[
                      { k: "G", d: "Go to address" },
                      { k: "X", d: "Show XRefs" },
                      { k: "Alt+←/→", d: "History nav" },
                      { k: "Ctrl+D", d: "Bookmark" },
                      { k: "Space", d: "Function graph" },
                    ].map((item) => (
                      <ListItem key={item.k} sx={{ py: 0.25 }}>
                        <Chip label={item.k} size="small" sx={{ mr: 1, minWidth: 70 }} />
                        <ListItemText primary={item.d} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>Editing</Typography>
                  <List dense disablePadding>
                    {[
                      { k: "L", d: "Rename label" },
                      { k: ";", d: "Add comment" },
                      { k: "T", d: "Set type" },
                      { k: "F", d: "Create function" },
                      { k: "D", d: "Define data" },
                    ].map((item) => (
                      <ListItem key={item.k} sx={{ py: 0.25 }}>
                        <Chip label={item.k} size="small" sx={{ mr: 1, minWidth: 70 }} />
                        <ListItemText primary={item.d} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>Search</Typography>
                  <List dense disablePadding>
                    {[
                      { k: "Ctrl+Shift+F", d: "Find strings" },
                      { k: "Ctrl+B", d: "Search bytes" },
                      { k: "N", d: "Next occurrence" },
                      { k: "Ctrl+F", d: "Text search" },
                      { k: "Ctrl+Shift+E", d: "Symbol tree" },
                    ].map((item) => (
                      <ListItem key={item.k} sx={{ py: 0.25 }}>
                        <Chip label={item.k} size="small" sx={{ mr: 1, minWidth: 70 }} />
                        <ListItemText primary={item.d} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
};

export default GhidraGuidePage;
