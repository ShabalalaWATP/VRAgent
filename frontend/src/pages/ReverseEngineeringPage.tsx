import React, { useState } from "react";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
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
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import BugReportIcon from "@mui/icons-material/BugReport";
import MemoryIcon from "@mui/icons-material/Memory";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SecurityIcon from "@mui/icons-material/Security";
import TerminalIcon from "@mui/icons-material/Terminal";
import SchoolIcon from "@mui/icons-material/School";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import { useNavigate } from "react-router-dom";

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

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "bash",
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
        p: 2,
        bgcolor: "#1a1a2e",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(139, 92, 246, 0.3)",
      }}
    >
      <Box
        sx={{
          position: "absolute",
          top: 8,
          right: 8,
          display: "flex",
          gap: 1,
        }}
      >
        <Chip label={language} size="small" color="secondary" />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#fff" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "monospace",
          fontSize: "0.9rem",
          color: "#e0e0e0",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const ReverseEngineeringPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const tools = [
    { name: "Ghidra", type: "Disassembler/Decompiler", platform: "Multi", cost: "Free (NSA)", best: "General RE, malware analysis" },
    { name: "IDA Pro", type: "Disassembler/Decompiler", platform: "Multi", cost: "Commercial", best: "Industry standard, extensive plugins" },
    { name: "Binary Ninja", type: "Disassembler/Decompiler", platform: "Multi", cost: "Commercial", best: "Modern UI, scripting" },
    { name: "radare2/Cutter", type: "Disassembler", platform: "Multi", cost: "Free", best: "CLI power users, CTFs" },
    { name: "x64dbg", type: "Debugger", platform: "Windows", cost: "Free", best: "Windows debugging" },
    { name: "GDB + GEF", type: "Debugger", platform: "Linux", cost: "Free", best: "Linux debugging, exploitation" },
    { name: "OllyDbg", type: "Debugger", platform: "Windows", cost: "Free", best: "32-bit Windows apps" },
    { name: "PE-bear", type: "PE Analyzer", platform: "Multi", cost: "Free", best: "PE file inspection" },
    { name: "dnSpy / ILSpy", type: ".NET Decompiler/Debugger", platform: "Windows", cost: "Free", best: ".NET assemblies" },
    { name: "Jadx / JADX-GUI", type: "Android Decompiler", platform: "Multi", cost: "Free", best: "APK to Java/Kotlin" },
    { name: "Frida", type: "Dynamic Instrumentation", platform: "Multi", cost: "Free", best: "Hooking, runtime tracing" },
    { name: "Apktool", type: "Repacker / Smali", platform: "Multi", cost: "Free", best: "Android resources, smali patching" },
    { name: "Capa (Mandiant)", type: "Capability Scanner", platform: "Multi", cost: "Free", best: "Automatic behavior tagging" },
    { name: "Sysinternals Suite", type: "Windows Utilities", platform: "Windows", cost: "Free", best: "Procmon, Autoruns, TCPView" },
  ];

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
      <Container maxWidth="lg">
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ mb: 2, color: "grey.400" }}
          >
            Back to Learn Hub
          </Button>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <MemoryIcon sx={{ fontSize: 40, color: "#8b5cf6" }} />
            <Typography
              variant="h3"
              sx={{
                fontWeight: 700,
                background: "linear-gradient(135deg, #8b5cf6 0%, #a855f7 100%)",
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                color: "transparent",
              }}
            >
              Reverse Engineering Intro
            </Typography>
          </Box>
          <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
            Understanding binaries, disassembly, and executable analysis fundamentals
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip icon={<BugReportIcon />} label="Malware Analysis" size="small" />
            <Chip icon={<SecurityIcon />} label="Vulnerability Research" size="small" />
            <Chip icon={<CodeIcon />} label="Binary Exploitation" size="small" />
          </Box>
        </Box>

        {/* Tabs */}
        <Paper sx={{ bgcolor: "#12121a", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={handleTabChange}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.1)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#8b5cf6" },
            }}
          >
            <Tab icon={<SchoolIcon />} label="Fundamentals" />
            <Tab icon={<BuildIcon />} label="Tools" />
            <Tab icon={<TerminalIcon />} label="x86 Assembly" />
            <Tab icon={<CodeIcon />} label="Static Analysis" />
            <Tab icon={<BugReportIcon />} label="Dynamic Analysis" />
            <Tab icon={<CheckCircleIcon />} label="Workflow" />
          </Tabs>

          {/* Tab 0: Fundamentals */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#8b5cf6", mb: 3 }}>
                What is Reverse Engineering?
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                Reverse engineering is the process of analyzing software to understand how it works
                without access to source code. It's essential for malware analysis, vulnerability
                research, and security auditing.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Key Concepts</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Executable Formats"
                        secondary="PE (Windows), ELF (Linux), Mach-O (macOS) - containers for code and data"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Disassembly"
                        secondary="Converting machine code back to assembly language instructions"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Decompilation"
                        secondary="Reconstructing high-level code (C/C++) from assembly - approximation only"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Debugging"
                        secondary="Running code step-by-step to observe behavior, registers, and memory"
                      />
                    </ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Memory Layout</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`High Memory
+---------------------+
|       Stack         | <- Local variables, return addresses (grows down)
|         v           |
|                     |
|         ^           |
+---------------------+
|        Heap         | <- Dynamic allocations (grows up)
+---------------------+
|        BSS          | <- Uninitialized global variables
+---------------------+
|        Data         | <- Initialized global variables
+---------------------+
|        Text         | <- Executable code (read-only)
+---------------------+
Low Memory`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Registers (x86-64)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Register</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Purpose</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["RAX", "Return value, accumulator"],
                          ["RBX", "Callee-saved, base pointer"],
                          ["RCX", "Counter, 4th argument (Windows)"],
                          ["RDX", "3rd argument, I/O pointer"],
                          ["RSI", "2nd argument (Linux), source index"],
                          ["RDI", "1st argument (Linux), destination index"],
                          ["RSP", "Stack pointer (top of stack)"],
                          ["RBP", "Base pointer (stack frame)"],
                          ["RIP", "Instruction pointer (next instruction)"],
                        ].map(([reg, purpose]) => (
                          <TableRow key={reg}>
                            <TableCell>
                              <Chip label={reg} size="small" color="secondary" />
                            </TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{purpose}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Calling Conventions (x64)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Platform</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Argument Order</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Stack Notes</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Linux (System V)", "RDI, RSI, RDX, RCX, R8, R9, rest on stack", "Caller aligns stack to 16 bytes before call"],
                          ["Windows (x64)", "RCX, RDX, R8, R9, rest on stack", "Shadow space: 32 bytes reserved by caller"],
                        ].map(([platform, order, notes]) => (
                          <TableRow key={platform}>
                            <TableCell sx={{ color: "grey.300" }}>{platform}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{order}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{notes}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Binary Protections</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Feature</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Purpose</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Quick Check</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["NX/DEP", "Mark memory non-executable to stop code injection", "checksec or PE header (DYNAMIC_BASE, NXCOMPAT)"],
                          ["ASLR/PIE", "Randomize addresses to hinder ROP/shellcode", "checksec or PE: DYNAMIC_BASE"],
                          ["Stack Canaries", "Detect stack smashing before returning", "checksec or look for __stack_chk_fail"],
                          ["Control-Flow Guard", "Validate indirect calls/jumps", "PE Guard CF flag, presence of __guard_check_icall"],
                          ["Code Signing", "Ensure binary integrity and publisher identity", "signtool verify / openssl pkcs7 -inform DER"],
                        ].map(([feature, purpose, check]) => (
                          <TableRow key={feature}>
                            <TableCell sx={{ color: "grey.300" }}>{feature}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{purpose}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{check}</TableCell>
                          </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Packer & Obfuscation Clues</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                {[
                  "Section names like .upx/.pec or very small import tables",
                  "High entropy sections and single large executable section",
                  "Import table rebuilt at runtime (GetProcAddress, LoadLibrary loops)",
                  "Self-modifying code or WriteProcessMemory on current process",
                  "Unknown TLS callbacks or many relocations in a non-PIE binary",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.5 }}>
                    <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                    <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                  </ListItem>
                ))}
              </List>
              <CodeBlock
                language="bash"
                code={`# UPX quick check / unpack
upx -t suspicious.exe       # Test
upx -d suspicious.exe       # Attempt decompress

# Detect common packers (Linux)
diec suspicious.exe         # Detect It Easy CLI

# Rebuild imports after unpacking (Windows)
scylla_x64.exe              # Attach to process and dump+fix imports`}
              />
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Quick YARA Template</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock
                language="python"
                code={`rule detect_suspicious_strings {
  meta:
    author = "analyst"
    description = "Example triage rule"
  strings:
    $http = "http://" nocase
    $https = "https://" nocase
    $ps = "powershell" nocase
    $valloc = "VirtualAlloc" ascii
  condition:
    2 of ($http, $https, $ps) or $valloc
}`}
              />
            </AccordionDetails>
          </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 1: Tools */}
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#8b5cf6", mb: 3 }}>
                Essential RE Tools
              </Typography>

              <TableContainer component={Paper} sx={{ bgcolor: "#1a1a2e", mb: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#8b5cf6" }}>Tool</TableCell>
                      <TableCell sx={{ color: "#8b5cf6" }}>Type</TableCell>
                      <TableCell sx={{ color: "#8b5cf6" }}>Platform</TableCell>
                      <TableCell sx={{ color: "#8b5cf6" }}>Cost</TableCell>
                      <TableCell sx={{ color: "#8b5cf6" }}>Best For</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {tools.map((tool) => (
                      <TableRow key={tool.name}>
                        <TableCell>
                          <Typography sx={{ color: "#a855f7", fontWeight: 600 }}>
                            {tool.name}
                          </Typography>
                        </TableCell>
                        <TableCell sx={{ color: "grey.300" }}>{tool.type}</TableCell>
                        <TableCell sx={{ color: "grey.300" }}>{tool.platform}</TableCell>
                        <TableCell>
                          <Chip
                            label={tool.cost}
                            size="small"
                            color={tool.cost === "Free" || tool.cost.includes("Free") ? "success" : "warning"}
                          />
                        </TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{tool.best}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Alert severity="success" sx={{ mb: 2 }}>
                <strong>Recommended Starting Point:</strong> Ghidra is free, powerful, and has 
                excellent documentation. Perfect for learning RE fundamentals.
              </Alert>

              <Grid container spacing={2} sx={{ mt: 1, mb: 2 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2.5, bgcolor: "#0f1024", border: "1px solid rgba(139,92,246,0.25)", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ color: "#a855f7", fontWeight: 600, mb: 1 }}>
                      Ghidra Starter Pack
                    </Typography>
                    <List dense>
                      {[
                        "Download zip, extract, run ghidraRun (Java 17+ required).",
                        "Create Non-Shared project > import binary > accept analysis defaults.",
                        "Enable Decompiler window (Window > Decompiler) and Symbol Tree.",
                        "Right click function > Rename, apply Data Type, add comments.",
                        "Use Xrefs (hover shortcut: X) to trace callers/callees quickly.",
                      ].map((item) => (
                        <ListItem key={item} sx={{ py: 0.4 }}>
                          <ListItemIcon sx={{ minWidth: 30 }}>
                            <CheckCircleIcon sx={{ color: "#22c55e" }} fontSize="small" />
                          </ListItemIcon>
                          <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300", fontSize: "0.9rem" } }} />
                        </ListItem>
                      ))}
                    </List>
                    <Alert severity="info" sx={{ mt: 1, bgcolor: "rgba(168,85,247,0.08)" }}>
                      Save often. Ghidra auto-analysis can be restarted via <code>Analysis &gt; Auto Analyze</code> after changing options.
                    </Alert>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2.5, bgcolor: "#0f1024", border: "1px solid rgba(139,92,246,0.25)", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ color: "#a855f7", fontWeight: 600, mb: 1 }}>
                      WinDbg (Preview) Starter Pack
                    </Typography>
                    <List dense>
                      {[
                        "Install WinDbg Preview from Microsoft Store (uses modern UI and engines).",
                        "Set symbols: File > Settings > Symbol Path = srv*C:\\symbols*https://msdl.microsoft.com/download/symbols.",
                        "User-mode attach: File > Attach to Process (select target) or launch with arguments.",
                        "Open command window (Ctrl+Alt+D) and issue .symfix; .reload /f to sync symbols.",
                        "Use .exr -1 for last exception, kb for call stack, and !analyze -v for crash triage.",
                      ].map((item) => (
                        <ListItem key={item} sx={{ py: 0.4 }}>
                          <ListItemIcon sx={{ minWidth: 30 }}>
                            <SecurityIcon sx={{ color: "#22c55e" }} fontSize="small" />
                          </ListItemIcon>
                          <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300", fontSize: "0.9rem" } }} />
                        </ListItem>
                      ))}
                    </List>
                    <Alert severity="warning" sx={{ mt: 1, bgcolor: "rgba(245,158,11,0.08)" }}>
                      Enable symbols before running commands. Without symbols, call stacks and breakpoints will be unreliable.
                    </Alert>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" sx={{ color: "grey.200", mt: 3, mb: 2 }}>
                Quick Setup Commands
              </Typography>

              <CodeBlock
                language="bash"
                code={`# Install radare2 (Linux)
git clone https://github.com/radareorg/radare2
cd radare2 && sys/install.sh

# Install GEF for GDB
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Run Ghidra (after download)
./ghidraRun

# Basic file analysis with radare2
r2 -A ./binary`}
              />

              <Typography variant="h6" sx={{ color: "grey.200", mt: 2, mb: 1 }}>
                WinDbg Symbol Path (PowerShell)
              </Typography>
              <CodeBlock
                language="powershell"
                code={`# Create a local symbol cache and set environment variable
$env:_NT_SYMBOL_PATH='srv*C:\\\\symbols*https://msdl.microsoft.com/download/symbols'

# Launch WinDbg Preview from shell
windbgx.exe

# Inside WinDbg: refresh symbols and load modules
.symfix
.reload /f
!sym noisy   ; optional: show symbol resolution issues`}
              />
            </Box>
          </TabPanel>

          {/* Tab 2: x86 Assembly */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#8b5cf6", mb: 3 }}>
                x86 Assembly Basics
              </Typography>

              <Alert severity="warning" sx={{ mb: 3 }}>
                Focus on reading assembly, not writing it. Recognize patterns rather than
                memorizing every instruction.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Common Instructions</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="asm"
                    code={`; Data Movement
mov rax, rbx      ; Copy rbx to rax
lea rax, [rbx+8]  ; Load effective address (pointer math)
push rax          ; Push to stack
pop rbx           ; Pop from stack

; Arithmetic
add rax, 10       ; rax = rax + 10
sub rax, rbx      ; rax = rax - rbx
imul rax, rbx     ; rax = rax * rbx
inc rax           ; rax++
dec rax           ; rax--

; Logic & Comparison
cmp rax, rbx      ; Compare (sets flags)
test rax, rax     ; Test if zero (AND with self)
xor rax, rax      ; Zero out register (common pattern)

; Control Flow
jmp label         ; Unconditional jump
je/jz label       ; Jump if equal/zero
jne/jnz label     ; Jump if not equal/not zero
jl/jg label       ; Jump if less/greater (signed)
call func         ; Call function
ret               ; Return from function`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Recognizing C Patterns</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="asm"
                    code={`; if (x == 5) { ... }
cmp dword [rbp-4], 5
jne skip_block
; ... if body ...
skip_block:

; for (int i = 0; i < 10; i++)
mov dword [rbp-4], 0     ; i = 0
loop_start:
cmp dword [rbp-4], 10    ; i < 10?
jge loop_end
; ... loop body ...
inc dword [rbp-4]        ; i++
jmp loop_start
loop_end:

; Function call: result = func(a, b)
mov edi, [rbp-8]         ; First arg in EDI (Linux x64)
mov esi, [rbp-12]        ; Second arg in ESI
call func
mov [rbp-16], eax        ; Store return value`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Function Shapes</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="asm"
                    code={`; Typical prologue/epilogue
push rbp
mov rbp, rsp
sub rsp, 0x40       ; local space
...
leave               ; mov rsp, rbp / pop rbp
ret

; Leaf function (no stack frame)
xor eax, eax
ret

; Switch statement (jump table)
mov eax, [rbp-4]
cmp eax, 4
ja  default_case
movsxd rax, dword [jmp_table + rax*4]
jmp rax

; Position-independent code (PIE)
call get_rip
get_rip:
pop rbx             ; rbx holds RIP
lea rax, [rbx+offset_to_data]`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Anti-Analysis Behaviors</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    {[
                      "Debugger checks (IsDebuggerPresent, NtQueryInformationProcess, timing deltas)",
                      "Sandbox evasion (sleep bombs, user interaction checks, MAC/vendor checks)",
                      "Virtualization checks (CPUID, registry keys for VBox/VMware, BIOS strings)",
                      "Process tampering (unhooking DLLs, patching EDR drivers)",
                      "Persistence drops delayed until specific hostname/domain or mutex exists",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.5 }}>
                        <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">API Breakpoints to Set</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>API</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Why</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["CreateProcessA/W", "Process creation / child staging"],
                          ["VirtualAlloc/VirtualProtect", "Memory allocation, possible shellcode staging"],
                          ["WriteProcessMemory", "Injection into other processes"],
                          ["CreateRemoteThread/NtCreateThreadEx", "Cross-process code execution"],
                          ["InternetConnect/WinHttpOpen", "C2 and data exfil channels"],
                          ["RegSetValue/RegCreateKey", "Persistence in registry"],
                        ].map(([api, why]) => (
                          <TableRow key={api}>
                            <TableCell sx={{ color: "grey.300" }}>{api}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{why}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 3: Static Analysis */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#8b5cf6", mb: 3 }}>
                Static Analysis Techniques
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                Analyzing binaries without executing them. Safe for malware analysis.
              </Typography>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Initial Triage</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# File type identification
file suspicious.exe
# suspicious.exe: PE32+ executable (GUI) x86-64, for MS Windows

# Strings extraction (look for URLs, IPs, commands)
strings -n 8 suspicious.exe | grep -E "(http|cmd|powershell)"

# Check hashes
sha256sum suspicious.exe
# Search hash on VirusTotal

# PE header info
rabin2 -I suspicious.exe

# List imports (API calls)
rabin2 -i suspicious.exe | grep -E "(CreateFile|WriteFile|Socket|Http)"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Ghidra Quick Start</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    <ListItem>
                      <ListItemText
                        primary="1. Create New Project"
                        secondary="File > New Project > Non-Shared Project"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="2. Import Binary"
                        secondary="File > Import File > Select binary > Accept defaults"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="3. Auto-Analyze"
                        secondary="Yes to auto-analysis prompt (wait for completion)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="4. Find Entry Point"
                        secondary="Symbol Tree > Functions > entry or main"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="5. Review Decompiler"
                        secondary="Window > Decompiler (shows pseudo-C code)"
                      />
                    </ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Ghidra: First 15 Minutes Checklist</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Run auto-analysis, then jump to entry/main; rename obvious functions (e.g., sub_401000 -> init_config).",
                      "Open Decompiler + Listing side-by-side; press X on API imports to see where they are used.",
                      "Mark global variables with meaningful names and data types (right click > Data > type).",
                      "Use Search > For Strings to find URLs, registry paths, keys; press D to create data labels.",
                      "Check Functions window for small, repeated helpers (often crypto/encoding) and explore cross-references.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.4 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="text"
                    code={`Handy keys (Listing/Decompiler):
F        -> Go to address/symbol
G        -> Jump to other address
X        -> Xrefs (who calls this?)
Ctrl+L   -> Search strings
Ctrl+Shift+F -> Search for instruction pattern
;        -> Comment line
R        -> Rename symbol
Y        -> Change data type/size
P        -> Create/clear function
Space    -> Switch between Graph/Listing view`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Decompilation Cleanup Plan</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Fix wrong calling conventions on imported functions (Function Signature).",
                      "Convert obvious arrays/structs instead of raw bytes; apply data types to offsets you see repeatedly.",
                      "Inline constants (e.g., flags, magic numbers) with labels so the decompiler becomes readable.",
                      "Mark library thunks (memcpy, memset, strcmp) to avoid noise and clarify control flow.",
                      "Group related functions with bookmarks or function tags (persistence, network, crypto).",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.4 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Suspicious Indicators</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Indicator</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Why Suspicious</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["VirtualAlloc + WriteProcessMemory", "Code injection"],
                          ["CreateRemoteThread", "Process injection"],
                          ["GetProcAddress(LoadLibrary)", "Dynamic API resolution (evasion)"],
                          ["Winsock/WinHTTP imports", "Network communication"],
                          ["RegSetValue/RegCreateKey", "Persistence mechanism"],
                          ["High entropy sections", "Packed/encrypted code"],
                          ["Few imports + GetProcAddress", "API obfuscation"],
                        ].map(([indicator, reason]) => (
                          <TableRow key={indicator}>
                            <TableCell>
                              <code style={{ color: "#f87171" }}>{indicator}</code>
                            </TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{reason}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 4: Dynamic Analysis */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#8b5cf6", mb: 3 }}>
                Dynamic Analysis Techniques
              </Typography>

              <Alert severity="error" sx={{ mb: 3 }}>
                <strong>Always use isolated VMs for malware analysis.</strong> Take snapshots and
                keep network isolation. Never run suspicious code on your main system.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">GDB + GEF Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Start debugging
gdb ./binary

# GEF commands (after installing GEF)
gef> info functions          # List functions
gef> disass main             # Disassemble main
gef> b *main+42              # Breakpoint at offset
gef> b *0x401234             # Breakpoint at address
gef> r                       # Run program
gef> r arg1 arg2             # Run with arguments
gef> ni                      # Next instruction
gef> si                      # Step into
gef> c                       # Continue
gef> x/20x $rsp              # Examine 20 hex words at RSP
gef> x/s 0x402000            # Examine as string
gef> vmmap                   # Memory mappings
gef> registers               # Show all registers`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">WinDbg Quick Start (User-Mode)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`# Start or attach (WinDbg Preview)
# File > Start debugging > Launch executable (with args) OR Attach to process

# Set up symbols early
.symfix; .reload /f
.lines               ; show source if available
.logopen /t dbg.log  ; log output to file

# Control execution
g          ; go (run)
p / t      ; step over (use /t to step a single thread)
t          ; step into
gc         ; continue until return
bl / bd / be ; list, disable, enable breakpoints

# Breakpoints (use bu for rebasing-safe)
bu user32!MessageBoxA
bp 0x401000 \"kb 5; .printf \\\"hit!\\\\n\\\"\" 

# Inspection
kb         ; call stack
r          ; registers
dv         ; display locals (if symbols)
!peb       ; PEB overview
!teb       ; TEB overview
x kernel32!*CreateFile*   ; find APIs
s -d 0x00400000 L?0x1000 ff d8 ff e0  ; scan for JPEG header

# Exiting
.detach    ; detach from process
.logclose  ; close log`}
                  />
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Use <code>bu</code> instead of <code>bp</code> when ASLR is enabled so breakpoints rebind after reloads.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">x64dbg Quick Reference</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Hotkey</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Action</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["F2", "Toggle breakpoint"],
                          ["F7", "Step into"],
                          ["F8", "Step over"],
                          ["F9", "Run"],
                          ["Ctrl+G", "Go to address"],
                          ["Ctrl+F", "Find pattern"],
                          ["; (semicolon)", "Add comment"],
                          ["Space", "Assemble (modify instruction)"],
                        ].map(([key, action]) => (
                          <TableRow key={key}>
                            <TableCell>
                              <Chip label={key} size="small" variant="outlined" />
                            </TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{action}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Monitoring Tools</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Process Monitor (ProcMon)"
                        secondary="File system, registry, and process activity"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Wireshark"
                        secondary="Network traffic capture and analysis"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="API Monitor"
                        secondary="Track Windows API calls"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="strace/ltrace (Linux)"
                        secondary="System calls and library calls"
                      />
                    </ListItem>
                  </List>
                  <CodeBlock
                    language="bash"
                    code={`# Linux: Trace system calls
strace -f -o trace.log ./binary

# Linux: Trace library calls
ltrace ./binary`}
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 5: Workflow */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#8b5cf6", mb: 3 }}>
                RE Workflow Checklist
              </Typography>

              <Paper sx={{ p: 3, bgcolor: "#1a1a2e", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 2 }}>
                  Analysis Steps
                </Typography>
                <List>
                  {[
                    "Identify file type, architecture, and packing hints (file, checksec, rabin2 -I)",
                    "Snapshot your VM and enable network isolation before touching the sample",
                    "Hash the binary (SHA-256) and search threat intel portals (VT/MalShare/MISP)",
                    "Extract readable and wide strings for quick leads (domains, commands, mutexes)",
                    "Check signature status and binary protections (ASLR/NX/canaries/CFG)",
                    "List imports/exports to map capabilities and potential injection paths",
                    "Load into disassembler (Ghidra) and auto-analyze",
                    "Find entry point, main/TLS callbacks, and initialization routines",
                    "Tag interesting functions: crypto, networking, persistence, credential access",
                    "Locate anti-analysis checks and note bypass ideas",
                    "Plan dynamic run: decide arguments, sample input, and breakpoints (alloc/proc/thread/APIs)",
                    "Execute under debugger with snapshots; capture memory dumps of decrypted payloads",
                    "Monitor OS activity (ProcMon, Sysmon, Wireshark, ETW) and save evidence",
                    "Document timelines, IOCs, config data, and carve reusable detection rules",
                  ].map((step, index) => (
                    <ListItem key={index} sx={{ py: 0.5 }}>
                      <ListItemIcon>
                        <Chip
                          label={index + 1}
                          size="small"
                          sx={{ bgcolor: "#8b5cf6", minWidth: 28 }}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={step}
                        sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 3, bgcolor: "#101124", borderRadius: 2, mt: 3 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 2 }}>
                  Day-One Walkthrough (Beginner Friendly)
                </Typography>
                <List dense>
                  {[
                    "1) Copy sample into an isolated VM snapshot; record SHA-256 and store original in a read-only folder.",
                    "2) Run triage commands (file, strings, checksec/rabin2) and note indicators like URLs, mutex names, or imports.",
                    "3) Open in Ghidra, auto-analyze, and rename high-signal functions (networking, crypto, persistence). Add comments as you learn.",
                    "4) Plan dynamic run: decide inputs/arguments; set WinDbg symbol path and breakpoints on CreateProcess, VirtualAlloc, WriteProcessMemory.",
                    "5) Execute under WinDbg with logging enabled (.logopen); capture call stacks and memory dumps when interesting events occur.",
                    "6) Revisit Ghidra with runtime knowledge (addresses, decrypted strings) and annotate functions so future runs are faster.",
                    "7) Export findings: IOCs (domains, hashes), behaviors (injection, persistence), and detection ideas (YARA, ETW, Sysmon).",
                  ].map((step) => (
                    <ListItem key={step} sx={{ py: 0.35 }}>
                      <ListItemIcon sx={{ minWidth: 30 }}>
                        <CheckCircleIcon sx={{ color: "#22c55e" }} />
                      </ListItemIcon>
                      <ListItemText primary={step} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
                <Alert severity="info" sx={{ mt: 1 }}>
                  Keep a running notebook (addresses, API patterns, function names). Iteration is normal; expect to loop between static and dynamic phases.
                </Alert>
              </Paper>

              <Alert severity="info" sx={{ mt: 3 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Learning Resources
                </Typography>
                <List dense>
                  {[
                    "Practical Malware Analysis (book)",
                    "crackmes.one - Practice binaries",
                    "pwn.college - Free CTF-style courses",
                    "Nightmare - Intro to binary exploitation",
                    "Malware Unicorn's RE101/RE102 workshops",
                  ].map((resource) => (
                    <ListItem key={resource} sx={{ py: 0 }}>
                      <ListItemText
                        primary={resource}
                        sx={{ "& .MuiListItemText-primary": { color: "grey.200" } }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Alert>
            </Box>
          </TabPanel>
        </Paper>

        {/* Footer */}
        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
  );
};

export default ReverseEngineeringPage;
