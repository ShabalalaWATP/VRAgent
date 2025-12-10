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
                  <Typography variant="h6">Why & When to RE?</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Goal</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Common Outputs</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Example Targets</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Malware triage", "IOCs, config extraction, behavior summary", "Droppers, loaders, RATs, ransomware"],
                          ["Vuln research", "Crash root cause, exploitability, patch diffing", "Closed-source apps, firmware, drivers"],
                          ["Compatibility/interop", "Protocol documentation, file format notes", "Legacy apps, proprietary codecs"],
                          ["Security validation", "Control-flow/protections review", "3rd-party SDKs, supply-chain components"],
                        ].map(([goal, outputs, targets]) => (
                          <TableRow key={goal}>
                            <TableCell sx={{ color: "grey.300" }}>{goal}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{outputs}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{targets}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Static vs Dynamic vs Hybrid</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Mode</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>What It Is</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Use It When</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Static", "No execution; disassembly/decompilation/strings", "You need safety, quick IOCs, or to map capabilities"],
                          ["Dynamic", "Run under debugger/monitor; observe runtime", "You need decrypted config, unpacked payload, or behavior proof"],
                          ["Hybrid", "Iterate: static to pick hooks, dynamic to confirm, back to static with new addresses", "You face obfuscation/packing and need context"],
                        ].map(([mode, what, when]) => (
                          <TableRow key={mode}>
                            <TableCell sx={{ color: "grey.300" }}>{mode}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{what}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{when}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Hybrid is the norm: let static analysis choose breakpoints/hooks, then feed runtime evidence back into your decompiler to rename and simplify.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safety, Ethics, and Legal</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Use isolated VMs with snapshots; never run suspicious binaries on your host.",
                      "Respect licensing and jurisdiction: some EULAs prohibit RE; malware analysis is typically allowed for defense.",
                      "Avoid uploading sensitive customer binaries to public sandboxes; prefer offline tools.",
                      "Keep hashes and notes to demonstrate integrity; document when you modify binaries (unpacking/patching).",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
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
                  <Typography variant="h6">Beginner Lab Setup (Safe)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Windows VM (safe triage)
# 1) Snapshot fresh VM, disable clipboard/shared folders
# 2) Install: 7zip, Ghidra, x64dbg, PE-bear, Sysinternals
# 3) Add FakeNet-NG or INetSim if you need safe network emulation

# Linux VM (CTF-style)
sudo apt install gdb gdb-multiarch python3-pip
pip install capstone unicorn keystone-engine
git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh

# Basic test samples (benign)
# - crackmes.one (Beginner)
# - Malware-Unicorn RE101 labs
# - PicoCTF binary exploitation challenges`}
                  />
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Start with known-safe crackmes before touching malware. Practice renaming, commenting, and mapping control flow on small binaries first.
                  </Alert>
                </AccordionDetails>
              </Accordion>

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
                  <Typography variant="h6">Safety & Ethics</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Only handle samples in isolated labs with snapshots and no personal credentials present.",
                      "Assume binaries are malicious until proven otherwise; do not upload sensitive customer samples to public sandboxes.",
                      "Document actions for reproducibility; hash files before and after modifications to prove integrity.",
                      "Respect licensing: commercial tools (IDA, JEB) have usage limits; many community samples are copyrighted.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.4 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <Alert severity="warning" sx={{ mt: 1 }}>
                    Keep Internet-off by default; re-enable only for controlled sinkholing or capture with strong egress rules.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">RE Phases (Fast Track)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Phase</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Goal</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Outputs</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Triage", "Decide if/where to spend time", "Hashes, file type, packer clue, quick strings/IOCs"],
                          ["Static pass", "Map capabilities and protections", "Imports/exports, sections, suspected crypto/network/persistence funcs"],
                          ["Dynamic pass", "Observe real behavior safely", "Process/file/reg/network events, dumps of decrypted payloads"],
                          ["Refine", "Explain how it works", "Named functions, deobfuscated configs, execution flow notes"],
                          ["Report", "Share findings and detections", "IOCs, behavioral summary, YARA/Sysmon/ETW ideas"],
                        ].map(([phase, goal, output]) => (
                          <TableRow key={phase}>
                            <TableCell sx={{ color: "grey.300" }}>{phase}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{goal}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{output}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
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
              <Typography variant="h6">Architecture Fingerprints</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#8b5cf6" }}>Hint</TableCell>
                      <TableCell sx={{ color: "#8b5cf6" }}>Arch</TableCell>
                      <TableCell sx={{ color: "#8b5cf6" }}>Notes</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      ["Little-endian PE/ELF64 with 0x48 0x89 / 0x55 0x48", "x86-64", "Typical push rbp/mov rbp,rsp prologues"],
                      ["0x55 0x8B 0xEC", "x86-32", "push ebp/mov ebp,esp classic MSVC prologue"],
                      ["0x7f 45 4c 46, e_machine=0xb7", "AArch64", "ELF header shows arm64; look for STP/LDUR"],
                      ["Thumb2 push {r11, lr}", "ARM32", "AArch32 with 16-bit opcodes; lots of B.W/BLX"],
                      ["Dalvik opcodes (0x6e invoke-virtual)", "DEX/Android", "Use JADX/JEB; smali shows registers v0,v1,..."],
                    ].map(([hint, arch, note]) => (
                      <TableRow key={hint}>
                        <TableCell sx={{ color: "grey.300" }}>{hint}</TableCell>
                        <TableCell sx={{ color: "grey.300" }}>{arch}</TableCell>
                        <TableCell sx={{ color: "grey.300" }}>{note}</TableCell>
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

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Plugin / Extension Picks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Tool</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Plugins</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Why</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Ghidra", "FunctionID, RetDec, yara-loader", "Better library identification, extra decomp option, YARA tagging in-project"],
                          ["IDA", "Lumina, BinDiff/Diaphora, flare-emu", "Cloud sigs, diffing similar samples, emulation-driven reversing"],
                          ["Binary Ninja", "HLIL, bincfg, signature kits", "Readable IL to cut through obfuscation; fast graph views"],
                          ["x64dbg", "Scylla, TitanHide, Labeless", "Dump+fix IAT, hide debugger from anti-debug, sync with IDA/Ghidra"],
                          ["radare2/Cutter", "r2ghidra-dec, r2pipe, aep", "Decompiler integration, scripting, auto-extract packers"],
                        ].map(([tool, plug, why]) => (
                          <TableRow key={tool}>
                            <TableCell sx={{ color: "grey.300" }}>{tool}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{plug}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{why}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Platform Loadouts (Starter)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Platform</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Core</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Network/Monitor</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Memory/Unpack</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Windows", "Ghidra/IDA, x64dbg, PE-bear", "Procmon, Wireshark/FakeNet-NG, Sysmon", "Scylla, procdump, Volatility 3"],
                          ["Linux", "Ghidra/r2/objdump, GDB+GEF", "strace/ltrace, tcpdump/Wireshark", "gcore, memfd dump tools, Volatility 3"],
                          ["Android", "JEB/JADX, Apktool, Frida", "mitmproxy/adb logcat, Objection", "Frida heap dumps, jadx after dynamic decrypt"],
                        ].map(([platform, core, net, mem]) => (
                          <TableRow key={platform}>
                            <TableCell sx={{ color: "grey.300" }}>{platform}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{core}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{net}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{mem}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Practice Labs & Samples</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "crackmes.one: small binaries to practice unpacking and static analysis.",
                      "MalwareTrafficAnalysis.net: pcaps with writeups for network-focused RE.",
                      "flare-on challenges: past binaries with varied packers/obfuscation.",
                      "pwn.college / picoCTF pwn: gentle intro to exploitation + RE basics.",
                      "Android: InsecureShop/InsecureBankv2 APKs for mobile reversing practice.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Keep a clean snapshot before running community samples; do not trust challenge binaries on host OS.
                  </Alert>
                </AccordionDetails>
              </Accordion>

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
                  <Typography variant="h6">Flags & Condition Codes</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Flag</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Meaning</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Common Jumps</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["ZF (Zero)", "Result was zero", "JZ/JE (equal), JNZ/JNE (not equal)"],
                          ["CF (Carry)", "Unsigned borrow/carry", "JB/JC (below), JAE/JNC (above or equal)"],
                          ["SF (Sign)", "Result negative (signed)", "JS/JNS"],
                          ["OF (Overflow)", "Signed overflow occurred", "JO/JNO"],
                          ["PF (Parity)", "Even parity", "JP/JPE vs JNP/JPO"],
                        ].map(([flag, meaning, jumps]) => (
                          <TableRow key={flag}>
                            <TableCell sx={{ color: "grey.300" }}>{flag}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{meaning}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{jumps}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Signed vs unsigned matters: <code>JG/JL</code> use SF/OF, while <code>JA/JB</code> use CF/ZF.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Compiler/Runtime Patterns</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "MSVC x64: 32-byte shadow space on stack after prologue; look for __security_cookie usage before returns.",
                      "GCC/Clang: PLT/GOT stubs in ELF; expect RIP-relative LEA for globals (lea rax, [rip+offset]).",
                      "Go binaries: large .gopclntab, many runtime.* symbols, main.main entry; expect stack growth checks.",
                      "Rust: mangled symbols (_RNv...), panicking branches, and predictable alloc/free via alloc:: functions.",
                      "C#/.NET: PE with CLR header; use dnSpy/ILSpy; methods are IL, not native, unless ReadyToRun/AOT.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
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
                  <Typography variant="h6">Stack Frame Map (x64 System V)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`High addresses
| arg5+  |        | Extra args (stack)          |
| ret IP |        | Return address              |
| old RBP| <----  | Saved base pointer          |
| local0 |        | Locals (negative offsets)   |
| buf[ ] |        |                              
| ...    |        |                              
|        | RSP -> | 16-byte aligned before call |
Low addresses`}
                  />
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Windows x64 reserves 32 bytes of shadow space before calls; watch for it when reconstructing stack variables.
                  </Alert>
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

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Diffing & Automation Ideas</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Diff similar samples to spot patched capabilities: Diaphora/BinDiff or Ghidra function IDs.",
                      "Generate quick IOCs: hash each section, list imports/exports, and note TLS callbacks for hunting.",
                      "Automate triage with r2pipe/ghidra scripts to rename imports, dump strings, and export call graphs.",
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
                    language="bash"
                    code={`# Quick function hashing (Ghidra headless example)
analyzeHeadless . ghproj -import suspicious.exe -postScript FunctionID.java

# Export imports/strings with radare2
r2 -qc "aaa; ii; iz" suspicious.exe > quick_triage.txt

# Compare two binaries (BinDiff CLI-style)
bindiff --primary=old.bin --secondary=new.bin --output=diff.bndb`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Beginner Flow: Visual Map</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`Snapshot VM + hash sample
        |
   Quick triage (file/strings/checksec)
        |
   Ghidra import -> entry/main -> rename imports/helpers
        |
   Pick breakpoints (alloc/proc/thread/net/packer stubs)
        |
   Debug run + Procmon/pcap -> dump memory
        |
   Load dump back in Ghidra -> fix imports -> rename new funcs
        |
   Extract IOCs + config -> draft detections (YARA/Sysmon)
        |
   Write notes: what happened, where, and how to detect`}
                  />
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Move down the flow until blocked, then loop back up with new clues (addresses, strings, dumps).
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">RE Lifecycle at a Glance</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`Intake  -> Hash, classify (PE/ELF/DEX), packer hint, VT search (if allowed)
Triage -> Strings, imports, protections, sections, entropy
Static -> Disassemble/decompile, rename, map crypto/net/persistence, annotate anti-analysis
Plan   -> Decide breakpoints/hooks, inputs, safe environment (snapshot, network rules)
Dynamic-> Debug/trace, capture dumps, observe OS activity (proc/file/net/regs)
Refine -> Feed runtime findings back into static (rename, comments, types)
Report -> IOCs, config, behavior timeline, detections (YARA/Sysmon/ETW), mitigations`}
                  />
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Keep each phase timeboxed. If blocked, switch modality (static ↔ dynamic) instead of grinding in one phase.
                  </Alert>
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
                  <Typography variant="h6">Binary Layout Landmarks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Region</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>What to Read</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Follow-ups</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          [".text", "Executable code", "Huge functions, opaque jumps, inline crypto tables"],
                          [".rdata/.data", "Strings, config, globals", "UTF-16 strings, embedded URLs, mutex names, feature flags"],
                          [".rsrc", "Icons, version info, embedded blobs", "Extract with wrestool; look for secondary payloads"],
                          [".idata / imports", "Imported APIs", "Tiny table? Expect GetProcAddress loops or packing"],
                          [".reloc/.pdata", "Relocations / unwind", "Missing reloc in a supposed PIE hints packing"],
                          [".tls", "TLS callbacks", "Malware often hides early execution here; set breakpoints on callbacks"],
                          [".plt/.got (ELF)", "Dynamic linker stubs", "Resolve which functions are lazily bound at runtime"],
                        ].map(([section, contents, followup]) => (
                          <TableRow key={section}>
                            <TableCell sx={{ color: "grey.300" }}>{section}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{contents}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{followup}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Strings & Config Extraction</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Pull both ASCII and UTF-16 strings; malware often hides config in wide chars or base64 chunks.",
                      "Correlate strings with sections: URLs in .rdata but referenced from .text are high-signal.",
                      "Extract resources (icons, version, RT_RCDATA) to catch embedded second-stage payloads.",
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
                    language="bash"
                    code={`# Unicode + ASCII strings with offsets (FireEye flarestrings)
flarestrings -n 6 suspicious.exe > strings_all.txt

# Carve wide strings quickly
strings -el suspicious.exe | grep -E "(http|key|user|cmd)"

# Extract resources for config or payloads
wrestool -x suspicious.exe -o extracted_res

# ELF: note dynamic deps + runpaths
readelf -d suspicious.elf | egrep "NEEDED|RUNPATH"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">PE / ELF Quick Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Check</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Command</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Read This</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["PE: Signature + timestamp", "sigcheck -q -m suspicious.exe", "Is it signed? Is the timestamp plausible or backdated?"],
                          ["PE: Sections & entropy", "rabin2 -S suspicious.exe", "Tiny import table + high entropy often means packing"],
                          ["PE: TLS callbacks", "rabin2 -d suspicious.exe | findstr TLS", "Early execution outside main/WinMain"],
                          ["ELF: Protections", "checksec --file=./a.out", "NX/PIE/RELRO/canaries enabled?"],
                          ["ELF: Needed libs/runpath", "readelf -d ./a.out | egrep \"NEEDED|RUNPATH\"", "Unexpected RPATH/RUNPATH may indicate hijack vectors"],
                          ["ELF: Syscall table hits", "strings a.out | grep syscall", "Suspicious syscalls (ptrace, seccomp, keyctl) hint anti-debug"],
                        ].map(([item, command, read]) => (
                          <TableRow key={item}>
                            <TableCell sx={{ color: "grey.300" }}>{item}</TableCell>
                            <TableCell>
                              <code style={{ color: "#a5b4fc" }}>{command}</code>
                            </TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{read}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
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
                  <Typography variant="h6">Ghidra: Power Tips</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Batch demangle/rename imports: run \"Window > Symbol Tree > Imports\", select libs, right-click > Rename Globals to clean up decompilation.",
                      "Auto-apply data types: import common headers (Data Type Manager) so WinAPI/ELF structs render clearly; then right-click variables to apply types.",
                      "Function ID + similarity: use FunctionID or open-source signatures to tag memcpy/strcpy/etc and shrink noise.",
                      "Scripting: use \"Window > Script Manager\" to run decompiled-string exporters, function hashers, or auto-comment xrefs. Bind hotkeys to frequently used scripts.",
                      "Bookmarks & filters: set bookmarks for persistence/crypto/networking and filter the function list by size or name to find suspicious tiny wrappers.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="python"
                    code={`# Ghidra: script snippet to dump strings + xrefs
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import RefType
p = currentProgram
fman = p.getFunctionManager()
for func in fman.getFunctions(True):
    for ref in getReferencesFrom(func.getEntryPoint()):
        if ref.getReferenceType() == RefType.DATA:
            s = getDataAt(ref.getToAddress())
            if s and s.value and len(str(s.value)) > 4:
                print(func.getName(), "->", str(s.value))`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">JEB Highlights (Android/Bytecode)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "APK pipeline: open APK, JEB auto-splits into dex/resources; use \"Android Resources\" view to map IDs to layout strings quickly.",
                      "Deobfuscation helpers: rename packages/classes in bulk via refactor, then propagate; use \"Type Editor\" to fix method signatures for clean decompiles.",
                      "Control flow: switch between Java/Kotlin decompilation and CFG to spot opaque predicates or reflection-heavy code.",
                      "String resolution: enable advanced string decryption plugins and inspect initialized arrays in smali; JEB shows inlined values in decompiled view.",
                      "Native bridges: follow JNI exports under \"Native Libraries\"; use the bridge view to jump from Java to native symbol stubs.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="text"
                    code={`JEB views to prioritize:
- Java decompilation + CFG side-by-side
- Smali for reflection/crypto constants
- Android Resources to decode strings/layout IDs
- Native Libraries for JNI exports/bridges
- Project Search: find URL/user-agent strings or crypto seeds`}
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
                  <Typography variant="h6">Pattern Hunts & Heuristics</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Pattern</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Why It Matters</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Where to Look</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["API hashing loops", "Evasion; resolves imports dynamically", "Tight loops over DWORDs near GetProcAddress"],
                          ["RC4/Salsa20 tables", "Config or payload decryption", "256-byte tables and swap loops in init functions"],
                          ["Base64 alphabet", "Command channels or config blobs", "Look for 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'"],
                          ["Single-call wrappers", "Obfuscation of key APIs", "Tiny functions wrapping VirtualAlloc/WriteFile/etc"],
                          ["Opaque predicates", "Control-flow flattening noise", "Repeating cmp/test with constant outcomes or junk jumps"],
                        ].map(([pattern, why, where]) => (
                          <TableRow key={pattern}>
                            <TableCell sx={{ color: "grey.300" }}>{pattern}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{why}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{where}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Entropy & Obfuscation Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "High entropy (>7.2) sections suggest packing or encryption; map them to virtual addresses for dynamic breakpoints.",
                      "Compare .text entropy to .rdata/.data; only one noisy section is a packer hint.",
                      "Self-modifying code often writes to current module then flips protections (PAGE_EXECUTE_READWRITE to PAGE_EXECUTE_READ).",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="python"
                    code={`# Quick section entropy (pefile)
import pefile, math, sys
pe = pefile.PE(sys.argv[1])
def entropy(data):
    import math
    if not data: return 0
    probs = [float(data.count(x))/len(data) for x in set(data)]
    return -sum(p * math.log(p, 2) for p in probs)
for s in pe.sections:
    print(f\"{s.Name.strip()}: {entropy(s.get_data()):.2f} size={s.SizeOfRawData}\")`}
                  />
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
                  <Typography variant="h6">Pre-Run Safety Checklist</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Snapshot the VM and disable shared folders/clipboard; keep a clean revert point.",
                      "Set network to Host-only/NAT with outbound block unless you intentionally observe C2.",
                      "Stage tools (x64dbg/WinDbg/GDB/ProcMon/Wireshark) and configure symbol paths before execution.",
                      "Copy the sample to a working directory and mark the original read-only; record SHA-256.",
                      "Decide inputs/arguments and logging paths up front to avoid reruns after self-deletion.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
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
                  <Typography variant="h6">Network Containment & Capture</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Prefer host-only or NAT with outbound blocks; allow outbound only when intentionally sinkholing.",
                      "Use loopback DNS overrides to redirect C2 to safe hosts (FakeNet-NG/INetSim) instead of real internet.",
                      "Capture traffic even when blocked; TLS ClientHello metadata, JA3/JA4, and SNI are still valuable for IOCs.",
                      "If you must observe live C2, route through an isolated VPN and record pcap + logs for replay.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="bash"
                    code={`# Simulate network + capture safely
fakenet-ng -q                      # Auto-respond to common protocols
tcpdump -i any -nn -w sample.pcap  # Capture for later replay

# MitM / inspection when you control certs
mitmproxy --mode transparent --listen-port 8080

# Windows firewall one-liners (as admin)
netsh advfirewall firewall add rule name="block_all_out" dir=out action=block program="sample.exe"`}
                  />
                </AccordionDetails>
              </Accordion>

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
                  <Typography variant="h6">High-Value Breakpoints</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Target</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Why</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Examples</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Process/thread creation", "Catch process hollowing or staging", "CreateProcessW, CreateRemoteThread, NtCreateThreadEx"],
                          ["Memory allocation/protection", "Find unpacked payload staging", "VirtualAlloc/VirtualProtect, NtAllocateVirtualMemory"],
                          ["Import resolution", "Locate dynamic API loading", "GetProcAddress, LdrGetProcedureAddress, dlopen + dlsym"],
                          ["Network I/O", "Capture plaintext configs or beacons", "connect, send/recv, InternetOpenUrl, WinHttpSendRequest"],
                          ["Anti-debug toggles", "Stop self-defense early", "IsDebuggerPresent, CheckRemoteDebuggerPresent, ptrace, prctl"],
                        ].map(([target, why, examples]) => (
                          <TableRow key={target}>
                            <TableCell sx={{ color: "grey.300" }}>{target}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{why}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{examples}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
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
                  <Typography variant="h6">Anti-Debug / Anti-VM Signals</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Check</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Purpose</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Quick Response</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["IsDebuggerPresent/CheckRemoteDebuggerPresent", "Detect attached debugger", "Patch return to 0 or breakpoint and flip flag"],
                          ["QueryPerformanceCounter loops", "Timing anti-debug", "Set conditional break or force constant return values"],
                          ["RDTSC/RDTSCP deltas", "Detect single-stepping", "Replace with NOPs or hardware breakpoints to reduce skew"],
                          ["VM artifact checks", "Detect sandbox/VM", "Patch string comparisons for MAC/vendor, mask registry keys"],
                          ["ptrace/prctl/SECCOMP", "Block debuggers on Linux", "Intercept and force success (0) before enforcement"],
                        ].map(([check, purpose, response]) => (
                          <TableRow key={check}>
                            <TableCell sx={{ color: "grey.300" }}>{check}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{purpose}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{response}</TableCell>
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

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Logging & Timeline Capture</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Signal</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Tool</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Notes</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Process/Thread starts", "Sysmon EID 1/8 or Procmon", "Command line, parent PID, integrity level"],
                          ["Network connects", "Sysmon EID 3 + pcap", "Capture dest IP/SNI/JA3; correlate with timing"],
                          ["Image loads", "Sysmon EID 7", "DLL sideloading or LOLBins used for staging"],
                          ["Registry writes", "Sysmon EID 13", "Persistence keys (Run/Services/IFEO/AppInit_DLLs)"],
                          ["File drops", "Sysmon EID 11", "Payload staging paths and temp file churn"],
                        ].map(([signal, tool, notes]) => (
                          <TableRow key={signal}>
                            <TableCell sx={{ color: "grey.300" }}>{signal}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{tool}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{notes}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <CodeBlock
                    language="bash"
                    code={`# Procmon: save PML with filters
procmon.exe /Quiet /Minimized /BackingFile log.pml /LoadConfig malware.pmc

# Sysmon: quick config (SwiftOnSecurity) then convert to CSV
sysmon -c sysmonconfig-export.xml
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:text > sysmon.txt

# ETW trace (kernel process/thread/file) minimal
logman start re_trace -p \"Microsoft-Windows-Kernel-Process\" 0x10 -p \"Microsoft-Windows-Kernel-File\" 0x10 -ets
logman stop re_trace -ets`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Runtime Dumping & Unpacking</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Windows: dump process memory
procdump.exe -ma <pid> dumped.dmp        # Full memory
scylla_x64.exe                           # Rebuild imports after dumping

# WinDbg: dump unpacked region
.writemem unpacked.bin 0x00007ff700000000 L?0x200000

# Linux: gcore live process
gcore $(pidof suspicious)                # Creates core.<pid>
objdump -d core.<pid> | head

# x64dbg: dump module and fix IAT
# (Dump memory -> Scylla: Get Imports -> Fix Dump)`}
                  />
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Capture dumps right after decryption/allocations; match regions to <code>.text</code> sizes to avoid grabbing only the packer stub.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Memory Forensics (Volatility 3)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Hunt injected code: scan for PAGE_EXECUTE_READWRITE regions and anomalous modules.",
                      "Extract configs from dumped processes; grep decoded strings before they are re-encrypted.",
                      "Correlate network sockets to owning PIDs to link traffic back to unpacked modules.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="bash"
                    code={`# Common Volatility 3 passes
vol.py -f mem.dmp windows.pslist
vol.py -f mem.dmp windows.malfind --dump
vol.py -f mem.dmp windows.netscan
vol.py -f mem.dmp windows.cmdline
vol.py -f mem.dmp windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Frida Hooks & Instrumentation</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="javascript"
                    code={`// Log network endpoints (Windows)
const sendPtr = Module.getExportByName("ws2_32.dll", "send");
Interceptor.attach(sendPtr, {
  onEnter(args) {
    const len = args[2].toInt32();
    const buf = args[1].readByteArray(Math.min(len, 256));
    console.log("send()", len, buf);
  },
});

// Trace dynamic API resolution
["LoadLibraryA", "GetProcAddress"].forEach((name) => {
  const ptr = Module.getExportByName("kernel32.dll", name);
  Interceptor.attach(ptr, {
    onEnter(args) {
      console.log(name, args[0].readCString());
    },
  });
});`}
                  />
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Use Frida on user-mode samples to collect decrypted configs without stepping through every branch; combine with ProcMon/Wireshark captures.
                  </Alert>
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
                    "1) Prep: snapshot VM, disable shared folders/clipboard, hash the sample, and copy it into a working folder (keep original read-only).",
                    "2) Quick triage (10–15m): run file/strings/checksec/rabin2 -I; collect obvious URLs, mutexes, import hints, and packer clues.",
                    "3) Ghidra pass (15–25m): import, auto-analyze, jump to entry/main, rename imports and obvious helpers, bookmark suspected net/crypto/persistence funcs.",
                    "4) Make a breakpoint plan: pick VirtualAlloc/WriteProcessMemory/CreateProcess/CreateRemoteThread + any packer-specific addresses from entropy/strings.",
                    "5) Dynamic run (20–30m): attach x64dbg/WinDbg, set breakpoints, log with .logopen or Procmon+pcap; capture a dump right after unpack/decrypt.",
                    "6) Loop back to static (15–20m): load the dump in Ghidra/PE-bear, rebuild imports if needed, and rename newly revealed functions/strings.",
                    "7) Extract outputs (10–15m): IOC table (hashes, URLs, mutexes), behavior summary (injection/persistence/network), and a draft YARA/Sysmon idea.",
                    "8) Timebox: if blocked after 60–90 minutes, switch modality (static ↔ dynamic) or write down open questions before continuing.",
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

              <Accordion sx={{ mt: 3 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Timeboxing & Depth</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "30-minute triage: file type, packer hint, key strings, import map, quick YARA/IOCs; decide if worth deeper dive.",
                      "2-hour deep dive: decompile entry/main + key subsystems (net/crypto/persistence), map anti-analysis, prep breakpoints.",
                      "Long-form analysis: unpack, document control flow, extract config, and produce detections; only if impact justifies effort.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Track elapsed time; if you are stuck, switch modality (static ↔ dynamic) instead of digging the same hole.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Reporting & Deliverables</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Executive: 5–8 sentence summary, impact, and recommended mitigations.",
                      "Technical: behavior narrative (lifecycle), IOC table (hashes, URLs, mutexes), config values, and packer/unpacker notes.",
                      "Detection: YARA (config strings, crypto constants), Sysmon/ETW ideas (process+net), Suricata/Zeek leads from pcaps.",
                      "Repro: commands to reproduce sandbox run, breakpoints used, and hashes/paths of dumps or unpacked payloads.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.35 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Notebook Template (copy/paste)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`Sample: <hash> | Path: <vm path> | Date: <utc>
Target: <PE/ELF/APK> arch: <x64/x86/arm> packer?: <y/n clue>

Triage:
- file/checksec: <>
- strings (top hits): <>
- imports/libs: <>
- TLS callbacks?: <>

Static notes:
- entry/main: <addr> summary
- interesting funcs: <addr -> name/purpose>
- suspected crypto/net/persistence: <>
- anti-analysis found: <>

Dynamic run:
- debugger + breakpoints: <>
- proc/file/reg events: <>
- net: dest IP/SNI/JA3, ports
- dumps captured: <path/hash> (fixed imports? y/n)

Outputs:
- IOCs: hashes/urls/mutex/registry/paths
- config: <>
- detection ideas: YARA strings/constants, Sysmon/ETW events
- open questions: <>`}
                  />
                </AccordionDetails>
              </Accordion>

              <Paper sx={{ p: 3, bgcolor: "#0f1028", borderRadius: 2, mt: 3 }}>
                <Typography variant="h6" sx={{ color: "#8b5cf6", mb: 2 }}>
                  Beginner Lab Scenario (Step-by-Step)
                </Typography>
                <List dense>
                  {[
                    "Grab a small, known-safe crackme (x86-64, no packing). Hash it and record the SHA-256.",
                    "Static pass: run file/checksec/strings; open in Ghidra, auto-analyze, and rename main/obvious helpers.",
                    "Find the comparison logic: look for strcmp/memcmp or hardcoded strings; set comments on key branches.",
                    "Plan dynamic run: break on strcmp/memcmp or on the function that reads input; note addresses.",
                    "Run under GDB/x64dbg with sample input; step until the check; dump any decoded strings or computed keys.",
                    "Patch or script: change a conditional jump (e.g., JNE -> JE) or write a Python solver based on discovered logic.",
                    "Document: input format, success condition, and the exact bytes/addresses you patched or traced.",
                  ].map((item, idx) => (
                    <ListItem key={item} sx={{ py: 0.4 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <Chip label={idx + 1} size="small" sx={{ bgcolor: "#8b5cf6", color: "#fff", minWidth: 24, height: 20 }} />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
                <Alert severity="info" sx={{ mt: 1 }}>
                  Focus on building habits: rename functions, add comments, and keep notes on addresses and decisions. Speed comes later.
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
