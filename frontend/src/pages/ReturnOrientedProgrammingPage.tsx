import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
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
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Alert,
  AlertTitle,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import LockIcon from "@mui/icons-material/Lock";
import TuneIcon from "@mui/icons-material/Tune";
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
        bgcolor: "#101626",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(37, 99, 235, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#2563eb", color: "#0b1020" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#e2e8f0" }}>
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
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const ReturnOrientedProgrammingPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const objectives = [
    "Explain Return-Oriented Programming (ROP) in simple terms.",
    "Show why memory bugs can lead to control-flow abuse.",
    "Identify common entry points and real-world risk areas.",
    "Recognize detection signals and safe triage steps.",
    "Apply prevention and hardening practices for ROP risks.",
  ];
  const beginnerPath = [
    "1) Read the beginner explanation and glossary.",
    "2) Learn the basics of the stack and return addresses.",
    "3) Review how ROP chains reuse existing code.",
    "4) Study detection signals and response steps.",
    "5) Apply the mitigation and hardening checklist.",
  ];
  const keyIdeas = [
    "ROP reuses existing code fragments instead of injecting new code.",
    "It usually appears when memory safety bugs allow control of returns.",
    "Modern defenses raise the cost, but do not replace safe coding.",
    "The best fix is to prevent memory corruption in the first place.",
  ];
  const glossary = [
    { term: "Stack", desc: "A memory region that stores function call data." },
    { term: "Return address", desc: "Where execution continues after a function ends." },
    { term: "Gadget", desc: "A short code sequence ending in a return instruction." },
    { term: "DEP/NX", desc: "Marks memory as non-executable to block injected code." },
    { term: "ASLR", desc: "Randomizes memory locations to make addresses harder to guess." },
    { term: "CFI", desc: "Control-flow integrity, restricts invalid jumps." },
  ];
  const misconceptions = [
    {
      myth: "ROP only matters to experts.",
      reality: "It is a common outcome of basic memory bugs.",
    },
    {
      myth: "DEP/NX stops all code execution attacks.",
      reality: "ROP can reuse existing executable code.",
    },
    {
      myth: "ASLR alone prevents ROP.",
      reality: "Address leaks or weak randomization can bypass it.",
    },
  ];

  const memoryBasics = [
    "Functions store a return address on the stack.",
    "If a buffer overflow overwrites that address, execution changes.",
    "DEP/NX blocks new code from running in data memory.",
    "ROP chains small instruction sequences that already exist in memory.",
    "Each return jumps to the next gadget, forming a chain.",
  ];
  const coreConcepts = [
    {
      concept: "Return addresses",
      meaning: "Saved locations that tell the CPU where to go next.",
      whyItMatters: "If overwritten, control flow can be hijacked.",
    },
    {
      concept: "Gadgets",
      meaning: "Existing code snippets ending in a return.",
      whyItMatters: "They can be chained to perform complex actions.",
    },
    {
      concept: "Calling convention",
      meaning: "Rules for passing arguments and using the stack.",
      whyItMatters: "ROP chains must align with these rules.",
    },
    {
      concept: "Non-executable memory",
      meaning: "Data pages cannot be executed as code.",
      whyItMatters: "Forces attackers to reuse existing code.",
    },
    {
      concept: "Address randomization",
      meaning: "Memory locations change between runs.",
      whyItMatters: "Harder to predict gadget addresses.",
    },
  ];
  const whereItShowsUp = [
    "C/C++ services handling untrusted input.",
    "Legacy libraries without modern compiler flags.",
    "Custom network parsers or binary protocols.",
    "Device firmware or IoT services with limited updates.",
    "Plugin ecosystems that load third-party code.",
  ];
  const attackFlow = [
    "A memory bug allows overwriting data on the stack or heap.",
    "The return address is corrupted to redirect execution.",
    "The program begins executing short existing code sequences.",
    "Each gadget ends in a return, moving to the next gadget.",
    "The chain completes a goal like calling a function safely.",
  ];
  const impactAreas = [
    "Remote code execution in vulnerable services.",
    "Bypass of memory protections like DEP/NX.",
    "Privilege escalation in low-level components.",
    "Denial of service from crashes or corrupted state.",
  ];

  const detectionSignals = [
    "Crashes with instruction pointers inside unexpected modules.",
    "Return addresses that land on small instruction sequences.",
    "Repeated crashes with similar stack patterns.",
    "Unusual fault addresses near executable memory regions.",
    "Spike in access violations after malformed input.",
  ];
  const telemetrySources = [
    "Crash reports and minidumps.",
    "EDR alerts for exploit-like behavior.",
    "Application logs around parsing failures.",
    "System logs for access violations.",
    "Vulnerability scanners highlighting unsafe code paths.",
  ];
  const baselineMetrics = [
    {
      metric: "Crash rate by endpoint",
      normal: "Low and stable across typical inputs.",
      investigate: "Sudden spikes after new traffic patterns.",
    },
    {
      metric: "Parser error rate",
      normal: "Stable within expected ranges.",
      investigate: "Large jump in malformed input errors.",
    },
    {
      metric: "Memory fault types",
      normal: "Occasional benign crashes only.",
      investigate: "New access violation patterns.",
    },
  ];
  const triageSteps = [
    "Identify the endpoint and input that triggered the crash.",
    "Collect crash dumps and stack traces.",
    "Check for overwrites of return addresses.",
    "Confirm whether DEP/NX and ASLR are enabled.",
    "Search for known vulnerable functions in the code path.",
  ];
  const responseSteps = [
    "Disable or rate limit the vulnerable endpoint.",
    "Patch the memory bug and add bounds checks.",
    "Rebuild with hardening flags enabled.",
    "Roll out updated binaries and verify mitigations.",
    "Add regression tests for the offending inputs.",
  ];

  const preventionChecklist = [
    "Fix memory safety bugs (bounds checks and safe APIs).",
    "Enable DEP/NX, ASLR, and stack canaries.",
    "Use compiler hardening flags consistently.",
    "Adopt Control-Flow Integrity where possible.",
    "Reduce attack surface by removing unused code.",
    "Prefer memory-safe languages for new components.",
  ];
  const secureCodingPatterns = [
    "Prefer length-checked functions and safe wrappers.",
    "Validate input size before copying or parsing.",
    "Avoid manual memory management when possible.",
    "Use fuzzing to catch crashes early.",
  ];
  const mitigationsTable = [
    {
      mitigation: "DEP/NX",
      purpose: "Prevents executing code in data memory.",
      limitation: "Does not stop reuse of existing code.",
    },
    {
      mitigation: "ASLR",
      purpose: "Randomizes memory layout.",
      limitation: "Leaks can reveal addresses.",
    },
    {
      mitigation: "Stack canaries",
      purpose: "Detects stack buffer overwrites.",
      limitation: "May be bypassed in some cases.",
    },
    {
      mitigation: "CFI",
      purpose: "Restricts invalid control-flow transitions.",
      limitation: "Coverage varies by compiler and runtime.",
    },
    {
      mitigation: "Shadow stack",
      purpose: "Separates real return addresses from writable stack.",
      limitation: "Requires hardware or OS support.",
    },
  ];
  const buildFlags = `# Linux hardening flags (example)
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
-fPIE -pie
-Wl,-z,relro,-z,now
-Wl,-z,noexecstack`;
  const platformDefenses = [
    {
      platform: "Windows",
      controls: "DEP, ASLR, CFG (/guard:cf), CET Shadow Stack",
    },
    {
      platform: "Linux",
      controls: "ASLR, NX, PIE, RELRO, stack canaries",
    },
    {
      platform: "macOS",
      controls: "ASLR, hardened runtime, pointer authentication",
    },
  ];

  const codeReviewChecklist = [
    "Search for unsafe C functions and manual buffer copies.",
    "Check for missing bounds checks in parsers.",
    "Verify build flags and linker options.",
    "Ensure crash reports are collected and reviewed.",
    "Review third-party libraries for memory safety issues.",
  ];
  const codeReviewCommands = `# Search for risky C functions
rg -n "strcpy|strcat|gets\\(|sprintf|scanf\\(|memcpy|memmove" src

# Search for manual buffer arithmetic
rg -n "\\+\\+|--|\\[.*\\]" src`;

  const labSteps = [
    "Use a safe demo app or test binary in a lab.",
    "Trigger a controlled crash with oversized input.",
    "Inspect the stack trace and note the fault address.",
    "Check if DEP/NX and ASLR are enabled.",
    "Document mitigations and rebuild with hardening flags.",
  ];
  const verificationChecklist = [
    "Memory bugs are fixed and tested.",
    "Binaries are built with stack protection and PIE.",
    "DEP/NX and ASLR are enabled in production.",
    "Crash handling and reporting are in place.",
    "Fuzzing is part of the release process.",
  ];
  const safeBoundaries = [
    "Only test in a lab or with written authorization.",
    "Avoid exploit development in production environments.",
    "Use non-sensitive sample inputs and data.",
    "Focus on detection and mitigation improvements.",
  ];

  const pageContext = `This page explains Return-Oriented Programming (ROP), a technique that exploits memory corruption vulnerabilities by chaining existing code fragments (gadgets) to perform malicious actions. Topics include understanding the stack and return addresses, how ROP bypasses DEP/NX protections, detection signals and triage steps, and mitigation strategies like ASLR, stack canaries, CFI, and shadow stacks. The guide focuses on defensive learning and prevention practices.`;

  return (
    <LearnPageLayout pageTitle="Return-Oriented Programming (ROP)" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <MemoryIcon sx={{ fontSize: 42, color: "#2563eb" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #2563eb 0%, #38bdf8 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Return-Oriented Programming (ROP)
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          A beginner-friendly deep dive into how ROP works and how to reduce the risk.
        </Typography>

        <Alert severity="warning" sx={{ mb: 3 }}>
          <AlertTitle>Defensive Learning Only</AlertTitle>
          This content focuses on prevention, detection, and safe engineering practices.
        </Alert>

        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Return-Oriented Programming, or ROP, is a technique that abuses how programs return from functions.
            When a function finishes, it jumps back to a return address stored on the stack. If a memory bug lets
            an attacker overwrite that address, the program can be redirected to run other pieces of code.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Modern systems often block running new code inside data memory using protections like DEP or NX.
            ROP works around that by reusing code that already exists in the program or its libraries. Think of
            it like cutting a movie into tiny clips and then splicing those clips together to create a new scene.
            Each clip is a small sequence of instructions that ends with a return.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            For beginners, the key idea is simple: ROP is not a separate bug, it is a way to exploit memory bugs.
            If you prevent buffer overflows and other memory corruption issues, you prevent ROP. Mitigations like
            ASLR, stack canaries, and CFI raise the difficulty, but safe coding remains the real fix.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            This page explains the concept, where it shows up in real systems, how to detect warning signs, and
            how to apply practical hardening steps that reduce ROP risk.
          </Typography>
        </Paper>

        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<MemoryIcon />} label="Stack" size="small" />
          <Chip icon={<CodeIcon />} label="Gadgets" size="small" />
          <Chip icon={<SearchIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Mitigations" size="small" />
          <Chip icon={<BuildIcon />} label="Hardening" size="small" />
        </Box>

        <Paper sx={{ bgcolor: "#111826", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#2563eb" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<TuneIcon />} label="Foundations" />
            <Tab icon={<MemoryIcon />} label="Attack Flow" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<ShieldIcon />} label="Defenses" />
            <Tab icon={<BuildIcon />} label="Safe Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {objectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Key Ideas
                </Typography>
                <List dense>
                  {keyIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Term</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Meaning</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {glossary.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(37, 99, 235, 0.25)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#2563eb", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#38bdf8", mb: 0.5 }}>
                          Reality
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {item.reality}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Memory Basics for ROP
                </Typography>
                <List dense>
                  {memoryBasics.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Core Concepts
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Concept</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Meaning</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Why It Matters</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {coreConcepts.map((item) => (
                        <TableRow key={item.concept}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.concept}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.meaning}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.whyItMatters}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Where ROP Shows Up
                </Typography>
                <List dense>
                  {whereItShowsUp.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  High-Level Attack Flow (Conceptual)
                </Typography>
                <List dense>
                  {attackFlow.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Impact Areas
                </Typography>
                <List dense>
                  {impactAreas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <BugReportIcon color="error" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Detection Signals
                </Typography>
                <List dense>
                  {detectionSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Telemetry Sources
                </Typography>
                <List dense>
                  {telemetrySources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Baseline Metrics
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Metric</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Normal</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Investigate When</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {baselineMetrics.map((item) => (
                        <TableRow key={item.metric}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.metric}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.normal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.investigate}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Quick Triage Steps
                </Typography>
                <List dense>
                  {triageSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mt: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Response Steps (Defensive)
                </Typography>
                <List dense>
                  {responseSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Prevention Checklist
                </Typography>
                <List dense>
                  {preventionChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Secure Coding Patterns
                </Typography>
                <List dense>
                  {secureCodingPatterns.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Mitigations Overview
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Mitigation</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Purpose</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Limitations</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {mitigationsTable.map((item) => (
                        <TableRow key={item.mitigation}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.mitigation}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.purpose}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.limitation}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Build Hardening Flags (Example)
                </Typography>
                <CodeBlock code={buildFlags} language="text" />
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Platform Defenses
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Platform</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Controls</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {platformDefenses.map((item) => (
                        <TableRow key={item.platform}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.platform}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.controls}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Extra Hardening Tips
                </Typography>
                <List dense>
                  {[
                    "Turn on crash reporting and monitor for anomalies.",
                    "Harden third-party libraries or replace them.",
                    "Segment high-risk parsers into separate processes.",
                    "Remove unused features to reduce gadget surface.",
                    "Practice secure patching and regular updates.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <LockIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Safe Lab Walkthrough
                </Typography>
                <List dense>
                  {labSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Code Review Checklist
                </Typography>
                <List dense>
                  {codeReviewChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2, mb: 3 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Code Search Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={codeReviewCommands} language="bash" />
                </AccordionDetails>
              </Accordion>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Verification Checklist
                </Typography>
                <List dense>
                  {verificationChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Safe Boundaries
                </Typography>
                <List dense>
                  {safeBoundaries.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#2563eb", color: "#2563eb" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default ReturnOrientedProgrammingPage;
