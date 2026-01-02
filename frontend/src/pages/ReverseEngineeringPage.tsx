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
  Card,
  CardContent,
  Divider,
  alpha,
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
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import AndroidIcon from "@mui/icons-material/Android";
import StorageIcon from "@mui/icons-material/Storage";
import VisibilityIcon from "@mui/icons-material/Visibility";
import LayersIcon from "@mui/icons-material/Layers";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import PestControlIcon from "@mui/icons-material/PestControl";
import DeveloperBoardIcon from "@mui/icons-material/DeveloperBoard";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import RouterIcon from "@mui/icons-material/Router";
import AppleIcon from "@mui/icons-material/Apple";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import ExtensionIcon from "@mui/icons-material/Extension";
import { useNavigate, Link } from "react-router-dom";

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

  const pageContext = `This page covers reverse engineering fundamentals and VRAgent's RE Hub capabilities including:
- VRAgent RE Hub: Binary Analysis (PE/ELF/DLL/SO), Unified APK Scanning, and Docker Inspector (layer risk + secrets)
- Ghidra integration for decompilation, Capstone for disassembly, YARA for signature matching, and fuzzy hashing
- AI-powered analysis with Google Gemini, vulnerability hunt results, attack surface mapping, and exportable reports
- What reverse engineering is and when to use it
- Essential RE tools: Ghidra, IDA Pro, Binary Ninja, radare2, x64dbg, GDB
- x86/x64 assembly language fundamentals
- Static analysis techniques and disassembly
- Dynamic analysis and debugging workflows
- Malware analysis techniques: unpacking, config extraction, behavioral analysis
- Mobile RE: Android APK reversing, iOS app analysis, Frida hooking
- Embedded systems and firmware analysis
- Complete RE workflow from binary to understanding`;

  return (
    <LearnPageLayout pageTitle="Reverse Engineering" pageContext={pageContext}>
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
            sx={{ borderRadius: 2, mb: 3 }}
          />
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

        {/* VRAgent RE Hub Capabilities */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.15)} 0%, ${alpha("#a855f7", 0.1)} 50%, ${alpha("#7c3aed", 0.05)} 100%)`,
            border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <RocketLaunchIcon sx={{ fontSize: 32, color: "#a855f7" }} />
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0" }}>
              VRAgent RE Hub Capabilities
            </Typography>
          </Box>
          
          <Typography variant="body1" sx={{ color: "grey.400", mb: 3 }}>
            VRAgent's Reverse Engineering Hub provides automated analysis powered by AI and industry tools.
            Upload binaries, APKs, or Docker images for instant security insights.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              {
                title: "Binary Analysis",
                icon: <MemoryIcon />,
                color: "#8b5cf6",
                capabilities: [
                  "Unified binary scan with metadata, packer flags, and indicators",
                  "Ghidra decompilation with AI function summaries",
                  "Strings, imports/exports, and section/entropy insights",
                  "YARA matches + fuzzy hashes (ssdeep, TLSH)",
                  "Optional vulnerability hunt with risk scoring",
                ],
              },
              {
                title: "APK Analysis",
                icon: <AndroidIcon />,
                color: "#22c55e",
                capabilities: [
                  "11-Phase UnifiedApkScanner with progress tracking",
                  "JADX decompilation with manifest/permission review",
                  "Attack surface map for exported components",
                  "Obfuscation analysis with crypto/secret checks",
                  "Certificate and signature analysis (v1/v2/v3)",
                  "AI functionality, security, and privacy reports",
                ],
              },
              {
                title: "Docker Inspector",
                icon: <LayersIcon />,
                color: "#06b6d4",
                capabilities: [
                  "Layer command inventory with size breakdown",
                  "Secrets detected in layer commands and metadata",
                  "Attack-vector categories (escape, priv-esc, lateral)",
                  "Risk score with critical/high counts + base image",
                  "AI security analysis and report saving",
                ],
              },
              {
                title: "AI-Powered Insights",
                icon: <SmartToyIcon />,
                color: "#f59e0b",
                capabilities: [
                  "Gemini analysis across binaries, APKs, and Docker",
                  "Attack surface maps and threat modeling outputs",
                  "Enhanced security scans and AI vulnerability findings",
                  "Guided walkthrough and interactive AI chat",
                  "Exportable reports (Markdown/PDF/DOCX) and sharing",
                ],
              },
            ].map((feature) => (
              <Grid item xs={12} md={6} key={feature.title}>
                <Card
                  sx={{
                    height: "100%",
                    bgcolor: alpha(feature.color, 0.1),
                    border: `1px solid ${alpha(feature.color, 0.3)}`,
                    borderRadius: 2,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                      <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e0e0e0" }}>
                        {feature.title}
                      </Typography>
                    </Box>
                    <List dense disablePadding>
                      {feature.capabilities.map((cap, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: feature.color }} />
                          </ListItemIcon>
                          <ListItemText
                            primary={cap}
                            primaryTypographyProps={{ variant: "body2", sx: { color: "grey.300" } }}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 2, borderColor: alpha("#8b5cf6", 0.2) }} />

          {/* Key Stats */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { value: "3", label: "Analysis Types", color: "#8b5cf6" },
              { value: "11", label: "APK Scan Phases", color: "#22c55e" },
              { value: "AI", label: "Powered Analysis", color: "#f59e0b" },
              { value: "500+", label: "Ghidra Functions", color: "#06b6d4" },
            ].map((stat, idx) => (
              <Grid item xs={6} sm={3} key={idx}>
                <Box sx={{ textAlign: "center", py: 1 }}>
                  <Typography variant="h5" sx={{ fontWeight: 800, color: stat.color }}>
                    {stat.value}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "grey.500" }}>
                    {stat.label}
                  </Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Button
              variant="contained"
              startIcon={<RocketLaunchIcon />}
              component={Link}
              to="/reverse-engineering"
              sx={{
                background: "linear-gradient(135deg, #8b5cf6 0%, #a855f7 100%)",
                fontWeight: 600,
                "&:hover": {
                  background: "linear-gradient(135deg, #7c3aed 0%, #9333ea 100%)",
                },
              }}
            >
              Launch RE Hub
            </Button>
            <Button
              variant="outlined"
              startIcon={<MemoryIcon />}
              component={Link}
              to="/learn/binary-analysis"
              sx={{
                borderColor: alpha("#8b5cf6", 0.5),
                color: "#a855f7",
                "&:hover": {
                  borderColor: "#8b5cf6",
                  bgcolor: alpha("#8b5cf6", 0.1),
                },
              }}
            >
              Binary Analysis Guide
            </Button>
          </Box>
        </Paper>

        {/* Educational Content Tabs */}
        <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
          <SchoolIcon sx={{ color: "#8b5cf6" }} />
          Reverse Engineering Fundamentals
        </Typography>

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

              {/* Beginner-Friendly Introduction */}
              <Paper sx={{ p: 3, bgcolor: "#0f1024", borderRadius: 2, mb: 3, border: "1px solid rgba(139,92,246,0.2)" }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <SchoolIcon /> Understanding RE: The Car Mechanic Analogy
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Imagine you find an old car with no manual, no documentation, and a sealed engine compartment. 
                  You want to understand how it works, fix problems, or modify it. That's essentially reverse engineering:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { analogy: "Opening the hood", re: "Disassembling a binary", desc: "Seeing the internal components/instructions" },
                    { analogy: "Tracing wires", re: "Following code flow", desc: "Understanding how parts connect and communicate" },
                    { analogy: "Testing the ignition", re: "Dynamic analysis", desc: "Running the program to observe behavior" },
                    { analogy: "Reading part numbers", re: "Identifying libraries/APIs", desc: "Recognizing known components and their purposes" },
                    { analogy: "Documenting your findings", re: "Annotating code", desc: "Building understanding through notes and labels" },
                  ].map((item, idx) => (
                    <Grid item xs={12} sm={6} md={4} key={idx}>
                      <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.08), borderRadius: 1, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ color: "#a855f7", fontWeight: 700 }}>
                          {item.analogy} → {item.re}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mt: 0.5 }}>
                          {item.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* What You'll Learn */}
              <Paper sx={{ p: 3, bgcolor: "#101124", borderRadius: 2, mb: 3, border: "1px solid rgba(34,197,94,0.2)" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2 }}>
                  🎯 What You'll Learn in This Guide
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { skill: "Read assembly code", time: "2-4 weeks", desc: "Understand what CPU instructions mean and recognize patterns" },
                    { skill: "Use disassemblers", time: "1-2 weeks", desc: "Navigate Ghidra/IDA to analyze binaries" },
                    { skill: "Identify functions", time: "2-3 weeks", desc: "Find main(), entry points, and key code sections" },
                    { skill: "Debug programs", time: "2-3 weeks", desc: "Set breakpoints, step through code, examine memory" },
                    { skill: "Recognize malware", time: "3-4 weeks", desc: "Spot suspicious APIs, injection, and persistence" },
                    { skill: "Write detections", time: "4-6 weeks", desc: "Create YARA rules and behavioral signatures" },
                  ].map((item, idx) => (
                    <Grid item xs={12} sm={6} md={4} key={idx}>
                      <Box sx={{ p: 1.5 }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 600 }}>
                          ✓ {item.skill}
                        </Typography>
                        <Chip label={item.time} size="small" sx={{ mt: 0.5, mb: 0.5, bgcolor: alpha("#22c55e", 0.15) }} />
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {item.desc}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

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

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Static vs Dynamic vs Hybrid (Explained Simply)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    {[
                      {
                        title: "Static Analysis",
                        icon: "🔬",
                        color: "#8b5cf6",
                        analogy: "Like examining a car without starting the engine",
                        what: "Looking at code without running it",
                        pros: ["Safe - malware can't execute", "See everything at once", "No environment needed"],
                        cons: ["Can't see runtime values", "Packed code is unreadable", "Anti-analysis tricks hide code"],
                        when: "Start here for initial triage and to plan your dynamic approach",
                      },
                      {
                        title: "Dynamic Analysis",
                        icon: "🏃",
                        color: "#22c55e",
                        analogy: "Like test-driving the car and watching the gauges",
                        what: "Running code and observing behavior",
                        pros: ["See actual execution", "Unpacks itself for you", "Real API calls revealed"],
                        cons: ["Risky with malware", "Might miss code paths", "Environment-dependent"],
                        when: "Use when static analysis hits packed/encrypted code or you need runtime values",
                      },
                      {
                        title: "Hybrid Approach",
                        icon: "🔄",
                        color: "#f59e0b",
                        analogy: "Like alternating between diagrams and test drives",
                        what: "Combining both methods iteratively",
                        pros: ["Best of both worlds", "Static guides dynamic", "Dynamic informs static"],
                        cons: ["More time-intensive", "Requires both skill sets", "Complex setup"],
                        when: "The professional approach - iterate between both as you discover more",
                      },
                    ].map((method) => (
                      <Grid item xs={12} md={4} key={method.title}>
                        <Paper sx={{ p: 2, bgcolor: alpha(method.color, 0.08), border: `1px solid ${alpha(method.color, 0.3)}`, borderRadius: 2, height: "100%" }}>
                          <Typography variant="h6" sx={{ color: method.color, mb: 1 }}>
                            {method.icon} {method.title}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "grey.400", fontStyle: "italic", mb: 1 }}>
                            "{method.analogy}"
                          </Typography>
                          <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                            <strong>What:</strong> {method.what}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#22c55e", mb: 0.5 }}>✓ Pros:</Typography>
                          <List dense disablePadding sx={{ mb: 1 }}>
                            {method.pros.map((pro) => (
                              <ListItem key={pro} sx={{ py: 0, pl: 2 }}>
                                <Typography variant="body2" sx={{ color: "grey.400" }}>• {pro}</Typography>
                              </ListItem>
                            ))}
                          </List>
                          <Typography variant="body2" sx={{ color: "#ef4444", mb: 0.5 }}>✗ Cons:</Typography>
                          <List dense disablePadding sx={{ mb: 1 }}>
                            {method.cons.map((con) => (
                              <ListItem key={con} sx={{ py: 0, pl: 2 }}>
                                <Typography variant="body2" sx={{ color: "grey.400" }}>• {con}</Typography>
                              </ListItem>
                            ))}
                          </List>
                          <Alert severity="info" sx={{ py: 0.5, bgcolor: "transparent" }}>
                            <Typography variant="caption">{method.when}</Typography>
                          </Alert>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    <strong>The Reality:</strong> Hybrid is the norm. Let static analysis choose breakpoints/hooks, then feed runtime evidence back into your decompiler to rename and simplify. Think of it as a conversation with the binary.
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

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Beginner Lab Setup (Step-by-Step)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="subtitle1" sx={{ color: "#a855f7", mb: 2 }}>
                    🖥️ Setting Up Your First RE Lab (Windows Focus)
                  </Typography>
                  <List dense>
                    {[
                      { step: "1. Install VirtualBox or VMware Workstation Player (both free)", note: "Your safety net - isolates malware from your real system" },
                      { step: "2. Download a Windows 10/11 evaluation ISO from Microsoft", note: "Free for 90 days, perfect for RE labs" },
                      { step: "3. Create a VM with 4GB+ RAM, 60GB+ disk, disable shared folders", note: "More RAM = faster analysis" },
                      { step: "4. Install the VM, disable Windows Defender, take a SNAPSHOT", note: "Name it 'Clean Install' - you'll revert here often" },
                      { step: "5. Install tools: 7zip, Ghidra, x64dbg, PE-bear, Sysinternals Suite", note: "Download all from official sources only" },
                      { step: "6. Take another snapshot named 'Tools Installed'", note: "Your ready-to-analyze baseline" },
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ py: 0.5, alignItems: "flex-start" }}>
                        <ListItemIcon sx={{ minWidth: 28, mt: 0.5 }}>
                          <Chip label={idx + 1} size="small" sx={{ bgcolor: "#8b5cf6", color: "#fff", width: 24, height: 24 }} />
                        </ListItemIcon>
                        <ListItemText 
                          primary={item.step} 
                          secondary={item.note}
                          sx={{ 
                            "& .MuiListItemText-primary": { color: "grey.300" },
                            "& .MuiListItemText-secondary": { color: "grey.500", fontStyle: "italic" }
                          }} 
                        />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="bash"
                    code={`# Linux VM Alternative (CTF-style)
sudo apt update && sudo apt install -y gdb gdb-multiarch python3-pip
pip install capstone unicorn keystone-engine
git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh

# Verify Ghidra (requires Java 17+)
java -version  # Should show 17 or higher
./ghidraRun    # Launch from extracted folder

# Get practice binaries (safe, beginner-friendly)
# - crackmes.one (filter by difficulty: Beginner)
# - Malware-Unicorn RE101 labs (guided exercises)
# - PicoCTF binary challenges (CTF-style, free)`}
                  />
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    <strong>Golden Rule:</strong> NEVER analyze suspicious files on your host machine. Always use a VM with snapshots disabled network access unless intentionally testing C2.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Key Concepts (With Simple Explanations)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    {[
                      {
                        concept: "Executable Formats",
                        simple: "Think of these as different 'packaging' for programs",
                        details: "PE (Windows .exe/.dll), ELF (Linux), Mach-O (macOS). They contain code, data, and metadata the OS needs to run the program.",
                        icon: "📦",
                      },
                      {
                        concept: "Disassembly",
                        simple: "Translating machine code back to assembly language",
                        details: "CPUs understand binary (0s and 1s). Disassemblers show us the human-readable version: 'mov eax, 5' instead of '0xB8 05 00 00 00'.",
                        icon: "🔤",
                      },
                      {
                        concept: "Decompilation",
                        simple: "Turning assembly into C-like code (an approximation)",
                        details: "Goes one step further than disassembly. Not perfect - variable names and structure are guessed. Ghidra's decompiler is excellent and free.",
                        icon: "📝",
                      },
                      {
                        concept: "Debugging",
                        simple: "Running code step-by-step like slow motion",
                        details: "Pause execution, examine registers and memory, change values, skip instructions. Essential for understanding dynamic behavior.",
                        icon: "🐛",
                      },
                      {
                        concept: "Symbols",
                        simple: "Human-readable names for functions and variables",
                        details: "Debug builds have symbols (names like 'main', 'strlen'). Release builds strip them, leaving 'sub_401000'. RE is about recovering meaning.",
                        icon: "🏷️",
                      },
                      {
                        concept: "Calling Conventions",
                        simple: "Rules for how functions receive and return data",
                        details: "Where are arguments passed? In registers or on the stack? Who cleans up? Different OSes/compilers have different rules.",
                        icon: "📞",
                      },
                    ].map((item) => (
                      <Grid item xs={12} md={6} key={item.concept}>
                        <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2, height: "100%" }}>
                          <Typography variant="subtitle1" sx={{ color: "#a855f7", fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                            {item.icon} {item.concept}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#22c55e", fontStyle: "italic", my: 1 }}>
                            "{item.simple}"
                          </Typography>
                          <Typography variant="body2" sx={{ color: "grey.400" }}>
                            {item.details}
                          </Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Memory Layout (Visual Guide)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    When a program runs, the OS gives it memory organized into sections. Understanding this layout helps you know where to look for what:
                  </Typography>
                  <CodeBlock
                    language="text"
                    code={`High Memory (0xFFFFFFFF...)
┌─────────────────────────────────────────────────────────────────┐
│                         STACK                                    │
│  • Local variables (int x, char buf[100])                       │
│  • Function return addresses (where to go after function ends)  │
│  • Arguments passed to functions                                 │
│  • GROWS DOWNWARD ↓ (toward lower addresses)                    │
│  ⚠️ Buffer overflows target this area!                          │
├─────────────────────────────────────────────────────────────────┤
│                    (unmapped gap)                                │
├─────────────────────────────────────────────────────────────────┤
│                         HEAP                                     │
│  • Dynamic allocations (malloc, new)                            │
│  • Objects created at runtime                                    │
│  • GROWS UPWARD ↑ (toward higher addresses)                     │
│  ⚠️ Use-after-free bugs exploit this area!                      │
├─────────────────────────────────────────────────────────────────┤
│                         BSS                                      │
│  • Uninitialized global variables                                │
│  • static int count; // starts as 0                              │
├─────────────────────────────────────────────────────────────────┤
│                         DATA                                     │
│  • Initialized global variables                                  │
│  • static int max = 100; // has a value                         │
│  • String literals "Hello World"                                 │
├─────────────────────────────────────────────────────────────────┤
│                         TEXT (CODE)                              │
│  • Your actual program instructions                              │
│  • Read-only in modern systems (NX/DEP protection)              │
│  • Where main() and all functions live                          │
└─────────────────────────────────────────────────────────────────┘
Low Memory (0x00000000...)`}
                  />
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Why This Matters:</strong> When debugging, you'll see addresses. Knowing which region an address belongs to tells you what kind of data you're looking at. Stack addresses are high, heap is in the middle, code is low.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Registers (x86-64) - Your CPU's Scratch Paper</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Registers are tiny, super-fast storage locations inside the CPU. Think of them as the CPU's "hands" - it can only work directly with data in registers.
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Register</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Purpose</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Beginner Tip</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["RAX", "Return value, accumulator", "Check this after a function call to see what it returned"],
                          ["RBX", "Callee-saved, base pointer", "Often used to hold important addresses across calls"],
                          ["RCX", "Counter, 4th argument (Windows)", "Loop counters, also used for function args"],
                          ["RDX", "3rd argument, I/O pointer", "Often holds buffer sizes or secondary return values"],
                          ["RSI", "2nd argument (Linux), source index", "In string operations, points to source data"],
                          ["RDI", "1st argument (Linux), destination index", "First function argument on Linux; destination in string ops"],
                          ["RSP", "Stack pointer (top of stack)", "⚠️ Critical! Always points to current stack top"],
                          ["RBP", "Base pointer (stack frame)", "Points to current function's stack frame base"],
                          ["RIP", "Instruction pointer (next instruction)", "⚠️ Most important! Shows WHERE execution is"],
                        ].map(([reg, purpose, tip]) => (
                          <TableRow key={reg}>
                            <TableCell>
                              <Chip label={reg} size="small" color="secondary" />
                            </TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{purpose}</TableCell>
                            <TableCell sx={{ color: "grey.500", fontSize: "0.85rem" }}>{tip}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <strong>Quick Reference:</strong> RAX = return value, RIP = current instruction, RSP = stack top. Master these three first!
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Calling Conventions (x64) - How Functions Talk</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    When one function calls another, they need to agree on where to put arguments and where to find the return value. This agreement is called a "calling convention."
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Platform</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>First 4-6 Arguments</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Extra Arguments</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Return Value</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        <TableRow>
                          <TableCell sx={{ color: "grey.300" }}>Linux (System V)</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>RDI, RSI, RDX, RCX, R8, R9</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>Pushed on stack (right to left)</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>RAX</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell sx={{ color: "grey.300" }}>Windows (x64)</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>RCX, RDX, R8, R9</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>Pushed on stack + 32-byte shadow space</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>RAX</TableCell>
                        </TableRow>
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <CodeBlock
                    language="text"
                    code={`Example: printf("Hello %s, you are %d years old", name, age);

Linux System V:
  RDI = pointer to "Hello %s, you are %d years old"
  RSI = pointer to name string
  RDX = age (integer value)
  call printf
  ; Return value (chars printed) now in RAX

Windows x64:
  RCX = pointer to format string
  RDX = pointer to name string
  R8  = age (integer value)
  call printf
  ; Return value now in RAX`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Binary Protections (Security Features)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Modern binaries have security features that make exploitation harder. When reversing, knowing what's enabled helps you understand the target:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Feature</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>What It Does</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>How to Check</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["NX/DEP", "Marks memory as non-executable (can't run code from stack/heap)", "checksec or PE header flags"],
                          ["ASLR/PIE", "Randomizes where code loads in memory (different each run)", "checksec or DYNAMIC_BASE flag"],
                          ["Stack Canaries", "Detects buffer overflows with a secret value on stack", "Look for __stack_chk_fail imports"],
                          ["CFG/CET", "Validates that jumps/calls go to valid targets", "PE Guard CF flag or CFG metadata"],
                          ["Code Signing", "Verifies the binary hasn't been modified", "signtool verify (Windows)"],
                        ].map(([feature, purpose, check]) => (
                          <TableRow key={feature}>
                            <TableCell>
                              <Chip label={feature} size="small" sx={{ bgcolor: "#22c55e", color: "#fff" }} />
                            </TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{purpose}</TableCell>
                            <TableCell sx={{ color: "grey.400", fontSize: "0.85rem" }}>{check}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <CodeBlock
                    language="bash"
                    code={`# Quick protection check (Linux)
checksec --file=./target

# Output example:
# RELRO: Full RELRO
# Stack: Canary found
# NX: NX enabled  
# PIE: PIE enabled
# If all green = well-protected binary`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">First RE Project: Crackme Tutorial</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Let's walk through your first reverse engineering challenge - a simple "crackme" (a program where you need to find the correct password):
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#a855f7", mb: 1 }}>
                      Step 1: Get a Practice Binary
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>
                      Go to crackmes.one, filter by "Difficulty: 1.0", download a simple x86 crackme. These are safe, legal practice binaries.
                    </Typography>
                  </Paper>
                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#a855f7", mb: 1 }}>
                      Step 2: Basic Triage
                    </Typography>
                    <CodeBlock
                      language="bash"
                      code={`# What is it?
file crackme.exe
# Output: PE32 executable (console) Intel 80386

# Any obvious strings?
strings crackme.exe | grep -i "pass\|correct\|wrong\|flag"
# Look for success/failure messages`}
                    />
                  </Paper>
                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#a855f7", mb: 1 }}>
                      Step 3: Open in Ghidra
                    </Typography>
                    <List dense>
                      {[
                        "Create a new project, import the binary",
                        "Say YES to auto-analysis",
                        "Find 'main' in the Symbol Tree → Functions",
                        "Look for string references to 'correct' or 'wrong'",
                        "Find the comparison that decides success/failure",
                      ].map((step, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <Typography sx={{ color: "#8b5cf6" }}>{idx + 1}.</Typography>
                          </ListItemIcon>
                          <ListItemText primary={step} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#a855f7", mb: 1 }}>
                      Step 4: Understand the Check
                    </Typography>
                    <CodeBlock
                      language="c"
                      code={`// Typical crackme pattern in decompiled code:
if (strcmp(user_input, "secretpassword") == 0) {
    puts("Correct! You win!");
} else {
    puts("Wrong password!");
}

// Your job: Find what "secretpassword" actually is
// It might be hardcoded, computed, or checked character by character`}
                    />
                  </Paper>
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <strong>Success Criteria:</strong> You've completed your first RE when you can explain HOW the password check works, not just what the password is. Understanding the mechanism is the goal!
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Common Beginner Mistakes (And How to Avoid Them)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    {[
                      {
                        mistake: "Running malware on your host machine",
                        fix: "ALWAYS use a VM with snapshots. No exceptions.",
                        severity: "error"
                      },
                      {
                        mistake: "Trying to understand every instruction",
                        fix: "Focus on control flow first. What happens if/else? Where are the interesting functions?",
                        severity: "warning"
                      },
                      {
                        mistake: "Not renaming functions and variables",
                        fix: "Rename as you go! 'sub_401234' → 'check_password' makes everything clearer.",
                        severity: "warning"
                      },
                      {
                        mistake: "Skipping strings/imports analysis",
                        fix: "Strings and imports are goldmines. Check them FIRST before diving into assembly.",
                        severity: "info"
                      },
                      {
                        mistake: "Not taking notes",
                        fix: "Keep a text file with addresses, findings, and questions. RE is iterative.",
                        severity: "info"
                      },
                      {
                        mistake: "Getting stuck on one approach",
                        fix: "If static analysis is blocked, try dynamic. If dynamic fails, go back to static with new knowledge.",
                        severity: "info"
                      },
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ py: 1, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <ListItemText
                          primary={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              {item.severity === "error" && <Chip label="Critical" size="small" color="error" />}
                              {item.severity === "warning" && <Chip label="Common" size="small" color="warning" />}
                              {item.severity === "info" && <Chip label="Tip" size="small" color="info" />}
                              <Typography sx={{ color: "grey.300" }}>❌ {item.mistake}</Typography>
                            </Box>
                          }
                          secondary={
                            <Typography sx={{ color: "#22c55e", mt: 0.5 }}>✓ {item.fix}</Typography>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
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

              {/* Beginner Tool Selection Guide */}
              <Paper sx={{ p: 3, bgcolor: "#0f1024", borderRadius: 2, mb: 3, border: "1px solid rgba(34,197,94,0.3)" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  🎯 How to Choose Your First Tool (Beginner's Decision Tree)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Don't get overwhelmed by options! Here's a simple guide to pick your starting point:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    {
                      question: "What's your budget?",
                      answer: "$0 (Free)",
                      recommendation: "Start with Ghidra + x64dbg (Windows) or Ghidra + GDB (Linux)",
                      color: "#22c55e",
                    },
                    {
                      question: "What OS are you analyzing?",
                      answer: "Windows PE files",
                      recommendation: "Ghidra for static, x64dbg for dynamic, PE-bear for quick inspection",
                      color: "#8b5cf6",
                    },
                    {
                      question: "What OS are you analyzing?",
                      answer: "Linux ELF files",
                      recommendation: "Ghidra for static, GDB+GEF for dynamic, readelf for quick inspection",
                      color: "#06b6d4",
                    },
                    {
                      question: "What OS are you analyzing?",
                      answer: "Android APKs",
                      recommendation: "JADX for decompilation, Apktool for resources, Frida for runtime",
                      color: "#f59e0b",
                    },
                  ].map((item, idx) => (
                    <Grid item xs={12} sm={6} key={idx}>
                      <Paper sx={{ p: 2, bgcolor: alpha(item.color, 0.1), border: `1px solid ${alpha(item.color, 0.3)}`, borderRadius: 2 }}>
                        <Typography variant="caption" sx={{ color: "grey.500" }}>
                          {item.question}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: item.color, fontWeight: 700, my: 0.5 }}>
                          {item.answer}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          → {item.recommendation}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
                <Alert severity="success" sx={{ mt: 2 }}>
                  <strong>Golden Rule:</strong> Master ONE disassembler + ONE debugger before exploring others. Ghidra + x64dbg is the recommended free combo.
                </Alert>
              </Paper>

              {/* Tool Categories Explained */}
              <Paper sx={{ p: 3, bgcolor: "#101124", borderRadius: 2, mb: 3 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 2 }}>
                  📚 Understanding Tool Categories
                </Typography>
                <Grid container spacing={2}>
                  {[
                    {
                      category: "Disassemblers",
                      icon: "🔬",
                      what: "Convert machine code to assembly language",
                      examples: "Ghidra, IDA Pro, Binary Ninja, radare2",
                      when: "Always first step - see what's in the binary",
                    },
                    {
                      category: "Decompilers",
                      icon: "📝",
                      what: "Convert assembly to C-like pseudo-code",
                      examples: "Ghidra (built-in), Hex-Rays (IDA addon), RetDec",
                      when: "After disassembly, to understand logic faster",
                    },
                    {
                      category: "Debuggers",
                      icon: "🐛",
                      what: "Run code step-by-step, examine memory/registers",
                      examples: "x64dbg, WinDbg, GDB, OllyDbg",
                      when: "When you need to see runtime behavior",
                    },
                    {
                      category: "PE/ELF Viewers",
                      icon: "📦",
                      what: "Inspect binary headers, sections, imports",
                      examples: "PE-bear, CFF Explorer, readelf, rabin2",
                      when: "Quick triage - what is this file?",
                    },
                    {
                      category: "Dynamic Instrumentation",
                      icon: "🪝",
                      what: "Hook functions, modify behavior at runtime",
                      examples: "Frida, x64dbg (scripting), DynamoRIO",
                      when: "Intercept API calls, bypass protections",
                    },
                    {
                      category: "Monitoring Tools",
                      icon: "👁️",
                      what: "Watch file/registry/network activity",
                      examples: "Procmon, Sysmon, Wireshark, strace",
                      when: "See what the binary DOES without stepping through code",
                    },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={4} key={item.category}>
                      <Paper sx={{ p: 2, bgcolor: "#0a0a0f", borderRadius: 1, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 600 }}>
                          {item.icon} {item.category}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", my: 1 }}>
                          {item.what}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "#22c55e", display: "block" }}>
                          Examples: {item.examples}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "grey.500", display: "block", mt: 0.5 }}>
                          Use when: {item.when}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

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

              {/* Ghidra Deep Dive for Beginners */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🚀 Ghidra: Complete Beginner's Walkthrough</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Ghidra is your Swiss Army knife for RE. Here's everything you need to get started:
                  </Typography>
                  
                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                      Step 1: Installation (5 minutes)
                    </Typography>
                    <List dense>
                      {[
                        "Download from ghidra-sre.org (NSA's official page)",
                        "Extract the ZIP - no installer needed",
                        "Install Java 17+ (Amazon Corretto or OpenJDK)",
                        "Run ghidraRun.bat (Windows) or ghidraRun (Linux/Mac)",
                      ].map((item, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <Chip label={idx + 1} size="small" sx={{ bgcolor: "#22c55e", color: "#fff", width: 20, height: 20, fontSize: "0.7rem" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>

                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>
                      Step 2: First Project (2 minutes)
                    </Typography>
                    <List dense>
                      {[
                        "File → New Project → Non-Shared Project",
                        "Choose a location (e.g., C:\\GhidraProjects\\)",
                        "File → Import File → Select your binary",
                        "Click 'OK' on the import dialog (defaults are fine)",
                        "Double-click the imported file to open CodeBrowser",
                      ].map((item, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <Chip label={idx + 1} size="small" sx={{ bgcolor: "#8b5cf6", color: "#fff", width: 20, height: 20, fontSize: "0.7rem" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>

                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      Step 3: Understanding the Interface
                    </Typography>
                    <CodeBlock
                      language="text"
                      code={`┌────────────────────────────────────────────────────────────────┐
│ Ghidra CodeBrowser Layout                                       │
├──────────────────┬─────────────────────┬───────────────────────┤
│  Symbol Tree     │    Listing          │   Decompiler          │
│  ─────────────   │    ─────────        │   ──────────          │
│  • Functions     │    Assembly code    │   C-like pseudo-code  │
│  • Imports       │    with addresses   │   (much easier to     │
│  • Exports       │    and bytes        │   read!)              │
│  • Classes       │                     │                       │
│                  │    Click a line →   │   ← Auto-syncs!       │
├──────────────────┴─────────────────────┴───────────────────────┤
│  Data Type Manager │ Console Output │ Program Trees           │
└────────────────────────────────────────────────────────────────┘

Essential Windows (Window menu to enable):
• Decompiler - MUST HAVE - shows pseudo-C code
• Symbol Tree - navigate functions/imports
• Bookmarks - mark important locations
• Function Call Graph - visualize call flow`}
                    />
                  </Paper>

                  <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#06b6d4", mb: 1 }}>
                      Essential Keyboard Shortcuts
                    </Typography>
                    <Grid container spacing={1}>
                      {[
                        { key: "G", action: "Go to address/symbol" },
                        { key: "X", action: "Show cross-references (who calls this?)" },
                        { key: "L", action: "Rename symbol/function" },
                        { key: "T", action: "Change data type" },
                        { key: ";", action: "Add comment" },
                        { key: "Ctrl+Shift+F", action: "Search for text" },
                        { key: "P", action: "Create/edit function" },
                        { key: "D", action: "Create data at cursor" },
                      ].map((item) => (
                        <Grid item xs={6} sm={3} key={item.key}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Chip label={item.key} size="small" sx={{ bgcolor: "#8b5cf6", fontFamily: "monospace" }} />
                            <Typography variant="caption" sx={{ color: "grey.400" }}>{item.action}</Typography>
                          </Box>
                        </Grid>
                      ))}
                    </Grid>
                  </Paper>
                </AccordionDetails>
              </Accordion>

              <Grid container spacing={2} sx={{ mt: 1, mb: 2 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2.5, bgcolor: "#0f1024", border: "1px solid rgba(139,92,246,0.25)", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ color: "#a855f7", fontWeight: 600, mb: 1 }}>
                      x64dbg Starter Pack (Windows Debugging)
                    </Typography>
                    <List dense>
                      {[
                        "Download from x64dbg.com - extract, no install needed",
                        "Run x96dbg.exe (auto-selects 32 or 64-bit)",
                        "File → Open to load a binary, or Attach to running process",
                        "F2 = breakpoint, F7 = step into, F8 = step over, F9 = run",
                        "View → Memory Map shows all loaded modules",
                        "Right-click address → Follow in Dump to see memory",
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
                      <strong>Pro Tip:</strong> Set breakpoints on APIs like CreateFileA, VirtualAlloc to catch interesting behavior.
                    </Alert>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2.5, bgcolor: "#0f1024", border: "1px solid rgba(139,92,246,0.25)", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ color: "#a855f7", fontWeight: 600, mb: 1 }}>
                      GDB + GEF Starter Pack (Linux Debugging)
                    </Typography>
                    <List dense>
                      {[
                        "Install: sudo apt install gdb, then install GEF plugin",
                        "Load binary: gdb ./program",
                        "Set breakpoint: b main or b *0x401000",
                        "Run program: r (or r arg1 arg2 for arguments)",
                        "Step: ni (next instruction), si (step into)",
                        "Examine memory: x/20x $rsp (20 hex words at RSP)",
                      ].map((item) => (
                        <ListItem key={item} sx={{ py: 0.4 }}>
                          <ListItemIcon sx={{ minWidth: 30 }}>
                            <SecurityIcon sx={{ color: "#22c55e" }} fontSize="small" />
                          </ListItemIcon>
                          <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300", fontSize: "0.9rem" } }} />
                        </ListItem>
                      ))}
                    </List>
                    <CodeBlock
                      language="bash"
                      code={`# Install GEF (makes GDB much better)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"`}
                    />
                  </Paper>
                </Grid>
              </Grid>

              {/* Common Tool Pitfalls */}
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">⚠️ Common Tool Pitfalls (And Solutions)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    {[
                      {
                        problem: "Ghidra analysis never finishes",
                        solution: "For large binaries, disable some analyzers in Analysis → Auto Analyze. Decompiler and Function ID are most important.",
                      },
                      {
                        problem: "x64dbg crashes on attach",
                        solution: "Run x64dbg as Administrator. Some processes require elevated privileges.",
                      },
                      {
                        problem: "Decompiler output looks wrong",
                        solution: "Right-click function → Edit Function Signature. Fix calling convention and parameter types.",
                      },
                      {
                        problem: "Can't find main() function",
                        solution: "Look for 'entry' or search for strings like 'Usage:' or error messages, then trace backwards.",
                      },
                      {
                        problem: "Binary is packed/encrypted",
                        solution: "Run dynamically until it unpacks, dump memory, then analyze the dump. Use Scylla to fix imports.",
                      },
                      {
                        problem: "No symbols in debugger",
                        solution: "Set symbol path (WinDbg: .symfix) or accept that you'll see addresses instead of function names.",
                      },
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ py: 1, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <ListItemText
                          primary={<Typography sx={{ color: "#ef4444" }}>❌ {item.problem}</Typography>}
                          secondary={<Typography sx={{ color: "#22c55e", mt: 0.5 }}>✓ {item.solution}</Typography>}
                        />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

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
                  <Grid container spacing={2}>
                    {[
                      {
                        name: "crackmes.one",
                        difficulty: "Beginner → Advanced",
                        type: "Password/license challenges",
                        tip: "Filter by difficulty 1.0-2.0 to start",
                      },
                      {
                        name: "PicoCTF",
                        difficulty: "Beginner",
                        type: "CTF challenges with hints",
                        tip: "Free, browser-based, great learning path",
                      },
                      {
                        name: "pwn.college",
                        difficulty: "Beginner → Intermediate",
                        type: "Structured exploitation course",
                        tip: "Video lectures + practice challenges",
                      },
                      {
                        name: "Malware Traffic Analysis",
                        difficulty: "Intermediate",
                        type: "Real malware pcaps with writeups",
                        tip: "Great for network-focused RE",
                      },
                      {
                        name: "FLARE-On",
                        difficulty: "Intermediate → Expert",
                        type: "Annual RE challenge (past years available)",
                        tip: "Work through older challenges first",
                      },
                      {
                        name: "Reverse Engineering for Beginners",
                        difficulty: "Beginner",
                        type: "Free book by Dennis Yurichev",
                        tip: "Comprehensive theory + examples",
                      },
                    ].map((item) => (
                      <Grid item xs={12} sm={6} md={4} key={item.name}>
                        <Paper sx={{ p: 2, bgcolor: "#0f1024", borderRadius: 1, height: "100%" }}>
                          <Typography variant="subtitle2" sx={{ color: "#a855f7", fontWeight: 600 }}>
                            {item.name}
                          </Typography>
                          <Chip label={item.difficulty} size="small" sx={{ mt: 0.5, mb: 1, bgcolor: alpha("#22c55e", 0.2) }} />
                          <Typography variant="body2" sx={{ color: "grey.400" }}>
                            {item.type}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "#22c55e", display: "block", mt: 0.5 }}>
                            💡 {item.tip}
                          </Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
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

              {/* Beginner Mindset Section */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2 }}>
                  🧠 The Right Mindset for Assembly
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Think of it like learning to read a new language, not write poetry.</strong>
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  When you read a book in Spanish, you don't need to be able to write Spanish poetry.
                  Similarly, reverse engineers read assembly - we rarely write it. Your goal is pattern 
                  recognition, not memorization.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(34, 197, 94, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>✅ Do This</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • Look for patterns (loops, ifs, function calls)<br/>
                        • Use a cheat sheet - pros do too<br/>
                        • Let the decompiler help you<br/>
                        • Focus on what the code DOES, not HOW
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(239, 68, 68, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>❌ Don't Do This</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • Try to memorize every instruction<br/>
                        • Read every line sequentially<br/>
                        • Ignore the decompiler output<br/>
                        • Get stuck on one confusing block
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(139, 92, 246, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>💡 Pro Tip</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        Start with the decompiler view, then look at assembly only when the 
                        decompiler is confused or you need precision.
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              {/* Visual Register Cheat Sheet */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">📋 Register Cheat Sheet (Keep This Open!)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Registers are like the CPU's built-in variables. Here's what each one typically does:
                  </Typography>
                  <CodeBlock
                    language="text"
                    code={`╔══════════════════════════════════════════════════════════════════════════════╗
║  x64 REGISTER QUICK REFERENCE                                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  GENERAL PURPOSE (you'll see these constantly)                               ║
║  ┌────────────────────────────────────────────────────────────────────────┐  ║
║  │  RAX  │ Return value from functions, also used for multiplication     │  ║
║  │  RBX  │ General purpose, often preserved (saved across function calls)│  ║
║  │  RCX  │ Counter for loops, 1st arg on Windows                         │  ║
║  │  RDX  │ Data register, 2nd arg on Windows                             │  ║
║  │  RSI  │ Source index (string ops), 2nd arg on Linux                   │  ║
║  │  RDI  │ Dest index (string ops), 1st arg on Linux                     │  ║
║  │  RBP  │ Base pointer - marks bottom of stack frame                    │  ║
║  │  RSP  │ Stack pointer - always points to top of stack                 │  ║
║  │ R8-R15│ Extra registers (args 5-6 and general use)                    │  ║
║  └────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  REGISTER SIZE NAMES (same register, different sizes)                        ║
║  ┌────────────────────────────────────────────────────────────────────────┐  ║
║  │  RAX (64-bit) → EAX (32-bit) → AX (16-bit) → AL/AH (8-bit low/high)   │  ║
║  │                                                                        │  ║
║  │  Example: If RAX = 0x123456789ABCDEF0                                  │  ║
║  │           EAX = 0x9ABCDEF0 (lower 32 bits)                             │  ║
║  │           AX  = 0xDEF0 (lower 16 bits)                                 │  ║
║  │           AL  = 0xF0 (lower 8 bits)                                    │  ║
║  └────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  CALLING CONVENTIONS (how functions receive arguments)                       ║
║  ┌────────────────────────────────────────────────────────────────────────┐  ║
║  │  Linux x64:   RDI, RSI, RDX, RCX, R8, R9, then stack                   │  ║
║  │  Windows x64: RCX, RDX, R8, R9, then stack (+ 32-byte shadow space)    │  ║
║  │  Return:      Always in RAX (or RAX:RDX for 128-bit)                   │  ║
║  └────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════╝`}
                  />
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Memory Trick:</strong> On Linux, args go in <code>RDI, RSI, RDX, RCX</code> - 
                    remember "Diana Says Don't Cry" (D-S-D-C).
                  </Alert>
                </AccordionDetails>
              </Accordion>

              {/* Step-by-Step Reading Exercise */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🎯 Exercise: Reading Your First Function</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Let's walk through reading a simple function step-by-step. This is a function that 
                    adds two numbers:
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>
                        Assembly (What you see)
                      </Typography>
                      <CodeBlock
                        language="asm"
                        code={`add_numbers:
    push rbp           ; [1] Save old base pointer
    mov rbp, rsp       ; [2] Set up new stack frame
    mov [rbp-8], edi   ; [3] Save 1st argument to stack
    mov [rbp-12], esi  ; [4] Save 2nd argument to stack
    mov eax, [rbp-8]   ; [5] Load 1st arg into eax
    add eax, [rbp-12]  ; [6] Add 2nd arg to eax
    pop rbp            ; [7] Restore old base pointer
    ret                ; [8] Return (result in eax)`}
                      />
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                        What Each Line Means
                      </Typography>
                      <Box sx={{ bgcolor: "rgba(0,0,0,0.3)", p: 2, borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: "grey.300", fontFamily: "monospace" }}>
                          [1-2] <strong>Prologue:</strong> Standard function setup<br/>
                          <span style={{ color: '#666' }}>      (You can usually skip these)</span><br/><br/>
                          [3-4] <strong>Save args:</strong> Store inputs on stack<br/>
                          <span style={{ color: '#666' }}>      edi=1st arg, esi=2nd arg (Linux)</span><br/><br/>
                          [5] <strong>Load:</strong> Get 1st number into eax<br/><br/>
                          [6] <strong>THE MATH:</strong> eax = eax + 2nd number<br/>
                          <span style={{ color: '#22c55e' }}>      ← This is the important line!</span><br/><br/>
                          [7-8] <strong>Epilogue:</strong> Cleanup and return<br/>
                          <span style={{ color: '#666' }}>      (Result is already in eax)</span>
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <strong>Key Insight:</strong> Most of assembly is setup/cleanup (prologue/epilogue). 
                    The actual work is usually just 1-3 instructions in the middle. Learn to spot and skip the boilerplate!
                  </Alert>
                </AccordionDetails>
              </Accordion>

              {/* The 5 Instructions You Need to Know */}
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🔑 The 5 Instructions You'll See 90% of the Time</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Instead of memorizing hundreds of instructions, learn these 5 really well:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Instruction</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Plain English</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Example</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Think of it as...</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["mov", "Copy value from B to A", "mov rax, rbx", "rax = rbx"],
                          ["call", "Call a function", "call printf", "printf(...)"],
                          ["cmp + jXX", "Compare and jump", "cmp rax, 5\\njge label", "if (rax >= 5) goto label"],
                          ["push/pop", "Save/restore to stack", "push rax\\npop rbx", "stack.push(rax)\\nrbx = stack.pop()"],
                          ["lea", "Calculate address", "lea rax, [rbx+8]", "rax = &rbx[1] (pointer math)"],
                        ].map(([inst, english, example, think]) => (
                          <TableRow key={inst}>
                            <TableCell sx={{ color: "#22c55e", fontFamily: "monospace" }}>{inst}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{english}</TableCell>
                            <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.75rem" }}>{example}</TableCell>
                            <TableCell sx={{ color: "#f59e0b", fontFamily: "monospace", fontSize: "0.75rem" }}>{think}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Pattern Recognition:</strong> When you see <code>cmp</code> followed by 
                    <code>jXX</code> (any jump instruction), that's an <code>if</code> statement. 
                    When you see it followed by a backwards jump, that's a <code>while/for</code> loop.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              {/* Common Patterns Section */}
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🔍 Spotting C Code Patterns in Assembly</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Here's how common C code looks when compiled. Learn to spot these patterns instantly:
                  </Typography>
                  
                  {/* If Statement */}
                  <Paper sx={{ p: 2, mb: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                    <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                      If Statement: <code style={{ color: "#f59e0b" }}>if (x == 5) &#123; do_something(); &#125;</code>
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <CodeBlock
                          language="asm"
                          code={`cmp dword [rbp-4], 5    ; Compare x with 5
jne skip_block          ; If NOT equal, skip
call do_something       ; This only runs if x == 5
skip_block:
; Code continues here...`}
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          <strong>Pattern:</strong><br/>
                          1. <code>cmp</code> instruction (comparison)<br/>
                          2. <code>jXX</code> jump (skip if condition fails)<br/>
                          3. Code block that runs conditionally<br/>
                          4. Label where skipped code continues<br/><br/>
                          <strong>Key insight:</strong> The jump skips the "true" branch!
                        </Typography>
                      </Grid>
                    </Grid>
                  </Paper>

                  {/* For Loop */}
                  <Paper sx={{ p: 2, mb: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                    <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                      For Loop: <code style={{ color: "#f59e0b" }}>for (int i = 0; i &lt; 10; i++)</code>
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <CodeBlock
                          language="asm"
                          code={`mov dword [rbp-4], 0     ; i = 0 (initialization)
.loop_start:
cmp dword [rbp-4], 10    ; i < 10? (condition)
jge .loop_end            ; Exit if i >= 10
; ... loop body here ...
inc dword [rbp-4]        ; i++ (increment)
jmp .loop_start          ; Go back to start
.loop_end:`}
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          <strong>Pattern:</strong><br/>
                          1. Initialize counter (usually <code>mov ... 0</code>)<br/>
                          2. Label for loop start<br/>
                          3. Compare counter to limit<br/>
                          4. Jump out if done<br/>
                          5. Loop body<br/>
                          6. Increment counter<br/>
                          7. Jump back to start<br/><br/>
                          <strong>Spot it by:</strong> A <code>jmp</code> going BACKWARDS
                        </Typography>
                      </Grid>
                    </Grid>
                  </Paper>

                  {/* Function Call */}
                  <Paper sx={{ p: 2, mb: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                    <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                      Function Call: <code style={{ color: "#f59e0b" }}>result = add(5, 10);</code>
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <CodeBlock
                          language="asm"
                          code={`; Linux x64 calling convention
mov edi, 5          ; 1st argument = 5
mov esi, 10         ; 2nd argument = 10
call add            ; Call the function
mov [rbp-8], eax    ; Save return value`}
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          <strong>Pattern:</strong><br/>
                          1. Load args into registers (order matters!)<br/>
                          2. <code>call</code> instruction<br/>
                          3. Use/store <code>eax</code> (return value)<br/><br/>
                          <strong>Args order (Linux):</strong> RDI, RSI, RDX, RCX, R8, R9<br/>
                          <strong>Args order (Windows):</strong> RCX, RDX, R8, R9
                        </Typography>
                      </Grid>
                    </Grid>
                  </Paper>

                  {/* Array Access */}
                  <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                    <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                      Array Access: <code style={{ color: "#f59e0b" }}>value = array[i];</code>
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <CodeBlock
                          language="asm"
                          code={`; array is at [rbp-40], i is at [rbp-4]
mov eax, [rbp-4]           ; Load i
cdqe                       ; Sign extend to 64-bit
mov eax, [rbp-40+rax*4]    ; array[i] (4 bytes per int)
; rax now contains array[i]`}
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          <strong>Pattern:</strong><br/>
                          1. Load index into register<br/>
                          2. Multiply by element size (often implicit)<br/>
                          3. Add to base address<br/><br/>
                          <strong>Key insight:</strong> <code>[base + index*scale]</code> is array access<br/>
                          Scale is usually 1, 2, 4, or 8 (element size)
                        </Typography>
                      </Grid>
                    </Grid>
                  </Paper>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">📚 All Common Instructions (Reference)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="asm"
                    code={`; ═══════════════════════════════════════════════════════════════
; DATA MOVEMENT - Moving data between registers and memory
; ═══════════════════════════════════════════════════════════════
mov rax, rbx      ; Copy rbx to rax (rax = rbx)
mov rax, [rbx]    ; Copy memory AT rbx to rax (rax = *rbx)
mov [rax], rbx    ; Copy rbx to memory AT rax (*rax = rbx)
lea rax, [rbx+8]  ; Load ADDRESS rbx+8 (pointer math, no memory access!)
push rax          ; Push to stack (rsp -= 8; [rsp] = rax)
pop rbx           ; Pop from stack (rbx = [rsp]; rsp += 8)
xchg rax, rbx     ; Swap rax and rbx

; ═══════════════════════════════════════════════════════════════
; ARITHMETIC - Math operations
; ═══════════════════════════════════════════════════════════════
add rax, 10       ; rax = rax + 10
sub rax, rbx      ; rax = rax - rbx
imul rax, rbx     ; rax = rax * rbx (signed)
mul rbx           ; rdx:rax = rax * rbx (unsigned, result in 2 regs)
inc rax           ; rax++ (increment)
dec rax           ; rax-- (decrement)
neg rax           ; rax = -rax (negate)
idiv rbx          ; rax = rdx:rax / rbx, rdx = remainder (signed)

; ═══════════════════════════════════════════════════════════════
; LOGIC & BITWISE - Testing and bit manipulation
; ═══════════════════════════════════════════════════════════════
cmp rax, rbx      ; Compare (sets flags, doesn't store result)
test rax, rax     ; AND with self (sets ZF if rax is 0)
and rax, 0xFF     ; Bitwise AND (rax = rax & 0xFF)
or rax, rbx       ; Bitwise OR
xor rax, rax      ; XOR with self = ZERO (rax = 0, faster than mov)
not rax           ; Bitwise NOT (flip all bits)
shl rax, 3        ; Shift left (rax *= 8)
shr rax, 1        ; Shift right logical (rax /= 2, unsigned)
sar rax, 1        ; Shift right arithmetic (keeps sign bit)

; ═══════════════════════════════════════════════════════════════
; CONTROL FLOW - Jumping and calling
; ═══════════════════════════════════════════════════════════════
jmp label         ; Unconditional jump (goto)
je/jz label       ; Jump if equal/zero (ZF=1)
jne/jnz label     ; Jump if not equal/not zero (ZF=0)
jl/jg label       ; Jump if less/greater (signed comparison)
jb/ja label       ; Jump if below/above (unsigned comparison)
jle/jge label     ; Jump if less-or-equal/greater-or-equal
call func         ; Push return address, jump to func
ret               ; Pop return address, jump back
leave             ; mov rsp, rbp; pop rbp (epilogue shortcut)

; ═══════════════════════════════════════════════════════════════
; STRING/MEMORY - Bulk operations (watch for these in loops)
; ═══════════════════════════════════════════════════════════════
rep movsb         ; Copy RCX bytes from [RSI] to [RDI]
rep stosb         ; Fill RCX bytes at [RDI] with AL (memset)
repne scasb       ; Search for AL in [RDI] (strlen-like)`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🚦 Flags Explained Simply</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Flags are like little on/off switches that get set after comparisons and math. 
                    The CPU checks these flags to decide whether to jump or not.
                  </Typography>
                  
                  <Paper sx={{ p: 2, mb: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                    <Typography variant="body2" sx={{ color: "#22c55e", mb: 1 }}>
                      <strong>The Mental Model:</strong>
                    </Typography>
                    <CodeBlock
                      language="text"
                      code={`After: cmp rax, rbx   (computes rax - rbx, sets flags, throws away result)

If rax == rbx:  Result is 0     → ZF=1 (zero flag set!)
If rax < rbx:   Result negative → SF=1 (sign flag set, or CF=1 for unsigned)  
If rax > rbx:   Result positive → ZF=0, SF=0`}
                    />
                  </Paper>

                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#8b5cf6" }}>Flag</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>What It Means</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Jumps That Use It</TableCell>
                          <TableCell sx={{ color: "#8b5cf6" }}>Think Of It As...</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["ZF (Zero)", "Result was exactly zero", "JZ/JE, JNZ/JNE", "\"Are they equal?\""],
                          ["SF (Sign)", "Result was negative", "JS, JNS", "\"Is it negative?\" (signed)"],
                          ["CF (Carry)", "Unsigned overflow/borrow", "JC/JB, JNC/JAE", "\"Did we go below 0?\" (unsigned)"],
                          ["OF (Overflow)", "Signed overflow", "JO, JNO", "\"Did sign bit flip unexpectedly?\""],
                        ].map(([flag, meaning, jumps, think]) => (
                          <TableRow key={flag}>
                            <TableCell sx={{ color: "#22c55e", fontFamily: "monospace" }}>{flag}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{meaning}</TableCell>
                            <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>{jumps}</TableCell>
                            <TableCell sx={{ color: "#f59e0b" }}>{think}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Most important jump table:</strong><br/>
                    <code>JE/JZ</code> = Jump if Equal (if ZF=1)<br/>
                    <code>JNE/JNZ</code> = Jump if Not Equal (if ZF=0)<br/>
                    <code>JG/JNLE</code> = Jump if Greater (signed: ZF=0 and SF=OF)<br/>
                    <code>JL/JNGE</code> = Jump if Less (signed: SF≠OF)<br/>
                    <code>JA/JNBE</code> = Jump if Above (unsigned: CF=0 and ZF=0)<br/>
                    <code>JB/JNAE</code> = Jump if Below (unsigned: CF=1)
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
                  <Typography variant="h6">📦 Understanding the Stack (Visual Guide)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    The stack is like a pile of plates - you can only add/remove from the top. 
                    Each function call adds a "frame" to the stack. Here's how it looks:
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <CodeBlock
                        language="text"
                        code={`╔════════════════════════════════════════════╗
║         THE STACK (x64 Linux)              ║
╠════════════════════════════════════════════╣
║                                            ║
║  High Memory (older frames)                ║
║  ┌──────────────────────────────────────┐  ║
║  │  ... caller's caller frame ...       │  ║
║  ├──────────────────────────────────────┤  ║
║  │  arg7, arg8, ... (extra args)        │  ║
║  │  Return address (where to go back)   │  ║
║  │  Saved RBP (caller's base)           │ ← RBP points here ║
║  ├──────────────────────────────────────┤  ║
║  │  local_var1  [rbp-8]                 │  ║
║  │  local_var2  [rbp-16]                │  ║
║  │  buffer[32]  [rbp-48]                │  ║
║  │  ... more locals ...                 │  ║
║  │  (padding for alignment)             │  ║
║  └──────────────────────────────────────┘  ║
║                                       ← RSP (stack top) ║
║  Low Memory (grows DOWN!)                  ║
║                                            ║
╚════════════════════════════════════════════╝`}
                      />
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                        Key Points:
                      </Typography>
                      <List dense>
                        {[
                          "[rbp-X] = local variables (negative offsets)",
                          "[rbp+X] = passed arguments (positive offsets)",
                          "RSP always points to top of stack",
                          "RBP is stable reference point in function",
                          "Stack grows DOWN (lower addresses)",
                        ].map((item) => (
                          <ListItem key={item} sx={{ py: 0.2 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon color="success" sx={{ fontSize: 16 }} />
                            </ListItemIcon>
                            <ListItemText 
                              primary={item} 
                              sx={{ "& .MuiListItemText-primary": { color: "grey.300", fontSize: "0.9rem" } }} 
                            />
                          </ListItem>
                        ))}
                      </List>
                      <Alert severity="warning" sx={{ mt: 2 }}>
                        <strong>Windows difference:</strong> Before every call, 32 bytes of 
                        "shadow space" is reserved for the callee. Look for <code>sub rsp, 0x28</code> or similar.
                      </Alert>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🔧 Function Prologue & Epilogue Patterns</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Every function starts with setup (prologue) and ends with cleanup (epilogue). 
                    Learn to skip these mentally - they're boilerplate.
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(34, 197, 94, 0.1)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Standard Function
                        </Typography>
                        <CodeBlock
                          language="asm"
                          code={`; PROLOGUE
push rbp        ; Save caller's base
mov rbp, rsp    ; Set our base
sub rsp, 0x40   ; Space for locals

; ... actual code ...

; EPILOGUE
leave           ; = mov rsp,rbp + pop rbp
ret`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(59, 130, 246, 0.1)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
                          Leaf Function (Optimized)
                        </Typography>
                        <CodeBlock
                          language="asm"
                          code={`; No prologue needed!
; (doesn't call other functions)

xor eax, eax    ; Return 0
ret

; (no epilogue either)`}
                        />
                        <Typography variant="caption" sx={{ color: "grey.500" }}>
                          Simple functions skip the prologue entirely
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(139, 92, 246, 0.1)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>
                          Switch Statement
                        </Typography>
                        <CodeBlock
                          language="asm"
                          code={`mov eax, [rbp-4]  ; Get switch var
cmp eax, 4        ; Max case
ja default_case   ; > max? default
; Jump table lookup:
lea rdx, [jmp_table]
movsxd rax, [rdx+rax*4]
jmp rax`}
                        />
                        <Typography variant="caption" sx={{ color: "grey.500" }}>
                          Jump table = array of addresses
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              {/* Common Beginner Mistakes */}
              <Paper sx={{ p: 3, mt: 3, mb: 3, bgcolor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#ef4444", mb: 2 }}>
                  ⚠️ Common Assembly Reading Mistakes
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Mistake: Reading Every Line Sequentially</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> You spend 30 minutes on the prologue and never reach the important code.<br/>
                      <strong>Solution:</strong> Jump to <code>call</code> instructions and interesting API names first. Work backwards.
                    </Typography>
                    
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Mistake: Ignoring the Decompiler</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> "Real hackers read raw assembly" - No, we use tools!<br/>
                      <strong>Solution:</strong> Let Ghidra/IDA decompile first. Only dive into assembly when decompiler is wrong.
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Mistake: Confusing LEA with MOV</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      <strong>LEA:</strong> <code>lea rax, [rbx+8]</code> → rax = address (rbx + 8)<br/>
                      <strong>MOV:</strong> <code>mov rax, [rbx+8]</code> → rax = value AT (rbx + 8)<br/>
                      LEA does math, MOV reads memory!
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Mistake: Getting Lost in Loops</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> Can't tell if a jump is a loop or an if-statement.<br/>
                      <strong>Solution:</strong> If the jump goes BACKWARDS (to a lower address), it's a loop. Forward = if/skip.
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Mistake: Wrong Calling Convention</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> You think RDI is the 1st arg, but it's RCX (Windows).<br/>
                      <strong>Solution:</strong> Check if it's a Windows or Linux binary first! (PE = Windows, ELF = Linux)
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Mistake: Not Renaming Variables</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      <strong>Problem:</strong> <code>[rbp-0x28]</code> everywhere is confusing.<br/>
                      <strong>Solution:</strong> In Ghidra/IDA, rename variables as you figure them out: <code>local_buffer</code>, <code>loop_counter</code>, etc.
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

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

              {/* Beginner Context Section */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2 }}>
                  🔬 What is Static Analysis?
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Think of it like examining a car engine without turning it on.</strong> You can see the parts, 
                  read the labels, check the wiring - but you're not actually running the engine.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(34, 197, 94, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>✅ Pros</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • 100% safe (nothing executes)<br/>
                        • See ALL the code at once<br/>
                        • No VM/sandbox needed<br/>
                        • Can't be evaded by anti-debug
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(239, 68, 68, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>❌ Cons</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • Can't see runtime behavior<br/>
                        • Packed/encrypted code is invisible<br/>
                        • Self-modifying code trips you up<br/>
                        • No actual network/file activity
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(139, 92, 246, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>🎯 Best For</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • Initial triage & classification<br/>
                        • Finding hardcoded IOCs<br/>
                        • Understanding program structure<br/>
                        • Safe malware examination
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              {/* Step-by-Step Triage Guide */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">📋 Step-by-Step: Your First Static Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Follow this checklist when you encounter any new binary:
                  </Typography>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 1: What IS This File? (30 seconds)
                        </Typography>
                        <CodeBlock
                          language="bash"
                          code={`# Get file type
file suspicious.exe
# Output: PE32+ executable (GUI) x86-64

# Get hash to search VirusTotal
sha256sum suspicious.exe
# 4a5b...copy this hash`}
                        />
                        <Typography variant="body2" sx={{ color: "grey.400", mt: 1 }}>
                          <strong>What to look for:</strong> Is it PE (Windows)? ELF (Linux)? 32 or 64-bit?
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 2: Check VirusTotal (1 minute)
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          1. Go to <code>virustotal.com</code><br/>
                          2. Search by hash (NOT by uploading!)<br/>
                          3. Check detection ratio and tags<br/><br/>
                          <strong>Why search by hash?</strong> Uploading alerts the malware author that their sample was submitted.
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 3: Extract Strings (2 minutes)
                        </Typography>
                        <CodeBlock
                          language="bash"
                          code={`# Get readable strings
strings -n 8 suspicious.exe > strings.txt

# Look for interesting patterns:
grep -i "http" strings.txt     # URLs
grep -i "password" strings.txt # Credentials
grep -i "cmd\|powershell" strings.txt`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 4: Check Imports (2 minutes)
                        </Typography>
                        <CodeBlock
                          language="bash"
                          code={`# List imported functions
rabin2 -i suspicious.exe | head -50

# OR with objdump for ELF
objdump -T suspicious.elf`}
                        />
                        <Typography variant="body2" sx={{ color: "grey.400", mt: 1 }}>
                          <strong>Red flags:</strong> VirtualAlloc, CreateRemoteThread, WriteProcessMemory, socket, connect
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 5: Load in Disassembler (5-10 minutes)
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          1. Open Ghidra, create new project<br/>
                          2. Import the binary, accept defaults<br/>
                          3. Let auto-analysis complete<br/>
                          4. Go to Functions → Look for <code>main</code> or <code>entry</code><br/>
                          5. Open Decompiler window (Window → Decompiler)<br/>
                          6. Start reading the pseudo-C code!
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              {/* What to Look For */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🔍 What to Look For (Cheat Sheet)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ color: "#ef4444" }}>🚨 Suspicious Strings</TableCell>
                              <TableCell sx={{ color: "#8b5cf6" }}>What It Might Mean</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {[
                              ["http:// or https://", "C2 server, data exfil"],
                              ["cmd.exe, powershell", "Command execution"],
                              ["password, credentials", "Credential theft"],
                              ["HKEY_, RegSetValue", "Registry persistence"],
                              [".onion, tor", "Tor communication"],
                              ["base64, encrypt, decrypt", "Obfuscation/crypto"],
                              ["inject, hook, patch", "Process manipulation"],
                            ].map(([str, meaning]) => (
                              <TableRow key={str}>
                                <TableCell sx={{ color: "#22c55e", fontFamily: "monospace", fontSize: "0.8rem" }}>{str}</TableCell>
                                <TableCell sx={{ color: "grey.300", fontSize: "0.85rem" }}>{meaning}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ color: "#ef4444" }}>🚨 Suspicious Imports</TableCell>
                              <TableCell sx={{ color: "#8b5cf6" }}>What It Might Mean</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {[
                              ["VirtualAlloc(Ex)", "Shellcode staging"],
                              ["CreateRemoteThread", "Process injection"],
                              ["WriteProcessMemory", "Memory tampering"],
                              ["LoadLibrary/GetProcAddress", "Dynamic API resolution"],
                              ["CreateService", "Persistence as service"],
                              ["InternetOpen/HttpSend", "Network communication"],
                              ["CryptEncrypt/Decrypt", "Encryption operations"],
                            ].map(([api, meaning]) => (
                              <TableRow key={api}>
                                <TableCell sx={{ color: "#f59e0b", fontFamily: "monospace", fontSize: "0.8rem" }}>{api}</TableCell>
                                <TableCell sx={{ color: "grey.300", fontSize: "0.85rem" }}>{meaning}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Initial Triage Commands</Typography>
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

              {/* What To Do If Stuck Section */}
              <Paper sx={{ p: 3, mt: 3, bgcolor: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2 }}>
                  🆘 What To Do If You're Stuck
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "I see no readable strings"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      The binary is probably packed or encrypted. Look for:<br/>
                      • High entropy sections (&gt;7.0)<br/>
                      • Very few imports (just LoadLibrary/GetProcAddress)<br/>
                      • Large .data sections with random-looking content<br/>
                      <strong>Solution:</strong> You need to unpack it first. Try dynamic analysis or look for unpacker tools.
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "The decompiler output makes no sense"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      Common causes:<br/>
                      • Wrong architecture selected (32 vs 64-bit)<br/>
                      • Function boundaries wrong (press 'P' to recreate)<br/>
                      • Missing struct/type definitions<br/>
                      <strong>Solution:</strong> Apply correct data types, create structs, rename variables to build context.
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "I found interesting code but don't know what it does"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      Try these approaches:<br/>
                      • Google the constants/magic numbers<br/>
                      • Search for similar code on GitHub<br/>
                      • Check if it's a known crypto algorithm (CyberChef can identify)<br/>
                      • Look up the API calls on MSDN/man pages<br/>
                      <strong>Solution:</strong> Switch to dynamic analysis to see what values actually flow through.
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "There are thousands of functions - where do I start?"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      Don't read sequentially! Start from:<br/>
                      • <code>main</code> or entry point<br/>
                      • Interesting imports (CreateFile, socket, etc.)<br/>
                      • Interesting strings (URLs, passwords)<br/>
                      • Functions with many xrefs (heavily used)<br/>
                      <strong>Solution:</strong> Use cross-references (X key) to trace from known interesting points.
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              {/* Glossary */}
              <Paper sx={{ p: 3, mt: 3, bgcolor: "rgba(139, 92, 246, 0.1)", border: "1px solid rgba(139, 92, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#8b5cf6", mb: 2 }}>
                  📖 Static Analysis Glossary
                </Typography>
                <Grid container spacing={1}>
                  {[
                    ["PE", "Portable Executable - Windows binary format (.exe, .dll)"],
                    ["ELF", "Executable and Linkable Format - Linux/Unix binary format"],
                    ["Import Table", "List of external functions the binary uses"],
                    ["Export Table", "Functions the binary exposes to others"],
                    ["Section", "Logical division of binary (.text=code, .data=variables)"],
                    ["Entropy", "Measure of randomness (high = likely packed/encrypted)"],
                    ["Xref", "Cross-reference - where a function/string is used"],
                    ["IOC", "Indicator of Compromise - hash, IP, domain, etc."],
                    ["Packed", "Compressed/encrypted binary that unpacks at runtime"],
                    ["Stub", "Small piece of code that leads to real code"],
                  ].map(([term, def]) => (
                    <Grid item xs={12} sm={6} key={term}>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        <strong style={{ color: "#22c55e" }}>{term}:</strong> {def}
                      </Typography>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
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

              {/* Beginner Context Section */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#ef4444", mb: 2 }}>
                  🔥 What is Dynamic Analysis?
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Now we actually start the car engine.</strong> We run the binary (in a safe environment) 
                  and watch what it does - what files it creates, what network connections it makes, what processes it spawns.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(34, 197, 94, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>✅ Pros</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • See ACTUAL behavior<br/>
                        • Unpacked code is visible<br/>
                        • Captures real C2 comms<br/>
                        • Reveals encrypted configs
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(239, 68, 68, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>⚠️ Risks</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • Malware ACTUALLY runs<br/>
                        • Can escape VM (rare)<br/>
                        • May spread on network<br/>
                        • Self-deletion can occur
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(139, 92, 246, 0.1)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>🎯 Best For</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300" }}>
                        • Packed/encrypted binaries<br/>
                        • Network IOC extraction<br/>
                        • Understanding runtime flow<br/>
                        • Dumping decrypted payloads
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              {/* Safety Checklist - Enhanced */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🛡️ SAFETY FIRST: Pre-Run Checklist</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    <strong>Stop!</strong> Before running ANY suspicious binary, verify ALL these items:
                  </Alert>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          VM Setup ✓
                        </Typography>
                        <List dense>
                          {[
                            "Fresh VM snapshot taken (can revert!)",
                            "Shared folders DISABLED",
                            "Clipboard sharing DISABLED",
                            "Drag-and-drop DISABLED",
                            "Guest additions minimal/removed",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.1 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 16 }} />
                              </ListItemIcon>
                              <ListItemText 
                                primary={item} 
                                sx={{ "& .MuiListItemText-primary": { color: "grey.300", fontSize: "0.85rem" } }} 
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Network Setup ✓
                        </Typography>
                        <List dense>
                          {[
                            "Network set to Host-Only OR Internal",
                            "NO internet access (or intentional sinkhole)",
                            "Wireshark/tcpdump ready to capture",
                            "FakeNet-NG ready (optional but recommended)",
                            "DNS redirected to safe server",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.1 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 16 }} />
                              </ListItemIcon>
                              <ListItemText 
                                primary={item} 
                                sx={{ "& .MuiListItemText-primary": { color: "grey.300", fontSize: "0.85rem" } }} 
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Tools Ready ✓
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          <strong>Windows:</strong> x64dbg, Process Monitor, Process Hacker, Wireshark, FakeNet-NG, API Monitor<br/>
                          <strong>Linux:</strong> GDB + GEF/pwndbg, strace, ltrace, Wireshark, tcpdump
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              {/* Step-by-Step First Dynamic Analysis */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">📋 Step-by-Step: Your First Dynamic Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 1: Start Monitoring Tools FIRST
                        </Typography>
                        <CodeBlock
                          language="text"
                          code={`1. Start Process Monitor (filter by process name)
2. Start Wireshark (capture on all interfaces)
3. Start Process Hacker (watch for new processes)
4. Optional: Start API Monitor
5. Optional: Start FakeNet-NG`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 2: Run the Binary
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          Either:<br/>
                          • Double-click to run normally<br/>
                          • Load in debugger (x64dbg) and run<br/>
                          • Use <code>cmd /c sample.exe</code> for CLI<br/><br/>
                          <strong>Tip:</strong> Watch for immediate self-deletion!
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 3: Watch for These Behaviors
                        </Typography>
                        <List dense>
                          {[
                            "New processes spawned",
                            "Files created/modified (especially in AppData, Temp)",
                            "Registry keys created (Run, Services)",
                            "Network connections attempted",
                            "DLLs loaded from unusual paths",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0 }}>
                              <ListItemText 
                                primary={`• ${item}`}
                                sx={{ "& .MuiListItemText-primary": { color: "grey.300", fontSize: "0.85rem" } }} 
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          Step 4: Collect Evidence
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          • Save Wireshark capture (.pcap)<br/>
                          • Export Process Monitor logs<br/>
                          • Screenshot interesting behaviors<br/>
                          • Copy any dropped files<br/>
                          • Note C2 IPs/domains<br/><br/>
                          <strong>Then:</strong> Revert VM to snapshot!
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>
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

              {/* What To Do If Malware Evades Section */}
              <Paper sx={{ p: 3, mt: 3, bgcolor: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2 }}>
                  🆘 What To Do If Malware Evades Analysis
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "It exits immediately / does nothing"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      Likely detecting your analysis environment. Try:<br/>
                      • Use a different VM (not VirtualBox - try VMware or bare metal)<br/>
                      • Change VM name, MAC address, username<br/>
                      • Remove obvious VM artifacts (guest tools)<br/>
                      • Patch IsDebuggerPresent to return 0<br/>
                      • Check for timing checks (RDTSC anti-debug)
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "It requires specific conditions to run"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      Some malware checks for:<br/>
                      • Specific date/time (use faketime)<br/>
                      • Geographic location (fake your IP/locale)<br/>
                      • Domain-joined machine<br/>
                      • Specific running processes<br/>
                      • Mouse movement/user interaction<br/>
                      <strong>Solution:</strong> Set breakpoints on time/locale APIs and trace.
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "It detects my debugger"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      Common anti-debug bypasses:<br/>
                      • Use ScyllaHide plugin (x64dbg)<br/>
                      • Use GEF's anti-debug features<br/>
                      • Patch PEB.BeingDebugged flag<br/>
                      • Use hardware breakpoints instead of software<br/>
                      • Trace with DynamoRIO/Intel PIN instead
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                      "Network activity doesn't show anything useful"
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      Malware may be:<br/>
                      • Using encrypted comms (TLS) - check SNI/JA3<br/>
                      • Using DNS tunneling - watch DNS queries<br/>
                      • Dead C2 server - try providing fake responses with FakeNet<br/>
                      • Waiting for specific trigger<br/>
                      <strong>Solution:</strong> Set up fake services that respond appropriately.
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              {/* Common Beginner Mistakes */}
              <Paper sx={{ p: 3, mt: 3, bgcolor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#ef4444", mb: 2 }}>
                  ⚠️ Common Dynamic Analysis Mistakes
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Not Taking a Snapshot First</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> Malware runs, corrupts VM, can't analyze again.<br/>
                      <strong>Solution:</strong> ALWAYS snapshot before running. Make it a habit.
                    </Typography>
                    
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Running on Host Machine</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> You infect your actual computer.<br/>
                      <strong>Solution:</strong> NEVER run malware outside a VM. Period.
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Starting Monitoring After Running</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      <strong>Problem:</strong> You miss the initial activity (often the most interesting).<br/>
                      <strong>Solution:</strong> Start ALL monitoring tools BEFORE running the sample.
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Not Blocking Network</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> Malware calls home, spreads, or receives commands.<br/>
                      <strong>Solution:</strong> Host-only networking by default. Only enable if needed.
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Single-Stepping Through Everything</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      <strong>Problem:</strong> Takes forever, triggers timing-based anti-debug.<br/>
                      <strong>Solution:</strong> Set strategic breakpoints (VirtualAlloc, CreateFile, etc).
                    </Typography>

                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>Not Saving Artifacts</Typography>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>
                      <strong>Problem:</strong> You revert VM and lose all evidence.<br/>
                      <strong>Solution:</strong> Copy dropped files, save pcaps, export logs BEFORE reverting.
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 5: Workflow */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#8b5cf6", mb: 3 }}>
                RE Workflow Checklist
              </Typography>

              {/* Visual Workflow Overview */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2 }}>
                  🗺️ The Big Picture: RE Workflow Map
                </Typography>
                <CodeBlock
                  language="text"
                  code={`┌─────────────────────────────────────────────────────────────────────────────┐
│                        REVERSE ENGINEERING WORKFLOW                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐       │
│   │  TRIAGE  │ ───► │  STATIC  │ ◄──► │ DYNAMIC  │ ───► │  REPORT  │       │
│   │ (10 min) │      │ (30 min) │      │ (30 min) │      │ (15 min) │       │
│   └──────────┘      └──────────┘      └──────────┘      └──────────┘       │
│        │                 │                  │                 │             │
│        ▼                 ▼                  ▼                 ▼             │
│   • file type       • Ghidra          • Debugger         • IOCs           │
│   • hash/VT         • Find main       • Breakpoints      • Timeline       │
│   • strings         • Rename funcs    • Monitor          • Detection      │
│   • imports         • Map behavior    • Dump memory      • Config         │
│                                                                             │
│   ◄────────────────────── LOOP BACK AS NEEDED ──────────────────────────►  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘`}
                />
                <Alert severity="info" sx={{ mt: 2 }}>
                  <strong>Key insight:</strong> You'll loop between static and dynamic analysis many times. 
                  Dynamic reveals what static can't see (unpacked code), and static helps you understand 
                  what dynamic captured.
                </Alert>
              </Paper>

              {/* Time Estimates */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: "rgba(34, 197, 94, 0.1)", border: "1px solid rgba(34, 197, 94, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2 }}>
                  ⏱️ Time Estimates for Beginners
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)", textAlign: "center" }}>
                      <Typography variant="h4" sx={{ color: "#22c55e" }}>30 min</Typography>
                      <Typography variant="subtitle2" sx={{ color: "grey.400" }}>Quick Triage</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", mt: 1 }}>
                        File type, hash check, strings, imports<br/>
                        <strong>Output:</strong> "Is this interesting? What is it?"
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)", textAlign: "center" }}>
                      <Typography variant="h4" sx={{ color: "#f59e0b" }}>2-3 hours</Typography>
                      <Typography variant="subtitle2" sx={{ color: "grey.400" }}>Standard Analysis</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", mt: 1 }}>
                        Ghidra + debugger, map main features<br/>
                        <strong>Output:</strong> IOCs, behavior summary, basic detection
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)", textAlign: "center" }}>
                      <Typography variant="h4" sx={{ color: "#ef4444" }}>1-2 days</Typography>
                      <Typography variant="subtitle2" sx={{ color: "grey.400" }}>Deep Dive</Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", mt: 1 }}>
                        Full unpack, config extraction, C2 protocol<br/>
                        <strong>Output:</strong> Detailed report, YARA rules, decoder
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
                <Typography variant="body2" sx={{ color: "grey.400", mt: 2, textAlign: "center" }}>
                  <strong>Tip:</strong> Start with 30-min triage. Only invest more time if the sample is worth it!
                </Typography>
              </Paper>

              {/* Printable Checklist */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">📋 Printable Analysis Checklist</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          □ Phase 1: Setup (5 min)
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", fontFamily: "monospace", fontSize: "0.8rem" }}>
                          □ VM snapshot taken<br/>
                          □ Network isolated (host-only)<br/>
                          □ Tools ready (Ghidra, debugger, Wireshark)<br/>
                          □ Sample copied, original marked read-only<br/>
                          □ SHA-256 hash recorded
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1 }}>
                          □ Phase 2: Triage (10 min)
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", fontFamily: "monospace", fontSize: "0.8rem" }}>
                          □ file command run<br/>
                          □ Strings extracted and searched<br/>
                          □ Imports/exports listed<br/>
                          □ VirusTotal hash search<br/>
                          □ Packing/entropy checked
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
                          □ Phase 3: Static Analysis (30 min)
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", fontFamily: "monospace", fontSize: "0.8rem" }}>
                          □ Loaded in Ghidra, auto-analyzed<br/>
                          □ Found entry/main function<br/>
                          □ Key functions renamed<br/>
                          □ Interesting strings cross-referenced<br/>
                          □ Suspected behavior identified<br/>
                          □ Breakpoint locations noted
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                          □ Phase 4: Dynamic Analysis (30 min)
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", fontFamily: "monospace", fontSize: "0.8rem" }}>
                          □ Monitoring tools started FIRST<br/>
                          □ Debugger attached, breakpoints set<br/>
                          □ Sample executed<br/>
                          □ Behavior observed/documented<br/>
                          □ Memory dump captured (if unpacking)<br/>
                          □ Network pcap saved
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12}>
                      <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)" }}>
                        <Typography variant="subtitle2" sx={{ color: "#8b5cf6", mb: 1 }}>
                          □ Phase 5: Wrap-Up (15 min)
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", fontFamily: "monospace", fontSize: "0.8rem" }}>
                          □ IOCs collected (hashes, IPs, domains, mutexes, file paths)<br/>
                          □ Behavior summary written<br/>
                          □ Detection ideas noted (YARA strings, Sysmon events)<br/>
                          □ Dropped files/memory dumps saved<br/>
                          □ VM reverted to snapshot
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              {/* Common Roadblocks */}
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">🚧 Common Roadblocks & Solutions</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    {[
                      {
                        problem: "\"I've been on this for an hour and I'm stuck\"",
                        solution: "Switch modality! If you're in static, try dynamic. If dynamic, go back to static with new knowledge. Set a 60-90 min timebox.",
                      },
                      {
                        problem: "\"The binary is packed and I can't read anything\"",
                        solution: "Run it under debugger, break on VirtualAlloc/VirtualProtect, wait for unpack, dump memory. Then analyze the dump.",
                      },
                      {
                        problem: "\"There are too many functions, I don't know where to start\"",
                        solution: "Don't read sequentially! Start from: main/entry, interesting imports (network/file/crypto), interesting strings.",
                      },
                      {
                        problem: "\"The decompiler output is garbage\"",
                        solution: "Try: fixing function boundaries (P key), applying correct types, checking if it's a different architecture than expected.",
                      },
                      {
                        problem: "\"Malware detects my VM and exits\"",
                        solution: "Try different VM software, remove obvious artifacts, use anti-anti-debug plugins (ScyllaHide), or try bare-metal analysis.",
                      },
                      {
                        problem: "\"I found the C2 but can't understand the protocol\"",
                        solution: "Capture pcap, look for patterns, try replaying modified requests. Check if it's a known malware family with documented protocol.",
                      },
                    ].map((item, idx) => (
                      <Grid item xs={12} md={6} key={idx}>
                        <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)", height: "100%" }}>
                          <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                            {item.problem}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "grey.300" }}>
                            <strong>→</strong> {item.solution}
                          </Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Paper sx={{ p: 3, bgcolor: "#1a1a2e", borderRadius: 2, mt: 3 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 2 }}>
                  Analysis Steps (Detailed)
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
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default ReverseEngineeringPage;
