import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Typography,
  Paper,
  Card,
  CardContent,
  Grid,
  Chip,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Tooltip,
  Alert,
  Tabs,
  Tab,
  alpha,
  useTheme,
  Divider,
  LinearProgress,
  Fab,
  Drawer,
  useMediaQuery,
} from "@mui/material";
import {
  ArrowBack as BackIcon,
  Route as RouteIcon,
  ExpandMore as ExpandMoreIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Speed as SpeedIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkIcon,
  Public as PublicIcon,
  Timer as TimerIcon,
  TrendingUp as TrendingIcon,
  ContentCopy as CopyIcon,
  Terminal as TerminalIcon,
  Psychology as AiIcon,
  Assessment as AssessmentIcon,
  Hub as HubIcon,
  CloudQueue as CloudIcon,
  LocationOn as LocationIcon,
  CompareArrows as CompareIcon,
  Timeline as TimelineIcon,
  Shield as ShieldIcon,
  Layers as LayersIcon,
  Chat as ChatIcon,
  History as HistoryIcon,
  Business as BusinessIcon,
  Storage as StorageIcon,
  Visibility as VisibilityIcon,
  BugReport as BugReportIcon,
  AccountTree as AccountTreeIcon,
  BatchPrediction as BatchIcon,
  ListAlt as ListAltIcon,
  Close as CloseIcon,
  KeyboardArrowUp as KeyboardArrowUpIcon,
  Radar as RadarIcon,
  Extension as ExtensionIcon,
  SettingsEthernet as SettingsEthernetIcon,
  DeviceHub as DeviceHubIcon,
  Scanner as ScannerIcon,
  FindInPage as FindInPageIcon,
  UploadFile as UploadFileIcon,
  Build as BuildIcon,
} from "@mui/icons-material";
import { Link, useNavigate } from "react-router-dom";

// Accent color for this learning page
const ACCENT_COLOR = "#ec4899";

// ============================================================================
// Command Reference Data
// ============================================================================

interface CommandOption {
  flag: string;
  description: string;
  example?: string;
  platform: "windows" | "linux" | "both";
}

const WINDOWS_OPTIONS: CommandOption[] = [
  { flag: "-d", description: "Do not resolve addresses to hostnames", example: "tracert -d 8.8.8.8", platform: "windows" },
  { flag: "-h <max_hops>", description: "Maximum number of hops to search", example: "tracert -h 15 google.com", platform: "windows" },
  { flag: "-w <timeout>", description: "Wait timeout in milliseconds for each reply", example: "tracert -w 3000 google.com", platform: "windows" },
  { flag: "-4", description: "Force using IPv4", example: "tracert -4 google.com", platform: "windows" },
  { flag: "-6", description: "Force using IPv6", example: "tracert -6 google.com", platform: "windows" },
  { flag: "-j <host_list>", description: "Loose source route along host list (IPv4)", example: "tracert -j 192.168.1.1 google.com", platform: "windows" },
  { flag: "-R", description: "Trace round-trip path (IPv6 only)", example: "tracert -R -6 google.com", platform: "windows" },
];

const LINUX_OPTIONS: CommandOption[] = [
  { flag: "-n", description: "Do not resolve IP addresses to hostnames", example: "traceroute -n 8.8.8.8", platform: "linux" },
  { flag: "-m <max_ttl>", description: "Set maximum number of hops (default 30)", example: "traceroute -m 20 google.com", platform: "linux" },
  { flag: "-w <timeout>", description: "Set probe timeout in seconds", example: "traceroute -w 3 google.com", platform: "linux" },
  { flag: "-q <queries>", description: "Number of probe packets per hop (default 3)", example: "traceroute -q 5 google.com", platform: "linux" },
  { flag: "-I", description: "Use ICMP ECHO instead of UDP datagrams", example: "sudo traceroute -I google.com", platform: "linux" },
  { flag: "-T", description: "Use TCP SYN for probes", example: "sudo traceroute -T google.com", platform: "linux" },
  { flag: "-p <port>", description: "Set destination port for UDP/TCP", example: "traceroute -p 443 google.com", platform: "linux" },
  { flag: "-f <first_ttl>", description: "Start from specified TTL (default 1)", example: "traceroute -f 5 google.com", platform: "linux" },
  { flag: "-z <pause>", description: "Pause between probes in ms", example: "traceroute -z 100 google.com", platform: "linux" },
  { flag: "-A", description: "Perform AS path lookups (show ASN)", example: "traceroute -A google.com", platform: "linux" },
];

// ============================================================================
// Troubleshooting Scenarios
// ============================================================================

interface TroubleshootingScenario {
  symptom: string;
  possibleCauses: string[];
  diagnosticSteps: string[];
  solutions: string[];
}

const TROUBLESHOOTING_SCENARIOS: TroubleshootingScenario[] = [
  {
    symptom: "All hops show * * * (timeouts)",
    possibleCauses: [
      "Firewall blocking ICMP/UDP packets",
      "Target host is down or unreachable",
      "ISP filtering traceroute traffic",
      "Network interface issue",
    ],
    diagnosticSteps: [
      "Try pinging the target: ping <target>",
      "Use TCP mode: traceroute -T <target>",
      "Try different port: traceroute -p 443 <target>",
      "Check local firewall settings",
    ],
    solutions: [
      "Contact network admin about firewall rules",
      "Use alternative diagnostic tools (mtr, pathping)",
      "Try traceroute from different network",
    ],
  },
  {
    symptom: "High latency at specific hop",
    possibleCauses: [
      "Congested router or network segment",
      "Geographic distance causing natural latency",
      "Undersized/overloaded network equipment",
      "Routing inefficiency",
    ],
    diagnosticSteps: [
      "Run traceroute multiple times to confirm",
      "Check if latency is consistent",
      "Look up hop IP for geographic location",
      "Compare with traceroute to nearby targets",
    ],
    solutions: [
      "Report to ISP if persistent",
      "Consider alternative route (VPN)",
      "Check for network maintenance notices",
    ],
  },
  {
    symptom: "Packet loss at intermediate hop",
    possibleCauses: [
      "ICMP rate limiting on router (common, often benign)",
      "Actual network congestion",
      "Hardware issue on router",
      "Asymmetric routing",
    ],
    diagnosticSteps: [
      "Check if packet loss continues to final hops",
      "Run mtr for continuous monitoring",
      "Test during different times of day",
      "Check if loss affects actual application traffic",
    ],
    solutions: [
      "If loss doesn't affect final hop, likely ICMP rate limiting (ignore)",
      "Report to ISP if affecting real traffic",
      "Document for support tickets",
    ],
  },
  {
    symptom: "Route never reaches destination",
    possibleCauses: [
      "TTL exhausted before reaching target",
      "Routing loop in network",
      "Target behind NAT/firewall",
      "BGP routing issue",
    ],
    diagnosticSteps: [
      "Increase max hops: traceroute -m 64 <target>",
      "Look for repeating IP addresses (loop)",
      "Try reverse traceroute from target if possible",
      "Check BGP looking glass tools",
    ],
    solutions: [
      "Report routing loop to affected ISP",
      "Use VPN to bypass problematic path",
      "Wait for BGP convergence if recent change",
    ],
  },
];

// ============================================================================
// Nmap Integration Data - Combined Network Analysis
// ============================================================================

const NMAP_SCAN_TYPES = [
  { id: "ping", name: "Ping Sweep", description: "Host discovery only - no port scanning", intensity: 1, time: "5-30 sec" },
  { id: "quick", name: "Quick Scan", description: "Top 100 ports, no service detection", intensity: 2, time: "30-60 sec" },
  { id: "stealth", name: "Stealth SYN Scan", description: "SYN scan - fast and less detectable", intensity: 3, time: "1-3 min" },
  { id: "basic", name: "Basic Scan", description: "Top 1000 ports with service detection", intensity: 4, time: "3-10 min" },
  { id: "version", name: "Version Detection", description: "Detailed service version identification", intensity: 5, time: "3-10 min" },
  { id: "script", name: "Script Scan", description: "Default NSE scripts for common services", intensity: 6, time: "3-10 min" },
  { id: "udp_quick", name: "UDP Quick Scan", description: "Common UDP ports with service detection", intensity: 7, time: "5-15 min" },
  { id: "os_detect", name: "OS Detection", description: "Operating system fingerprinting", intensity: 8, time: "5-15 min" },
  { id: "vuln", name: "Vulnerability Scan", description: "Run vulnerability detection scripts", intensity: 9, time: "10-30 min" },
  { id: "aggressive", name: "Aggressive Scan", description: "OS, version, scripts, traceroute combined", intensity: 10, time: "10-20 min" },
  { id: "udp", name: "UDP Full Scan", description: "All common UDP ports with extensive probing", intensity: 11, time: "20-60 min" },
  { id: "comprehensive", name: "Comprehensive Scan", description: "TCP + UDP + OS + scripts + traceroute", intensity: 12, time: "20-45 min" },
  { id: "full_tcp", name: "Full TCP Scan", description: "All 65535 TCP ports with service detection", intensity: 13, time: "30-120 min" },
  { id: "full_all", name: "Full All Ports Scan", description: "All 65535 TCP + UDP ports with all detection methods", intensity: 14, time: "60-240 min" },
];

const NMAP_NSE_CATEGORIES = [
  { id: "vuln", name: "Vulnerability Scripts", description: "Checks for known vulnerabilities", warning: "May trigger IDS/IPS" },
  { id: "safe", name: "Safe Scripts", description: "Non-intrusive scripts that won't crash services", warning: null },
  { id: "discovery", name: "Discovery Scripts", description: "Enumerate services and gather info", warning: "Generates traffic" },
  { id: "auth", name: "Authentication Scripts", description: "Check for auth issues, default creds", warning: null },
  { id: "brute", name: "Brute Force Scripts", description: "Password brute forcing", warning: "May lock accounts" },
  { id: "exploit", name: "Exploit Scripts", description: "Attempt to exploit vulnerabilities", warning: "DANGEROUS - Authorized pentests only" },
  { id: "malware", name: "Malware Detection Scripts", description: "Detect malicious software and backdoors", warning: "May generate alerts" },
];

const COMBINED_WORKFLOW_STEPS = [
  {
    step: 1,
    title: "Network Path Discovery",
    tool: "Traceroute",
    icon: <RouteIcon />,
    description: "First, trace the network path to understand the topology between you and the target.",
    actions: ["Run traceroute to target", "Identify network segments", "Note filtering/firewalls"],
  },
  {
    step: 2,
    title: "Path Analysis",
    tool: "AI Analysis",
    icon: <AiIcon />,
    description: "AI analyzes the path to infer ISPs, geographic locations, and security posture.",
    actions: ["ISP identification", "Geographic path mapping", "Attack surface assessment"],
  },
  {
    step: 3,
    title: "Host Discovery",
    tool: "Nmap Ping Sweep",
    icon: <RadarIcon />,
    description: "Discover live hosts on the target network using Nmap ping scan.",
    actions: ["Identify live hosts", "Map network topology", "Prepare scan targets"],
  },
  {
    step: 4,
    title: "Port Scanning",
    tool: "Nmap Port Scan",
    icon: <ScannerIcon />,
    description: "Scan discovered hosts for open ports and running services.",
    actions: ["Identify open ports", "Detect services", "Version fingerprinting"],
  },
  {
    step: 5,
    title: "Vulnerability Assessment",
    tool: "Nmap NSE Scripts",
    icon: <BugReportIcon />,
    description: "Run vulnerability detection scripts against discovered services.",
    actions: ["CVE detection", "Misconfig identification", "Banner analysis"],
  },
  {
    step: 6,
    title: "Comprehensive Report",
    tool: "AI Analysis",
    icon: <AssessmentIcon />,
    description: "Generate AI-powered security report combining all findings.",
    actions: ["Risk scoring", "Remediation priorities", "Executive summary"],
  },
];

const HIGH_RISK_PORTS_SAMPLE = [
  { port: 21, service: "FTP", severity: "high", reason: "Often transmits credentials in cleartext" },
  { port: 22, service: "SSH", severity: "info", reason: "Verify strong authentication required" },
  { port: 23, service: "Telnet", severity: "critical", reason: "All data including credentials in cleartext" },
  { port: 445, service: "SMB", severity: "high", reason: "Common target for ransomware (EternalBlue)" },
  { port: 3306, service: "MySQL", severity: "high", reason: "Database exposure - verify authentication" },
  { port: 3389, service: "RDP", severity: "high", reason: "Remote Desktop - common brute force target" },
  { port: 6379, service: "Redis", severity: "critical", reason: "Often has no authentication by default" },
  { port: 27017, service: "MongoDB", severity: "critical", reason: "Often has no authentication by default" },
  { port: 2375, service: "Docker API", severity: "critical", reason: "Full container control if exposed" },
  { port: 9200, service: "Elasticsearch", severity: "critical", reason: "Often has no authentication" },
];

// ============================================================================
// Main Component
// ============================================================================

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div role="tabpanel" hidden={value !== index}>
    {value === index && <Box>{children}</Box>}
  </div>
);

// VRAgent Advanced Features Data
const AI_ANALYSIS_FEATURES = [
  {
    title: "Network Inference",
    icon: <AiIcon />,
    color: "#8b5cf6",
    items: [
      "ISP identification from hostname patterns (e.g., comcast, att, level3)",
      "Geographic path inference from router naming conventions",
      "ASN (Autonomous System Number) pattern detection",
      "Cloud provider detection (AWS, Azure, GCP, Cloudflare)",
      "Network type classification (residential, business, datacenter)",
    ],
  },
  {
    title: "Network Segments",
    icon: <LayersIcon />,
    color: "#3b82f6",
    items: [
      "Local Network (hops 1-2): Your router and local infrastructure",
      "ISP Network (hops 3-5): Your internet provider's infrastructure",
      "Transit/Backbone (hops 6-12): Internet backbone, IXPs, peering",
      "Destination Network (hops 13+): Target's hosting or CDN",
      "Automatic segment boundary detection",
    ],
  },
  {
    title: "Performance Grading",
    icon: <AssessmentIcon />,
    color: "#10b981",
    items: [
      "Overall grade A-F based on latency, loss, and consistency",
      "Bottleneck identification with specific hop flagging",
      "Jitter assessment (RTT variance per hop)",
      "Packet loss analysis with severity ratings",
      "Comparative performance against baseline expectations",
    ],
  },
];

const SECURITY_ANALYSIS_FEATURES = [
  {
    title: "Attack Surface Analysis",
    icon: <ShieldIcon />,
    color: "#ef4444",
    items: [
      "Exposed infrastructure identification",
      "Potential pivot points in the network path",
      "Filtering detection (which hops block probes)",
      "MITM position identification (where interception is possible)",
      "Network chokepoint discovery",
    ],
  },
  {
    title: "Security Observations",
    icon: <VisibilityIcon />,
    color: "#f59e0b",
    items: [
      "Severity-rated security findings (info/low/medium/high)",
      "Firewall placement inference",
      "Router fingerprinting indicators",
      "Geographic anomalies (unexpected routing)",
      "Cloud provider security posture assessment",
    ],
  },
  {
    title: "Risk Scoring",
    icon: <BugReportIcon />,
    color: "#ec4899",
    items: [
      "0-100 risk score based on path analysis",
      "Weighted factors: exposed hops, geographic path, filtering",
      "Actionable recommendations for mitigation",
      "Historical risk trend tracking",
      "Comparison with industry baselines",
    ],
  },
];

const ADVANCED_TRACE_MODES = [
  {
    mode: "Multi-Trace Analysis",
    icon: <CompareIcon />,
    description: "Run multiple traces to detect routing variance",
    features: [
      "Up to 5 consecutive traces with configurable delay",
      "Load balancing detection (ECMP/Per-flow)",
      "Divergence and convergence point identification",
      "Routing stability assessment",
      "AI-powered variance analysis",
    ],
  },
  {
    mode: "Batch Traceroute",
    icon: <BatchIcon />,
    description: "Trace multiple targets simultaneously",
    features: [
      "Up to 10 targets in parallel (3 concurrent)",
      "Combined network topology visualization",
      "Shared infrastructure identification",
      "Comparative performance analysis",
      "Automatic report saving per target",
    ],
  },
  {
    mode: "Historical Comparison",
    icon: <HistoryIcon />,
    description: "Compare saved traces to detect routing changes",
    features: [
      "Side-by-side path comparison",
      "Routing change detection with diff",
      "AI-powered change significance analysis",
      "Security implications of route changes",
      "Trend analysis over time",
    ],
  },
  {
    mode: "Interactive Chat",
    icon: <ChatIcon />,
    description: "Ask AI questions about traceroute results",
    features: [
      "Natural language queries about network paths",
      "Latency explanation and recommendations",
      "Security assessment on demand",
      "Troubleshooting guidance",
      "Context-aware responses based on trace data",
    ],
  },
];

const TracerouteGuidePage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [activeTab, setActiveTab] = useState(0);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("intro");
  const [scrollProgress, setScrollProgress] = useState(0);

  // Navigation items for sidebar
  const navigationItems = [
    { id: "intro", label: "Introduction", icon: <PublicIcon /> },
    { id: "overview", label: "Overview", icon: <InfoIcon /> },
    { id: "commands", label: "Commands", icon: <TerminalIcon /> },
    { id: "interpreting", label: "Interpreting Results", icon: <AssessmentIcon /> },
    { id: "troubleshooting", label: "Troubleshooting", icon: <WarningIcon /> },
    { id: "security", label: "Security", icon: <ShieldIcon /> },
    { id: "ai-analysis", label: "AI Analysis", icon: <AiIcon /> },
    { id: "nmap-integration", label: "Nmap Integration", icon: <RadarIcon /> },
  ];

  // Scroll tracking
  useEffect(() => {
    const handleScroll = () => {
      const totalHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = (window.scrollY / totalHeight) * 100;
      setScrollProgress(progress);

      // Update active section based on scroll position
      const sections = navigationItems.map(item => document.getElementById(item.id));
      for (let i = sections.length - 1; i >= 0; i--) {
        const section = sections[i];
        if (section) {
          const rect = section.getBoundingClientRect();
          if (rect.top <= 150) {
            setActiveSection(navigationItems[i].id);
            break;
          }
        }
      }
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    setMobileNavOpen(false);
  };

  const pageContext = `This page covers the combined Nmap & Traceroute Analyzer with 4 analysis modes:
- Traceroute Path Analysis: Hop-by-hop network path discovery with latency and packet loss tracking
- Nmap Scan Mode: Live network scanning with 14 scan types (ping sweep, quick, stealth, basic, version, script, UDP, OS detection, vulnerability, aggressive, comprehensive)
- Nmap File Analyzer: Upload and analyze existing Nmap XML/nmap/gnmap output files
- Nmap Command Builder: Interactive NSE script selector with custom command generation
- Platform support: Windows (tracert), Linux/macOS (traceroute), MTR fallback
- AI-powered security assessment with risk scoring (0-100), attack surface analysis, and remediation guidance
- Network topology visualization with host relationships and service detection
- NSE script categories: vuln, safe, discovery, auth, brute, exploit, malware
- Export capabilities: JSON, Markdown, PDF, DOCX for professional reporting`;

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCommand(cmd);
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  const CodeBlock: React.FC<{ code: string; language?: string }> = ({ code, language = "bash" }) => (
    <Box
      sx={{
        position: "relative",
        bgcolor: "#1e1e1e",
        borderRadius: 1,
        p: 2,
        fontFamily: "monospace",
        fontSize: "0.875rem",
        color: "#d4d4d4",
        overflow: "auto",
      }}
    >
      <IconButton
        size="small"
        onClick={() => copyCommand(code)}
        sx={{
          position: "absolute",
          top: 8,
          right: 8,
          color: copiedCommand === code ? "#10b981" : "#888",
        }}
      >
        {copiedCommand === code ? <CheckIcon fontSize="small" /> : <CopyIcon fontSize="small" />}
      </IconButton>
      <code>{code}</code>
    </Box>
  );

  // Sidebar Navigation Component
  const SidebarNavigation = () => (
    <Box
      sx={{
        position: "sticky",
        top: 80,
        width: 240,
        flexShrink: 0,
        display: { xs: "none", md: "block" },
      }}
    >
      <Paper sx={{ p: 2, borderRadius: 2 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <ListAltIcon sx={{ color: ACCENT_COLOR }} />
          <Typography variant="subtitle2" fontWeight="bold">
            Contents
          </Typography>
        </Box>
        <LinearProgress
          variant="determinate"
          value={scrollProgress}
          sx={{
            mb: 2,
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(ACCENT_COLOR, 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR },
          }}
        />
        <List dense>
          {navigationItems.map((item) => (
            <ListItem
              key={item.id}
              component="button"
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1,
                mb: 0.5,
                bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.1) : "transparent",
                border: "none",
                cursor: "pointer",
                width: "100%",
                textAlign: "left",
                "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.05) },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? ACCENT_COLOR : "text.secondary" }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  fontWeight: activeSection === item.id ? "bold" : "normal",
                  color: activeSection === item.id ? ACCENT_COLOR : "text.primary",
                }}
              />
            </ListItem>
          ))}
        </List>
        <Divider sx={{ my: 2 }} />
        <Button
          component={Link}
          to="/dynamic/traceroute"
          fullWidth
          variant="contained"
          size="small"
          sx={{ bgcolor: ACCENT_COLOR, "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.8) } }}
        >
          Launch Analyzer
        </Button>
      </Paper>
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="Nmap & Traceroute Analyzer" pageContext={pageContext}>
    <Box sx={{ p: 3, display: "flex", gap: 3 }}>
      {/* Sidebar Navigation */}
      <SidebarNavigation />

      {/* Mobile Navigation FAB */}
      {isMobile && (
        <Fab
          size="small"
          onClick={() => setMobileNavOpen(true)}
          sx={{
            position: "fixed",
            bottom: 80,
            right: 16,
            bgcolor: ACCENT_COLOR,
            "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.8) },
          }}
        >
          <ListAltIcon />
        </Fab>
      )}

      {/* Scroll to Top FAB */}
      {isMobile && scrollProgress > 20 && (
        <Fab
          size="small"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          sx={{
            position: "fixed",
            bottom: 140,
            right: 16,
            bgcolor: alpha(ACCENT_COLOR, 0.8),
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      )}

      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="right"
        open={mobileNavOpen}
        onClose={() => setMobileNavOpen(false)}
      >
        <Box sx={{ width: 280, p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6">Contents</Typography>
            <IconButton onClick={() => setMobileNavOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>
          <List>
            {navigationItems.map((item) => (
              <ListItem
                key={item.id}
                component="button"
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 1,
                  mb: 0.5,
                  bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.1) : "transparent",
                  border: "none",
                  cursor: "pointer",
                  width: "100%",
                  textAlign: "left",
                }}
              >
                <ListItemIcon sx={{ color: activeSection === item.id ? ACCENT_COLOR : "text.secondary" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>

      {/* Main Content */}
      <Box sx={{ flex: 1, minWidth: 0 }}>
      {/* Back Link */}
      <Box sx={{ mb: 3 }} id="intro">
        <Chip
          component={Link}
          to="/learn"
          icon={<BackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2 }}
        />
      </Box>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <RouteIcon sx={{ fontSize: 40, color: ACCENT_COLOR }} />
        <Box>
          <Typography variant="h4" sx={{ fontWeight: "bold" }}>
            Nmap & Traceroute Analyzer Guide
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Master 4-in-1 network analysis: Traceroute path discovery, live Nmap scanning, file analysis, and custom command building
          </Typography>
        </Box>
        <Box sx={{ flex: 1 }} />
        <Button
          component={Link}
          to="/dynamic/traceroute"
          variant="contained"
          sx={{
            bgcolor: ACCENT_COLOR,
            "&:hover": { bgcolor: "#db2777" },
          }}
        >
          Launch Analyzer
        </Button>
      </Box>

      {/* Tabs */}
      <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 3 }} variant="scrollable" scrollButtons="auto">
        <Tab label="Overview" />
        <Tab label="Commands & Options" />
        <Tab label="Interpreting Results" />
        <Tab label="Troubleshooting" />
        <Tab label="Security" />
        <Tab label="VRAgent AI Analysis" icon={<AiIcon />} iconPosition="start" />
        <Tab label="Nmap Integration" icon={<RadarIcon />} iconPosition="start" />
      </Tabs>

      {/* Tab 0: Overview */}
      <Box id="overview">
      {activeTab === 0 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <PublicIcon color="primary" />
                4-in-1 Network Analysis Tool
              </Typography>
              <Typography variant="body1" paragraph>
                VRAgent's Nmap & Traceroute Analyzer combines 4 powerful network analysis modes into a single interface:
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                <strong>Mode 1: Traceroute Path Analysis</strong> - Hop-by-hop network path discovery with latency and packet loss tracking. Maps the route packets take from your computer to any destination.<br/><br/>
                <strong>Mode 2: Nmap Live Scanning</strong> - Execute 14 different Nmap scan types (ping sweep, stealth SYN, version detection, vulnerability scans, OS detection, comprehensive scans) directly from the interface.<br/><br/>
                <strong>Mode 3: Nmap File Analyzer</strong> - Upload and analyze existing Nmap output files (XML, .nmap, .gnmap formats) with AI-powered security assessment.<br/><br/>
                <strong>Mode 4: Nmap Command Builder</strong> - Interactive NSE script selector with 7 categories (vuln, safe, discovery, auth, brute, exploit, malware) for custom command generation.
              </Alert>

              <Grid container spacing={2}>
                <Grid item xs={12} md={3}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#3b82f6", 0.1) }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        <RouteIcon sx={{ mr: 1, color: "#3b82f6" }} />
                        Path Tracing
                      </Typography>
                      <Typography variant="body2">
                        Hop-by-hop network path discovery with latency tracking and packet loss detection.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#10b981", 0.1) }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        <RadarIcon sx={{ mr: 1, color: "#10b981" }} />
                        Live Scanning
                      </Typography>
                      <Typography variant="body2">
                        14 Nmap scan types from quick ping sweeps to comprehensive vulnerability assessments.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        <UploadFileIcon sx={{ mr: 1, color: "#8b5cf6" }} />
                        File Analysis
                      </Typography>
                      <Typography variant="body2">
                        Upload existing Nmap XML/nmap/gnmap files for AI-powered security assessment.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#f59e0b", 0.1) }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        <BuildIcon sx={{ mr: 1, color: "#f59e0b" }} />
                        Command Builder
                      </Typography>
                      <Typography variant="body2">
                        Interactive NSE script selector with 7 categories for custom Nmap command generation.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <Typography variant="h6" gutterBottom>Quick Start Guide</Typography>

              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <RouteIcon sx={{ fontSize: 18, color: "#3b82f6" }} />
                Mode 1: Traceroute Path Analysis
              </Typography>
              <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                Enter a target domain or IP to discover the network path
              </Typography>
              <CodeBlock code="traceroute google.com" />

              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <RadarIcon sx={{ fontSize: 18, color: "#10b981" }} />
                Mode 2: Nmap Live Scanning
              </Typography>
              <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                Select from 14 scan types (quick, stealth, vulnerability, comprehensive, etc.)
              </Typography>
              <CodeBlock code="nmap -sV -sC 192.168.1.1" />

              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <UploadFileIcon sx={{ fontSize: 18, color: "#8b5cf6" }} />
                Mode 3: Nmap File Analyzer
              </Typography>
              <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                Upload .xml, .nmap, or .gnmap files for AI analysis
              </Typography>

              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <BuildIcon sx={{ fontSize: 18, color: "#f59e0b" }} />
                Mode 4: Nmap Command Builder
              </Typography>
              <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                Interactive NSE script selector with custom command generation
              </Typography>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <Typography variant="h6" gutterBottom>Understanding Output</Typography>
              
              <Box sx={{ bgcolor: "#1e1e1e", p: 2, borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4", mb: 2 }}>
                <Box sx={{ color: "#888" }}># traceroute to google.com (142.250.80.46)</Box>
                <Box><span style={{ color: "#f59e0b" }}>1</span>  192.168.1.1    <span style={{ color: "#10b981" }}>1.2ms</span>  <span style={{ color: "#10b981" }}>0.9ms</span>  <span style={{ color: "#10b981" }}>1.1ms</span></Box>
                <Box><span style={{ color: "#f59e0b" }}>2</span>  10.0.0.1       <span style={{ color: "#10b981" }}>8.5ms</span>  <span style={{ color: "#10b981" }}>9.1ms</span>  <span style={{ color: "#10b981" }}>8.8ms</span></Box>
                <Box><span style={{ color: "#f59e0b" }}>3</span>  * * *</Box>
                <Box><span style={{ color: "#f59e0b" }}>4</span>  72.14.215.85   <span style={{ color: "#f59e0b" }}>25.3ms</span>  <span style={{ color: "#f59e0b" }}>24.8ms</span>  <span style={{ color: "#f59e0b" }}>25.1ms</span></Box>
                <Box><span style={{ color: "#f59e0b" }}>5</span>  142.250.80.46  <span style={{ color: "#10b981" }}>23.5ms</span>  <span style={{ color: "#10b981" }}>23.2ms</span>  <span style={{ color: "#10b981" }}>23.4ms</span></Box>
              </Box>
              
              <List dense>
                <ListItem>
                  <ListItemIcon><Chip label="1" size="small" sx={{ bgcolor: "#f59e0b", color: "white" }} /></ListItemIcon>
                  <ListItemText primary="Hop number" secondary="Sequential count from source" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><Chip label="IP" size="small" variant="outlined" /></ListItemIcon>
                  <ListItemText primary="Router IP/hostname" secondary="Identity of each hop" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><Chip label="ms" size="small" sx={{ bgcolor: "#10b981", color: "white" }} /></ListItemIcon>
                  <ListItemText primary="Round-trip times" secondary="Latency for each probe" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><Chip label="* * *" size="small" /></ListItemIcon>
                  <ListItemText primary="Timeout" secondary="No response (firewall or rate limit)" />
                </ListItem>
              </List>
            </Paper>
          </Grid>
        </Grid>
      )}
      </Box>

      {/* Tab 1: Commands & Options */}
      <Box id="commands">
      {activeTab === 1 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon color="primary" />
                Windows (tracert)
              </Typography>
              
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Option</TableCell>
                      <TableCell>Description</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {WINDOWS_OPTIONS.map((opt, i) => (
                      <TableRow key={i}>
                        <TableCell>
                          <code style={{ color: "#ec4899" }}>{opt.flag}</code>
                        </TableCell>
                        <TableCell>
                          {opt.description}
                          {opt.example && (
                            <Box sx={{ mt: 0.5 }}>
                              <Chip 
                                label={opt.example} 
                                size="small" 
                                onClick={() => copyCommand(opt.example!)}
                                sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}
                              />
                            </Box>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon color="primary" />
                Linux/macOS (traceroute)
              </Typography>
              
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Option</TableCell>
                      <TableCell>Description</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {LINUX_OPTIONS.map((opt, i) => (
                      <TableRow key={i}>
                        <TableCell>
                          <code style={{ color: "#ec4899" }}>{opt.flag}</code>
                        </TableCell>
                        <TableCell>
                          {opt.description}
                          {opt.example && (
                            <Box sx={{ mt: 0.5 }}>
                              <Chip 
                                label={opt.example} 
                                size="small" 
                                onClick={() => copyCommand(opt.example!)}
                                sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}
                              />
                            </Box>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Alternative Tools</Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold">mtr (My Traceroute)</Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Combines ping and traceroute into a continuous real-time display.
                      </Typography>
                      <CodeBlock code="mtr google.com" />
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold">pathping (Windows)</Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Extended traceroute with packet loss statistics over time.
                      </Typography>
                      <CodeBlock code="pathping google.com" />
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold">tcptraceroute</Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Uses TCP SYN packets to trace through firewalls.
                      </Typography>
                      <CodeBlock code="tcptraceroute -p 443 google.com" />
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      )}
      </Box>

      {/* Tab 2: Interpreting Results */}
      <Box id="interpreting">
      {activeTab === 2 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Latency Patterns</Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Card sx={{ bgcolor: alpha("#10b981", 0.1), height: "100%" }}>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" color="success.main">
                        ✓ Healthy Pattern
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", my: 1 }}>
                        1: 1ms → 2: 5ms → 3: 15ms → 4: 25ms → 5: 30ms
                      </Box>
                      <Typography variant="body2">
                        Gradual, consistent increase in latency. Each hop adds predictable delay 
                        based on distance and network conditions.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Card sx={{ bgcolor: alpha("#ef4444", 0.1), height: "100%" }}>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" color="error.main">
                        ✗ Problem Pattern
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", my: 1 }}>
                        1: 1ms → 2: 5ms → 3: <span style={{ color: "#ef4444" }}>150ms</span> → 4: 155ms → 5: 160ms
                      </Box>
                      <Typography variant="body2">
                        Sudden jump in latency at hop 3. The bottleneck affects all subsequent hops. 
                        Issue is likely at or just before hop 3.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Network Segments</Typography>
              <List>
                <ListItem>
                  <ListItemIcon><Chip label="1-2" size="small" sx={{ bgcolor: "#3b82f6", color: "white" }} /></ListItemIcon>
                  <ListItemText 
                    primary="Local Network" 
                    secondary="Your router, home/office network. Usually 1-5ms." 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><Chip label="3-5" size="small" sx={{ bgcolor: "#8b5cf6", color: "white" }} /></ListItemIcon>
                  <ListItemText 
                    primary="ISP Network" 
                    secondary="Your internet provider's infrastructure. Typically 10-30ms." 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><Chip label="6-12" size="small" sx={{ bgcolor: "#f59e0b", color: "white" }} /></ListItemIcon>
                  <ListItemText 
                    primary="Transit/Backbone" 
                    secondary="Internet backbone, peering points. Can vary widely." 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><Chip label="13+" size="small" sx={{ bgcolor: "#10b981", color: "white" }} /></ListItemIcon>
                  <ListItemText 
                    primary="Destination Network" 
                    secondary="Target's hosting provider or CDN." 
                  />
                </ListItem>
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Common Indicators</Typography>
              
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningIcon color="warning" />
                    <Typography>Asterisks (* * *)</Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2">
                    <strong>Not always a problem!</strong> Many routers are configured to not respond 
                    to traceroute probes (ICMP rate limiting). If the trace completes successfully, 
                    intermediate timeouts are usually benign.
                  </Typography>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <InfoIcon color="info" />
                    <Typography>Asymmetric Paths</Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2">
                    The return path may differ from the outbound path. High RTT at a hop might 
                    actually be caused by a slow return route, not the outbound hop itself.
                  </Typography>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <ErrorIcon color="error" />
                    <Typography>Routing Loops</Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2">
                    If you see the same IPs repeating in sequence, there's a routing loop. 
                    This is a serious network misconfiguration that should be reported to the ISP.
                  </Typography>
                </AccordionDetails>
              </Accordion>
            </Paper>
          </Grid>
        </Grid>
      )}
      </Box>

      {/* Tab 3: Troubleshooting */}
      <Box id="troubleshooting">
      {activeTab === 3 && (
        <Grid container spacing={3}>
          {TROUBLESHOOTING_SCENARIOS.map((scenario, index) => (
            <Grid item xs={12} key={index}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <WarningIcon color="warning" />
                    <Typography variant="h6">{scenario.symptom}</Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={4}>
                      <Typography variant="subtitle2" color="error.main" gutterBottom>
                        Possible Causes
                      </Typography>
                      <List dense>
                        {scenario.possibleCauses.map((cause, i) => (
                          <ListItem key={i}>
                            <ListItemIcon><ErrorIcon fontSize="small" color="error" /></ListItemIcon>
                            <ListItemText primary={cause} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Typography variant="subtitle2" color="info.main" gutterBottom>
                        Diagnostic Steps
                      </Typography>
                      <List dense>
                        {scenario.diagnosticSteps.map((step, i) => (
                          <ListItem key={i}>
                            <ListItemIcon><InfoIcon fontSize="small" color="info" /></ListItemIcon>
                            <ListItemText primary={step} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Typography variant="subtitle2" color="success.main" gutterBottom>
                        Solutions
                      </Typography>
                      <List dense>
                        {scenario.solutions.map((solution, i) => (
                          <ListItem key={i}>
                            <ListItemIcon><CheckIcon fontSize="small" color="success" /></ListItemIcon>
                            <ListItemText primary={solution} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </Grid>
          ))}
        </Grid>
      )}
      </Box>

      {/* Tab 4: Security */}
      <Box id="security">
      {activeTab === 4 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Alert severity="warning" sx={{ mb: 3 }}>
              <strong>Security Note:</strong> Traceroute reveals your network topology to the target. 
              Be mindful when tracing to unknown or potentially hostile destinations.
            </Alert>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon color="error" />
                Security Implications
              </Typography>
              
              <List>
                <ListItem>
                  <ListItemIcon><WarningIcon color="warning" /></ListItemIcon>
                  <ListItemText 
                    primary="Network Reconnaissance" 
                    secondary="Attackers use traceroute to map target networks and identify infrastructure." 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><WarningIcon color="warning" /></ListItemIcon>
                  <ListItemText 
                    primary="Firewall Detection" 
                    secondary="Gaps in traceroute output can reveal firewall placement." 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><WarningIcon color="warning" /></ListItemIcon>
                  <ListItemText 
                    primary="Router Fingerprinting" 
                    secondary="TTL behavior and response patterns can identify router vendors." 
                  />
                </ListItem>
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <CheckIcon color="success" />
                Defensive Measures
              </Typography>
              
              <List>
                <ListItem>
                  <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="ICMP Rate Limiting" 
                    secondary="Configure routers to limit ICMP responses (commonly done)." 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Firewall Rules" 
                    secondary="Block inbound traceroute probes at perimeter firewalls." 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Network Segmentation" 
                    secondary="Internal network structure should be hidden from external probes." 
                  />
                </ListItem>
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Penetration Testing Use Cases</Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold">Path Discovery</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Map the network path to targets during reconnaissance phase. 
                        Identify chokepoints and potential defensive measures.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold">Firewall Evasion Testing</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Use TCP traceroute (-T) to test if ICMP is blocked but TCP passes. 
                        Test different ports for firewall rule gaps.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold">ISP/CDN Identification</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Identify what infrastructure sits between you and the target. 
                        Useful for understanding the attack surface.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      )}
      </Box>

      {/* Tab 5: VRAgent AI Analysis */}
      <Box id="ai-analysis">
      {activeTab === 5 && (
        <Grid container spacing={3}>
          {/* Header Alert */}
          <Grid item xs={12}>
            <Alert 
              severity="info" 
              icon={<AiIcon />}
              sx={{ 
                bgcolor: alpha("#8b5cf6", 0.1), 
                border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
                "& .MuiAlert-icon": { color: "#8b5cf6" }
              }}
            >
              <Typography variant="subtitle2" fontWeight="bold">
                VRAgent AI-Powered Network Analysis
              </Typography>
              <Typography variant="body2">
                VRAgent extends traditional traceroute with AI-powered analysis, providing deep insights into 
                network topology, security posture, and performance characteristics. Features include ISP inference, 
                geographic path analysis, attack surface assessment, and risk scoring.
              </Typography>
            </Alert>
          </Grid>

          {/* AI Analysis Features */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <AiIcon sx={{ color: "#8b5cf6" }} />
                AI Network Intelligence
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                VRAgent's AI engine analyzes every traceroute to extract actionable intelligence about the network path.
              </Typography>
              
              <Grid container spacing={2}>
                {AI_ANALYSIS_FEATURES.map((feature, index) => (
                  <Grid item xs={12} md={4} key={index}>
                    <Card 
                      variant="outlined" 
                      sx={{ 
                        height: "100%",
                        borderColor: alpha(feature.color, 0.3),
                        "&:hover": { borderColor: feature.color }
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                          <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                          <Typography variant="subtitle1" fontWeight="bold">
                            {feature.title}
                          </Typography>
                        </Box>
                        <List dense>
                          {feature.items.map((item, i) => (
                            <ListItem key={i} sx={{ py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckIcon sx={{ fontSize: 14, color: feature.color }} />
                              </ListItemIcon>
                              <ListItemText 
                                primary={item} 
                                primaryTypographyProps={{ variant: "body2" }}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          {/* Security Analysis */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon sx={{ color: "#ef4444" }} />
                Security & Risk Analysis
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Every trace is analyzed for security implications, identifying potential vulnerabilities and attack vectors.
              </Typography>
              
              <Grid container spacing={2}>
                {SECURITY_ANALYSIS_FEATURES.map((feature, index) => (
                  <Grid item xs={12} md={4} key={index}>
                    <Card 
                      variant="outlined"
                      sx={{ 
                        height: "100%",
                        borderColor: alpha(feature.color, 0.3),
                        "&:hover": { borderColor: feature.color }
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                          <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                          <Typography variant="subtitle1" fontWeight="bold">
                            {feature.title}
                          </Typography>
                        </Box>
                        <List dense>
                          {feature.items.map((item, i) => (
                            <ListItem key={i} sx={{ py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <WarningIcon sx={{ fontSize: 14, color: feature.color }} />
                              </ListItemIcon>
                              <ListItemText 
                                primary={item} 
                                primaryTypographyProps={{ variant: "body2" }}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          {/* Risk Score Visualization */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ec4899" }} />
                Risk Scoring System
              </Typography>
              
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid item xs={12} md={3}>
                  <Card sx={{ bgcolor: alpha("#10b981", 0.1), textAlign: "center", p: 2 }}>
                    <Typography variant="h3" fontWeight="bold" color="success.main">0-25</Typography>
                    <Typography variant="subtitle2" color="text.secondary">Low Risk</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      Clean path, no suspicious hops, standard routing
                    </Typography>
                  </Card>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Card sx={{ bgcolor: alpha("#3b82f6", 0.1), textAlign: "center", p: 2 }}>
                    <Typography variant="h3" fontWeight="bold" color="info.main">26-50</Typography>
                    <Typography variant="subtitle2" color="text.secondary">Moderate Risk</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      Some filtering detected, minor routing anomalies
                    </Typography>
                  </Card>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Card sx={{ bgcolor: alpha("#f59e0b", 0.1), textAlign: "center", p: 2 }}>
                    <Typography variant="h3" fontWeight="bold" color="warning.main">51-75</Typography>
                    <Typography variant="subtitle2" color="text.secondary">Elevated Risk</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      Geographic anomalies, exposed infrastructure
                    </Typography>
                  </Card>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Card sx={{ bgcolor: alpha("#ef4444", 0.1), textAlign: "center", p: 2 }}>
                    <Typography variant="h3" fontWeight="bold" color="error.main">76-100</Typography>
                    <Typography variant="subtitle2" color="text.secondary">High Risk</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      Suspicious routing, potential MITM positions
                    </Typography>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          {/* Advanced Trace Modes */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <AccountTreeIcon sx={{ color: "#3b82f6" }} />
                Advanced Trace Modes
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                VRAgent offers specialized trace modes for different analysis needs.
              </Typography>
              
              <Grid container spacing={2}>
                {ADVANCED_TRACE_MODES.map((mode, index) => (
                  <Grid item xs={12} md={6} key={index}>
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                          <Box sx={{ color: "#8b5cf6" }}>{mode.icon}</Box>
                          <Box>
                            <Typography variant="subtitle1" fontWeight="bold">{mode.mode}</Typography>
                            <Typography variant="body2" color="text.secondary">{mode.description}</Typography>
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <List dense>
                          {mode.features.map((feature, i) => (
                            <ListItem key={i}>
                              <ListItemIcon>
                                <CheckIcon sx={{ fontSize: 16, color: "#10b981" }} />
                              </ListItemIcon>
                              <ListItemText primary={feature} />
                            </ListItem>
                          ))}
                        </List>
                      </AccordionDetails>
                    </Accordion>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          {/* AI Analysis JSON Structure */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon sx={{ color: "#f59e0b" }} />
                AI Analysis Output Structure
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Each traceroute generates a comprehensive AI analysis with the following structure:
              </Typography>
              
              <Box
                sx={{
                  bgcolor: "#1e1e1e",
                  borderRadius: 1,
                  p: 2,
                  fontFamily: "monospace",
                  fontSize: "0.75rem",
                  color: "#d4d4d4",
                  overflow: "auto",
                  maxHeight: 400,
                }}
              >
                <pre style={{ margin: 0 }}>{`{
  "summary": "Comprehensive network path analysis summary",
  "network_inference": {
    "isp_identified": "Comcast Business",
    "geographic_path": ["Seattle", "San Jose", "Los Angeles"],
    "asn_patterns": ["AS7922 (Comcast)", "AS15169 (Google)"],
    "cloud_providers": ["Google Cloud", "Cloudflare"],
    "network_type": "business"
  },
  "network_segments": [
    {"segment": "Local", "hops": [1, 2], "ownership": "Private"},
    {"segment": "ISP", "hops": [3, 4, 5], "ownership": "Comcast"},
    {"segment": "Transit", "hops": [6, 7, 8], "ownership": "Level3"},
    {"segment": "Destination", "hops": [9, 10], "ownership": "Google"}
  ],
  "performance_analysis": {
    "overall_grade": "B+",
    "bottlenecks": ["Hop 5: 45ms latency spike"],
    "jitter_assessment": "Low variance (2-5ms)",
    "packet_loss": "No significant loss detected"
  },
  "security_observations": [
    {
      "observation": "ICMP filtering at hop 7",
      "severity": "info",
      "implication": "Standard security practice"
    },
    {
      "observation": "Geographic hop to unexpected region",
      "severity": "medium",
      "implication": "Potential traffic routing concern"
    }
  ],
  "attack_surface_analysis": {
    "exposed_infrastructure": ["10.0.0.1", "72.14.215.85"],
    "mitm_positions": ["Hops 5-6: ISP to transit boundary"],
    "filtering_detected": ["Hop 7 blocks ICMP"],
    "pivot_points": ["Hop 4: Access to ISP network"]
  },
  "recommendations": [
    "Monitor hop 5 for persistent latency",
    "Consider VPN for sensitive traffic",
    "Verify expected geographic path"
  ],
  "risk_score": 35
}`}</pre>
              </Box>
            </Paper>
          </Grid>

          {/* Report Features */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <AssessmentIcon sx={{ color: "#10b981" }} />
                Report & History Features
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <StorageIcon sx={{ color: "#3b82f6" }} />
                        Save Reports
                      </Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Automatically save traceroute results and AI analysis for future reference.
                      </Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• Full trace data preservation" /></ListItem>
                        <ListItem><ListItemText primary="• AI analysis included" /></ListItem>
                        <ListItem><ListItemText primary="• Project organization" /></ListItem>
                        <ListItem><ListItemText primary="• Risk score tracking" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <HistoryIcon sx={{ color: "#f59e0b" }} />
                        Historical Analysis
                      </Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Track routing changes over time for any target.
                      </Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• Last 10 traces to any target" /></ListItem>
                        <ListItem><ListItemText primary="• Path change detection" /></ListItem>
                        <ListItem><ListItemText primary="• Performance trending" /></ListItem>
                        <ListItem><ListItemText primary="• Anomaly identification" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CompareIcon sx={{ color: "#8b5cf6" }} />
                        Compare Traces
                      </Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Side-by-side comparison of multiple traces with AI analysis.
                      </Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• Path difference highlighting" /></ListItem>
                        <ListItem><ListItemText primary="• Routing stability assessment" /></ListItem>
                        <ListItem><ListItemText primary="• Change significance scoring" /></ListItem>
                        <ListItem><ListItemText primary="• Security impact analysis" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          {/* Streaming Progress */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <TimelineIcon sx={{ color: "#ec4899" }} />
                Real-Time Streaming Analysis
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                VRAgent provides real-time streaming of traceroute progress with live hop updates.
              </Typography>
              
              <Card variant="outlined" sx={{ p: 2, bgcolor: alpha("#1e1e1e", 0.5) }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Chip label="LIVE" color="success" size="small" sx={{ animation: "pulse 2s infinite" }} />
                  <Typography variant="body2" color="text.secondary">
                    Tracing route to google.com (142.250.80.46)...
                  </Typography>
                </Box>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4" }}>
                  <Box sx={{ mb: 0.5 }}>✓ Hop 1: 192.168.1.1 (1.2ms)</Box>
                  <Box sx={{ mb: 0.5 }}>✓ Hop 2: 10.0.0.1 (8.5ms)</Box>
                  <Box sx={{ mb: 0.5 }}>✓ Hop 3: 72.14.215.85 (25.3ms)</Box>
                  <Box sx={{ color: "#f59e0b" }}>⟳ Hop 4: Probing...</Box>
                </Box>
                <LinearProgress sx={{ mt: 2, bgcolor: alpha("#8b5cf6", 0.2), "& .MuiLinearProgress-bar": { bgcolor: "#8b5cf6" } }} />
              </Card>
            </Paper>
          </Grid>
        </Grid>
      )}
      </Box>

      {/* Tab 6: Nmap Integration */}
      <Box id="nmap-integration">
      {activeTab === 6 && (
        <Grid container spacing={3}>
          {/* Header Alert */}
          <Grid item xs={12}>
            <Alert 
              severity="info" 
              icon={<RadarIcon />}
              sx={{ 
                bgcolor: alpha("#3b82f6", 0.1), 
                border: `1px solid ${alpha("#3b82f6", 0.3)}`,
                "& .MuiAlert-icon": { color: "#3b82f6" }
              }}
            >
              <Typography variant="subtitle2" fontWeight="bold">
                Combined Network Analysis: Traceroute + Nmap
              </Typography>
              <Typography variant="body2">
                VRAgent integrates traceroute network path analysis with Nmap port scanning to provide 
                comprehensive security assessments. Discover the route to your target, then scan for 
                vulnerabilities along the path.
              </Typography>
            </Alert>
          </Grid>

          {/* Combined Workflow */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <AccountTreeIcon sx={{ color: "#3b82f6" }} />
                Combined Network Analysis Workflow
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Follow this workflow for comprehensive network security assessment combining path discovery with vulnerability scanning.
              </Typography>
              
              <Grid container spacing={2}>
                {COMBINED_WORKFLOW_STEPS.map((step, index) => (
                  <Grid item xs={12} md={4} key={index}>
                    <Card 
                      variant="outlined"
                      sx={{ 
                        height: "100%",
                        borderColor: alpha("#3b82f6", 0.3),
                        position: "relative",
                        overflow: "visible",
                        "&:hover": { borderColor: "#3b82f6" }
                      }}
                    >
                      <Box
                        sx={{
                          position: "absolute",
                          top: -12,
                          left: 16,
                          bgcolor: "#3b82f6",
                          color: "white",
                          borderRadius: "50%",
                          width: 32,
                          height: 32,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontWeight: "bold",
                          fontSize: "0.875rem",
                        }}
                      >
                        {step.step}
                      </Box>
                      <CardContent sx={{ pt: 3 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <Box sx={{ color: "#3b82f6" }}>{step.icon}</Box>
                          <Typography variant="subtitle1" fontWeight="bold">
                            {step.title}
                          </Typography>
                        </Box>
                        <Chip label={step.tool} size="small" sx={{ mb: 1, bgcolor: alpha("#3b82f6", 0.1) }} />
                        <Typography variant="body2" color="text.secondary" paragraph>
                          {step.description}
                        </Typography>
                        <List dense>
                          {step.actions.map((action, i) => (
                            <ListItem key={i} sx={{ py: 0, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckIcon sx={{ fontSize: 14, color: "#10b981" }} />
                              </ListItemIcon>
                              <ListItemText 
                                primary={action} 
                                primaryTypographyProps={{ variant: "body2" }}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          {/* Nmap Scan Types */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <ScannerIcon sx={{ color: "#8b5cf6" }} />
                Nmap Scan Types (14 Options)
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                VRAgent supports 14 different Nmap scan types, ordered from least to most intensive. Choose based on your needs and time constraints.
              </Typography>
              
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Scan Type</TableCell>
                      <TableCell>Description</TableCell>
                      <TableCell align="center">Intensity</TableCell>
                      <TableCell align="center">Est. Time</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {NMAP_SCAN_TYPES.map((scan) => (
                      <TableRow key={scan.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold" sx={{ color: ACCENT_COLOR }}>
                            {scan.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">{scan.description}</Typography>
                        </TableCell>
                        <TableCell align="center">
                          <LinearProgress
                            variant="determinate"
                            value={(scan.intensity / 14) * 100}
                            sx={{
                              width: 60,
                              height: 6,
                              borderRadius: 3,
                              bgcolor: alpha("#8b5cf6", 0.1),
                              "& .MuiLinearProgress-bar": {
                                bgcolor: scan.intensity <= 4 ? "#10b981" : scan.intensity <= 8 ? "#f59e0b" : "#ef4444",
                              },
                            }}
                          />
                        </TableCell>
                        <TableCell align="center">
                          <Chip label={scan.time} size="small" variant="outlined" />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          {/* NSE Script Categories */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <ExtensionIcon sx={{ color: "#f59e0b" }} />
                NSE Script Categories
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Nmap Scripting Engine (NSE) categories for extended scanning capabilities.
              </Typography>
              
              <List>
                {NMAP_NSE_CATEGORIES.map((cat) => (
                  <ListItem key={cat.id} sx={{ flexDirection: "column", alignItems: "flex-start", py: 1 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                      <Chip 
                        label={cat.id} 
                        size="small" 
                        sx={{ 
                          bgcolor: cat.warning ? alpha("#ef4444", 0.1) : alpha("#10b981", 0.1),
                          color: cat.warning ? "#ef4444" : "#10b981",
                        }} 
                      />
                      <Typography variant="subtitle2" fontWeight="bold">{cat.name}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                      {cat.description}
                    </Typography>
                    {cat.warning && (
                      <Alert severity="warning" sx={{ mt: 1, py: 0, width: "100%" }}>
                        <Typography variant="caption">{cat.warning}</Typography>
                      </Alert>
                    )}
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          {/* High-Risk Ports */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#ef4444" }} />
                High-Risk Port Detection
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                VRAgent automatically flags 200+ high-risk ports with severity ratings. Here are some examples:
              </Typography>
              
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Port</TableCell>
                      <TableCell>Service</TableCell>
                      <TableCell>Risk</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {HIGH_RISK_PORTS_SAMPLE.map((port) => (
                      <TableRow key={port.port} hover>
                        <TableCell>
                          <Chip label={port.port} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">{port.service}</Typography>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={port.reason}>
                            <Chip 
                              label={port.severity}
                              size="small"
                              sx={{
                                bgcolor: 
                                  port.severity === "critical" ? alpha("#ef4444", 0.2) :
                                  port.severity === "high" ? alpha("#f59e0b", 0.2) :
                                  port.severity === "medium" ? alpha("#3b82f6", 0.2) :
                                  alpha("#10b981", 0.2),
                                color:
                                  port.severity === "critical" ? "#ef4444" :
                                  port.severity === "high" ? "#f59e0b" :
                                  port.severity === "medium" ? "#3b82f6" :
                                  "#10b981",
                              }}
                            />
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          {/* Vulnerability Detection */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} />
                Automated Vulnerability Detection
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                VRAgent's Nmap integration automatically detects 300+ known vulnerable software versions and misconfigurations.
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined" sx={{ height: "100%" }}>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <FindInPageIcon sx={{ color: "#8b5cf6" }} />
                        Banner Analysis
                      </Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Automatically analyze service banners for vulnerable versions.
                      </Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• OpenSSH vulnerabilities (RegreSSHion, CVE-2024-6387)" /></ListItem>
                        <ListItem><ListItemText primary="• Apache/nginx version detection" /></ListItem>
                        <ListItem><ListItemText primary="• Database server analysis (MySQL, PostgreSQL)" /></ListItem>
                        <ListItem><ListItemText primary="• Log4j and Spring4Shell detection" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined" sx={{ height: "100%" }}>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <DeviceHubIcon sx={{ color: "#3b82f6" }} />
                        NSE Script Results
                      </Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Parse and interpret NSE script outputs for vulnerabilities.
                      </Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• SMB vulnerabilities (EternalBlue, MS17-010)" /></ListItem>
                        <ListItem><ListItemText primary="• SSL/TLS issues (Heartbleed, POODLE)" /></ListItem>
                        <ListItem><ListItemText primary="• HTTP vulnerabilities (Shellshock, SQL injection)" /></ListItem>
                        <ListItem><ListItemText primary="• Default credentials detection" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined" sx={{ height: "100%" }}>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <AiIcon sx={{ color: "#10b981" }} />
                        AI Risk Assessment
                      </Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        AI-powered analysis combining all findings into actionable reports.
                      </Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• Risk score (0-100) calculation" /></ListItem>
                        <ListItem><ListItemText primary="• Attack vector identification" /></ListItem>
                        <ListItem><ListItemText primary="• Compliance concerns (PCI-DSS, HIPAA)" /></ListItem>
                        <ListItem><ListItemText primary="• Prioritized recommendations" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          {/* AI Report Structure */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <AssessmentIcon sx={{ color: "#10b981" }} />
                AI-Generated Security Report Structure
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Every Nmap scan generates a comprehensive AI analysis with the following structure:
              </Typography>
              
              <Box
                sx={{
                  bgcolor: "#1e1e1e",
                  borderRadius: 1,
                  p: 2,
                  fontFamily: "monospace",
                  fontSize: "0.75rem",
                  color: "#d4d4d4",
                  overflow: "auto",
                  maxHeight: 400,
                }}
              >
                <pre style={{ margin: 0 }}>{`{
  "risk_level": "High",
  "risk_score": 72,
  "executive_summary": "The network scan revealed multiple security concerns...",
  "network_overview": {
    "attack_surface_rating": "Large",
    "internet_exposed_services": 15,
    "internal_only_services": 8
  },
  "key_findings": [
    {
      "title": "Critical: MongoDB exposed without authentication",
      "severity": "Critical",
      "affected_hosts": ["192.168.1.50"],
      "affected_ports": [27017],
      "recommendation": "Enable authentication immediately"
    }
  ],
  "vulnerable_services": [
    {
      "service": "OpenSSH",
      "port": 22,
      "hosts": ["192.168.1.10", "192.168.1.20"],
      "vulnerability": "RegreSSHion (CVE-2024-6387)",
      "severity": "Critical",
      "cve_ids": ["CVE-2024-6387"],
      "exploit_available": true
    }
  ],
  "high_risk_hosts": [
    {
      "ip": "192.168.1.50",
      "risk_level": "Critical",
      "critical_services": ["MongoDB", "Redis"],
      "priority_actions": ["Enable auth", "Firewall rules"]
    }
  ],
  "attack_vectors": [
    {
      "vector": "Unauthenticated Database Access",
      "severity": "Critical",
      "entry_points": ["192.168.1.50:27017"],
      "potential_impact": "Data breach, ransomware"
    }
  ],
  "compliance_concerns": [
    {
      "standard": "PCI-DSS",
      "concern": "Unencrypted database connections",
      "remediation": "Enable TLS for all database traffic"
    }
  ],
  "recommendations": [
    {
      "priority": "Immediate",
      "category": "Configuration",
      "action": "Enable authentication on MongoDB",
      "rationale": "Unauthenticated access = data breach risk"
    }
  ]
}`}</pre>
              </Box>
            </Paper>
          </Grid>

          {/* Quick Reference Commands */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: ACCENT_COLOR }} />
                Quick Reference: Combined Analysis Commands
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>1. Trace the path first:</Typography>
                  <CodeBlock code="traceroute -n target.com" />
                  
                  <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>2. Quick host discovery:</Typography>
                  <CodeBlock code="nmap -sn 192.168.1.0/24" />
                  
                  <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>3. Basic service scan:</Typography>
                  <CodeBlock code="nmap -sV -sC -T4 target.com" />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>4. Vulnerability scan:</Typography>
                  <CodeBlock code="nmap -sV --script vuln target.com" />
                  
                  <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>5. Comprehensive scan:</Typography>
                  <CodeBlock code="nmap -A -T4 -p- target.com" />
                  
                  <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>6. Stealth scan (requires root):</Typography>
                  <CodeBlock code="sudo nmap -sS -T4 target.com" />
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          {/* Tool Links */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
              <Typography variant="h6" gutterBottom>Try the Combined Tools</Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Use VRAgent's integrated network analysis tools for comprehensive security assessment.
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Button
                    component={Link}
                    to="/dynamic/traceroute"
                    variant="contained"
                    fullWidth
                    startIcon={<RouteIcon />}
                    sx={{ bgcolor: ACCENT_COLOR, "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.8) } }}
                  >
                    Traceroute Analyzer
                  </Button>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Button
                    component={Link}
                    to="/dynamic/nmap"
                    variant="contained"
                    fullWidth
                    startIcon={<RadarIcon />}
                    sx={{ bgcolor: "#3b82f6", "&:hover": { bgcolor: alpha("#3b82f6", 0.8) } }}
                  >
                    Nmap Scanner
                  </Button>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Button
                    component={Link}
                    to="/dynamic/network"
                    variant="outlined"
                    fullWidth
                    startIcon={<DeviceHubIcon />}
                    sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
                  >
                    Network Analysis Hub
                  </Button>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      )}
      </Box>

      {/* Bottom Navigation */}
      <Box sx={{ mt: 4, textAlign: "center" }}>
        <Button
          variant="outlined"
          startIcon={<BackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
        >
          Back to Learning Hub
        </Button>
      </Box>
      </Box>
    </Box>
    </LearnPageLayout>
  );
};

export default TracerouteGuidePage;
