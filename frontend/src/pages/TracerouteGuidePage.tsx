import React, { useState } from "react";
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
} from "@mui/icons-material";
import { Link, useNavigate } from "react-router-dom";

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
  const [activeTab, setActiveTab] = useState(0);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);

  const pageContext = `This page covers traceroute and network path analysis including:
- Traceroute command options for Windows and Linux
- Understanding hop-by-hop network path analysis
- Latency interpretation and troubleshooting
- Common network issues: high latency, packet loss, unreachable destination
- Security applications: firewall detection, CDN identification
- MTR (My Traceroute) for advanced analysis
- Network topology discovery techniques
- Interpreting asterisks and timeouts in traceroute output`;

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

  return (
    <LearnPageLayout pageTitle="Traceroute Guide" pageContext={pageContext}>
    <Box sx={{ p: 3 }}>
      {/* Back Link */}
      <Box sx={{ mb: 3 }}>
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
        <RouteIcon sx={{ fontSize: 40, color: "#ec4899" }} />
        <Box>
          <Typography variant="h4" sx={{ fontWeight: "bold" }}>
            Traceroute Guide
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Learn network path analysis and troubleshooting techniques
          </Typography>
        </Box>
        <Box sx={{ flex: 1 }} />
        <Button
          component={Link}
          to="/network/traceroute"
          variant="contained"
          sx={{
            bgcolor: "#ec4899",
            "&:hover": { bgcolor: "#db2777" },
          }}
        >
          Open Traceroute Tool
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
      </Tabs>

      {/* Tab 0: Overview */}
      {activeTab === 0 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <PublicIcon color="primary" />
                What is Traceroute?
              </Typography>
              <Typography variant="body1" paragraph>
                Traceroute is a network diagnostic tool that maps the path packets take from your computer 
                to a destination host. It reveals each "hop" (router) along the way, showing network topology 
                and helping identify where delays or failures occur.
              </Typography>
              
              <Alert severity="info" sx={{ mb: 3 }}>
                <strong>How it works:</strong> Traceroute sends packets with incrementing Time-To-Live (TTL) values. 
                Each router decrements the TTL; when it reaches 0, the router sends back an ICMP "Time Exceeded" 
                message, revealing its identity.
              </Alert>

              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#3b82f6", 0.1) }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        <SpeedIcon sx={{ mr: 1, color: "#3b82f6" }} />
                        Latency Analysis
                      </Typography>
                      <Typography variant="body2">
                        Measure round-trip time (RTT) to each hop, identifying slow segments 
                        and network bottlenecks.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#10b981", 0.1) }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        <NetworkIcon sx={{ mr: 1, color: "#10b981" }} />
                        Path Discovery
                      </Typography>
                      <Typography variant="body2">
                        Map the network topology between you and any destination, 
                        understanding routing decisions.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#f59e0b", 0.1) }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        <WarningIcon sx={{ mr: 1, color: "#f59e0b" }} />
                        Troubleshooting
                      </Typography>
                      <Typography variant="body2">
                        Pinpoint exactly where connectivity issues occur - whether in your 
                        network, ISP, or destination.
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <Typography variant="h6" gutterBottom>Quick Start Examples</Typography>
              
              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Windows:</Typography>
              <CodeBlock code="tracert google.com" />
              
              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Linux/macOS:</Typography>
              <CodeBlock code="traceroute google.com" />
              
              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Skip DNS resolution (faster):</Typography>
              <CodeBlock code="traceroute -n 8.8.8.8" />
              
              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Use ICMP (may need sudo):</Typography>
              <CodeBlock code="sudo traceroute -I google.com" />
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

      {/* Tab 1: Commands & Options */}
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

      {/* Tab 2: Interpreting Results */}
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

      {/* Tab 3: Troubleshooting */}
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

      {/* Tab 4: Security */}
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

      {/* Tab 5: VRAgent AI Analysis */}
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
    </LearnPageLayout>
  );
};

export default TracerouteGuidePage;
