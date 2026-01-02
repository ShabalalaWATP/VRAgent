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
      <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 3 }}>
        <Tab label="Overview" />
        <Tab label="Commands & Options" />
        <Tab label="Interpreting Results" />
        <Tab label="Troubleshooting" />
        <Tab label="Security" />
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
