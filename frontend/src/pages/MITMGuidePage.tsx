import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Typography,
  Paper,
  Card,
  CardContent,
  Grid,
  Chip,
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
  Alert,
  Tabs,
  Tab,
  alpha,
  useTheme,
  Tooltip,
  IconButton,
} from "@mui/material";
import {
  ArrowBack as BackIcon,
  ExpandMore as ExpandMoreIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  SwapHoriz as MitmIcon,
  Visibility as ViewIcon,
  Rule as RuleIcon,
  PlayArrow as PlayIcon,
  ContentCopy as CopyIcon,
  Psychology as AIIcon,
  Download as ExportIcon,
  Http as HttpIcon,
  Lock as LockIcon,
  Settings as SettingsIcon,
  BugReport as BugIcon,
  Speed as SpeedIcon,
  School as LearnIcon,
  Cable as WebSocketIcon,
  VpnKey as CertIcon,
  Shield as ShieldIcon,
  Terminal as TerminalIcon,
  Apple as AppleIcon,
  Android as AndroidIcon,
  Devices as DevicesIcon,
  Storage as StorageIcon,
  VerifiedUser as VerifiedIcon,
} from "@mui/icons-material";

// ============================================================================
// Data
// ============================================================================

interface ModeInfo {
  name: string;
  description: string;
  useCase: string;
  color: string;
}

const PROXY_MODES: ModeInfo[] = [
  {
    name: "Passthrough",
    description: "Traffic flows through without modification. You can observe all requests and responses in real-time.",
    useCase: "Initial reconnaissance, understanding API behavior, logging traffic for later analysis",
    color: "#10b981",
  },
  {
    name: "Intercept",
    description: "Traffic is held for manual review. You can inspect, modify, or drop each request before forwarding.",
    useCase: "Testing authentication, modifying parameters, testing input validation",
    color: "#f59e0b",
  },
  {
    name: "Auto Modify",
    description: "Apply predefined rules to automatically modify matching traffic patterns.",
    useCase: "Automated testing, injecting headers, simulating attack scenarios at scale",
    color: "#8b5cf6",
  },
];

interface PresetInfo {
  name: string;
  description: string;
  whatItDoes: string;
  securityTest: string;
}

const PRESET_RULES: PresetInfo[] = [
  {
    name: "Strip Security Headers",
    description: "Removes protective headers from responses",
    whatItDoes: "Removes X-Frame-Options, Content-Security-Policy, X-XSS-Protection, etc.",
    securityTest: "Test if application handles missing security headers gracefully",
  },
  {
    name: "Downgrade HTTPS",
    description: "Changes HTTPS links to HTTP",
    whatItDoes: "Rewrites https:// URLs to http:// in responses",
    securityTest: "Test for mixed content vulnerabilities and HSTS bypass",
  },
  {
    name: "Add Debug Headers",
    description: "Injects debugging headers into requests",
    whatItDoes: "Adds X-Debug-Token, X-Forwarded-For, X-Real-IP headers",
    securityTest: "Test for header injection and debug mode exposure",
  },
  {
    name: "Slow Response",
    description: "Adds artificial delay to responses",
    whatItDoes: "Introduces 2-5 second delays to test timeout handling",
    securityTest: "Test application resilience and timeout handling",
  },
  {
    name: "Corrupt JSON",
    description: "Modifies JSON responses to be malformed",
    whatItDoes: "Introduces syntax errors in JSON payloads",
    securityTest: "Test error handling and graceful degradation",
  },
  {
    name: "Cookie Tampering",
    description: "Modifies cookie attributes",
    whatItDoes: "Removes Secure/HttpOnly flags from Set-Cookie headers",
    securityTest: "Test cookie security and session handling",
  },
];

interface UseCaseInfo {
  title: string;
  description: string;
  steps: string[];
  icon: React.ReactNode;
}

const USE_CASES: UseCaseInfo[] = [
  {
    title: "API Security Testing",
    description: "Test REST API endpoints for vulnerabilities",
    steps: [
      "Create proxy pointing to your API server",
      "Configure your client to use the proxy",
      "Capture normal API traffic in Passthrough mode",
      "Switch to Intercept mode to modify requests",
      "Test for authentication bypass, SQLi, XSS",
      "Run AI Analysis to identify vulnerabilities",
    ],
    icon: <HttpIcon />,
  },
  {
    title: "Mobile App Testing",
    description: "Intercept traffic from mobile applications",
    steps: [
      "Set up proxy on a port accessible from mobile device",
      "Install proxy certificate on mobile device",
      "Configure mobile WiFi to use proxy",
      "Capture and analyze app traffic",
      "Test for certificate pinning bypass",
      "Look for hardcoded secrets in requests",
    ],
    icon: <SecurityIcon />,
  },
  {
    title: "Microservice Debugging",
    description: "Debug inter-service communication",
    steps: [
      "Create proxy between microservices",
      "Route service A to call service B through proxy",
      "Observe request/response patterns",
      "Identify serialization issues",
      "Test failure scenarios with Auto Modify",
      "Validate error handling between services",
    ],
    icon: <BugIcon />,
  },
  {
    title: "Performance Testing",
    description: "Simulate network conditions",
    steps: [
      "Set up proxy with delay rules",
      "Apply 'Slow Response' preset",
      "Test application timeout handling",
      "Identify performance bottlenecks",
      "Validate retry logic",
      "Test under degraded conditions",
    ],
    icon: <SpeedIcon />,
  },
];

// ============================================================================
// Main Component
// ============================================================================

const MITMGuidePage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const CodeBlock: React.FC<{ code: string; title?: string }> = ({ code, title }) => (
    <Box sx={{ position: "relative", mb: 2 }}>
      {title && (
        <Typography variant="caption" sx={{ color: "text.secondary", mb: 0.5, display: "block" }}>
          {title}
        </Typography>
      )}
      <Box
        sx={{
          bgcolor: "#1e1e1e",
          borderRadius: 1,
          p: 2,
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e0e0e0",
          overflow: "auto",
          position: "relative",
        }}
      >
        <IconButton
          size="small"
          onClick={() => copyToClipboard(code)}
          sx={{ position: "absolute", top: 8, right: 8, color: "grey.500" }}
        >
          <CopyIcon fontSize="small" />
        </IconButton>
        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{code}</pre>
      </Box>
    </Box>
  );

  const pageContext = `MITM (Man-in-the-Middle) Workbench Guide page. This page teaches users about intercepting and analyzing network traffic including: TCP/HTTP/HTTPS proxy with traffic interception, WebSocket deep inspection with frame-level analysis and opcode parsing (TEXT, BINARY, CLOSE, PING, PONG), Certificate Authority generation and management for HTTPS MITM interception with installation instructions for Windows, macOS, Linux, Firefox, Android, and iOS, rule-based traffic modification with 6 preset rules, AI-powered natural language rule creation, real-time AI traffic suggestions detecting auth headers, JSON APIs, CORS, cookies, session management with disk-backed storage, and traffic export to PCAP format.`;

  return (
    <LearnPageLayout pageTitle="MITM Attacks Guide" pageContext={pageContext}>
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
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
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: "linear-gradient(135deg, #eab308 0%, #ca8a04 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <MitmIcon sx={{ fontSize: 32, color: "white" }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              MITM Workbench Guide
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Learn to intercept, inspect, and modify HTTP/HTTPS traffic
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Chip icon={<LearnIcon />} label="Beginner Friendly" color="success" size="small" />
          <Chip label="Est. 15 min read" size="small" variant="outlined" />
          <Button
            component={Link}
            to="/network/mitm"
            variant="contained"
            size="small"
            sx={{
              background: "linear-gradient(135deg, #eab308 0%, #ca8a04 100%)",
              ml: 2,
            }}
          >
            Open MITM Workbench →
          </Button>
        </Box>
      </Box>

      {/* Tabs */}
      <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} variant="scrollable" scrollButtons="auto" sx={{ mb: 3 }}>
        <Tab label="Overview" />
        <Tab label="AI Features" />
        <Tab label="WebSocket Inspection" />
        <Tab label="Certificate Management" />
        <Tab label="Proxy Modes" />
        <Tab label="Use Cases" />
        <Tab label="Quick Start" />
      </Tabs>

      {/* Tab 0: Overview */}
      {activeTab === 0 && (
        <Box>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="subtitle2" gutterBottom>What is a Man-in-the-Middle Proxy?</Typography>
            A MITM proxy sits between your application and its target server, allowing you to observe, 
            modify, or block traffic in real-time. It's essential for security testing, debugging, and 
            understanding application behavior.
          </Alert>

          <Grid container spacing={3}>
            {/* Key Features */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%" }}>
                <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <SecurityIcon color="primary" /> Key Features
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                    <ListItemText 
                      primary="Traffic Interception" 
                      secondary="Capture all HTTP/HTTPS requests and responses"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                    <ListItemText 
                      primary="Request Modification" 
                      secondary="Edit headers, body, and parameters on-the-fly"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                    <ListItemText 
                      primary="Rule-Based Automation" 
                      secondary="Create rules to auto-modify matching traffic"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                    <ListItemText 
                      primary="AI Security Analysis" 
                      secondary="AI-powered detection of vulnerabilities"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                    <ListItemText 
                      primary="Export Reports" 
                      secondary="Generate Markdown, PDF, or Word reports"
                    />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* When to Use */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%" }}>
                <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <InfoIcon color="info" /> When to Use MITM
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><HttpIcon /></ListItemIcon>
                    <ListItemText primary="Testing API security and authentication" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><BugIcon /></ListItemIcon>
                    <ListItemText primary="Debugging microservice communication" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><ViewIcon /></ListItemIcon>
                    <ListItemText primary="Analyzing third-party API integrations" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><SecurityIcon /></ListItemIcon>
                    <ListItemText primary="Security testing web applications" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><SpeedIcon /></ListItemIcon>
                    <ListItemText primary="Simulating network conditions" />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* Preset Rules */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <RuleIcon color="warning" /> Available Preset Rules
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Pre-configured rules for common security testing scenarios. Apply with one click.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell><strong>Preset</strong></TableCell>
                        <TableCell><strong>What It Does</strong></TableCell>
                        <TableCell><strong>Security Test</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {PRESET_RULES.map((preset) => (
                        <TableRow key={preset.name} hover>
                          <TableCell>
                            <Typography variant="body2" fontWeight={500}>{preset.name}</Typography>
                            <Typography variant="caption" color="text.secondary">{preset.description}</Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">{preset.whatItDoes}</Typography>
                          </TableCell>
                          <TableCell>
                            <Chip label={preset.securityTest} size="small" variant="outlined" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Tab 1: AI Features */}
      {activeTab === 1 && (
        <Box>
          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="subtitle2" gutterBottom>NEW: AI-Powered Rule Creation & Suggestions</Typography>
            Use natural language to create rules and get intelligent suggestions based on your traffic patterns.
          </Alert>

          <Grid container spacing={3}>
            {/* Natural Language Rule Creation */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", border: `2px solid ${alpha("#8b5cf6", 0.3)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <AIIcon sx={{ color: "#8b5cf6" }} />
                  <Typography variant="h6" fontWeight={600}>Natural Language Rules</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Create interception rules by describing what you want in plain English. The AI understands your intent and generates the appropriate rule.
                </Typography>
                <Typography variant="subtitle2" fontWeight={600} gutterBottom>Example Commands:</Typography>
                <List dense>
                  <ListItem sx={{ py: 0.5 }}>
                    <Chip label="Block all requests to analytics.google.com" size="small" variant="outlined" sx={{ mr: 1 }} />
                  </ListItem>
                  <ListItem sx={{ py: 0.5 }}>
                    <Chip label="Add a 2 second delay to all API responses" size="small" variant="outlined" sx={{ mr: 1 }} />
                  </ListItem>
                  <ListItem sx={{ py: 0.5 }}>
                    <Chip label="Remove the Authorization header" size="small" variant="outlined" sx={{ mr: 1 }} />
                  </ListItem>
                  <ListItem sx={{ py: 0.5 }}>
                    <Chip label="Replace all prices with $0.00" size="small" variant="outlined" sx={{ mr: 1 }} />
                  </ListItem>
                  <ListItem sx={{ py: 0.5 }}>
                    <Chip label="Add X-Debug-Mode: true header" size="small" variant="outlined" sx={{ mr: 1 }} />
                  </ListItem>
                </List>
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="caption">
                    Works even without AI - common patterns like blocking, delays, and header modifications have built-in fallbacks.
                  </Typography>
                </Alert>
              </Paper>
            </Grid>

            {/* Real-Time AI Suggestions */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", border: `2px solid ${alpha("#06b6d4", 0.3)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <InfoIcon sx={{ color: "#06b6d4" }} />
                  <Typography variant="h6" fontWeight={600}>AI Traffic Suggestions</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  The AI analyzes your captured traffic and suggests security tests based on what it detects.
                </Typography>
                <Typography variant="subtitle2" fontWeight={600} gutterBottom>Auto-Detects:</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                  <Chip icon={<LockIcon />} label="Auth Headers" size="small" color="warning" />
                  <Chip icon={<HttpIcon />} label="JSON APIs" size="small" color="primary" />
                  <Chip label="Cookies" size="small" color="secondary" />
                  <Chip label="Admin Paths" size="small" color="error" />
                  <Chip label="CORS" size="small" color="info" />
                </Box>
                <Typography variant="subtitle2" fontWeight={600} gutterBottom>Suggestion Categories:</Typography>
                <List dense>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><SecurityIcon color="error" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Security" secondary="Auth bypass, header injection tests" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><SpeedIcon color="warning" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Performance" secondary="Latency testing, timeout handling" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><BugIcon color="info" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Debug" secondary="Error handling, logging verification" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><LearnIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Learning" secondary="Educational security experiments" />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* How to Use */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" fontWeight={600} gutterBottom>How to Use AI Features</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Chip label="1" color="primary" sx={{ mb: 1, width: 40, height: 40, fontSize: "1.2rem" }} />
                      <Typography variant="subtitle2" fontWeight={600}>Capture Traffic</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Start your proxy and let traffic flow through. The more traffic, the better suggestions.
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Chip label="2" color="primary" sx={{ mb: 1, width: 40, height: 40, fontSize: "1.2rem" }} />
                      <Typography variant="subtitle2" fontWeight={600}>Get Suggestions or Type</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Click "AI Suggestions" for automatic recommendations, or type what you want in natural language.
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Chip label="3" color="primary" sx={{ mb: 1, width: 40, height: 40, fontSize: "1.2rem" }} />
                      <Typography variant="subtitle2" fontWeight={600}>Apply & Test</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Click "Quick Apply" on suggestions or "Create Rule" for your natural language input.
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Tab 2: WebSocket Inspection - NEW */}
      {activeTab === 2 && (
        <Box>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="subtitle2" gutterBottom>WebSocket Deep Inspection</Typography>
            Inspect, analyze, and modify WebSocket frames in real-time. Perfect for testing live chat, real-time APIs, and gaming protocols.
          </Alert>

          <Grid container spacing={3}>
            {/* WebSocket Overview */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", border: `2px solid ${alpha("#10b981", 0.3)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <WebSocketIcon sx={{ color: "#10b981" }} />
                  <Typography variant="h6" fontWeight={600}>Frame-Level Analysis</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Decode and inspect individual WebSocket frames with full protocol visibility.
                </Typography>
                <Typography variant="subtitle2" fontWeight={600} gutterBottom>Supported Opcodes:</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                  <Chip icon={<HttpIcon />} label="TEXT (0x1)" size="small" color="primary" />
                  <Chip icon={<StorageIcon />} label="BINARY (0x2)" size="small" color="secondary" />
                  <Chip label="CONTINUATION (0x0)" size="small" />
                  <Chip label="CLOSE (0x8)" size="small" color="error" />
                  <Chip label="PING (0x9)" size="small" color="warning" />
                  <Chip label="PONG (0xA)" size="small" color="success" />
                </Box>
                <List dense>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Payload decoding (text & JSON)" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Mask/unmask frame detection" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Direction tracking (client↔server)" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Connection state & statistics" />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* WebSocket Rules */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", border: `2px solid ${alpha("#8b5cf6", 0.3)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <RuleIcon sx={{ color: "#8b5cf6" }} />
                  <Typography variant="h6" fontWeight={600}>WebSocket Rules</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Create rules to automatically modify or drop WebSocket frames.
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Match by direction (client→server, server→client, both)" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Match by opcode (TEXT, BINARY, etc.)" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Regex payload pattern matching" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="JSON path matching for structured data" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Actions: modify, drop, delay" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Payload find/replace with JSON path edits" />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* WebSocket Connection Stats */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" fontWeight={600} gutterBottom>
                  Connection Tracking
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Monitor active WebSocket connections with detailed statistics.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell><strong>Metric</strong></TableCell>
                        <TableCell><strong>Description</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {[
                        ["Connection ID", "Unique identifier for each WebSocket session"],
                        ["Client IP/Port", "Source address of the WebSocket client"],
                        ["Target Host/Port", "Destination server being proxied"],
                        ["Status", "Active or Closed connection state"],
                        ["Total Frames", "Count of all frames sent/received"],
                        ["Bytes Sent/Received", "Data transfer statistics"],
                        ["Close Code/Reason", "WebSocket close handshake details"],
                      ].map(([metric, desc], i) => (
                        <TableRow key={i}>
                          <TableCell sx={{ fontWeight: 600 }}>{metric}</TableCell>
                          <TableCell>{desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Tab 3: Certificate Management - NEW */}
      {activeTab === 3 && (
        <Box>
          <Alert severity="warning" sx={{ mb: 3 }}>
            <Typography variant="subtitle2" gutterBottom>HTTPS Interception Requires CA Certificate</Typography>
            To intercept HTTPS traffic, you must install the VRAgent CA certificate on your target device or browser.
          </Alert>

          <Grid container spacing={3}>
            {/* CA Generation */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", border: `2px solid ${alpha("#eab308", 0.3)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <CertIcon sx={{ color: "#eab308" }} />
                  <Typography variant="h6" fontWeight={600}>CA Certificate Generation</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Generate a 4096-bit RSA Root CA certificate for HTTPS interception.
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><VerifiedIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="4096-bit RSA key pair" secondary="Industry-standard security" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><VerifiedIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="10-year validity (configurable)" secondary="Valid for long-term testing" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><VerifiedIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="SHA-256 signature" secondary="Modern hashing algorithm" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><VerifiedIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Automatic host cert generation" secondary="On-the-fly for any hostname" />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* Host Certificates */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", border: `2px solid ${alpha("#10b981", 0.3)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <ShieldIcon sx={{ color: "#10b981" }} />
                  <Typography variant="h6" fontWeight={600}>Host Certificate Management</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Dynamically generate certificates for intercepted hosts.
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Auto-generated per hostname" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Wildcard SAN support (*.example.com)" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="IP address support in SAN" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Certificate caching & persistence" />
                  </ListItem>
                  <ListItem sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="List, view, and delete host certs" />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* Installation Instructions */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <DevicesIcon /> Platform Installation Instructions
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  Install the CA certificate on your target device to intercept HTTPS traffic.
                </Typography>
                
                <Grid container spacing={2}>
                  {/* Windows */}
                  <Grid item xs={12} md={6} lg={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <TerminalIcon sx={{ color: "#0078d4" }} />
                          <Typography variant="subtitle2" fontWeight={600}>Windows</Typography>
                        </Box>
                        <Typography variant="caption" component="div" sx={{ mb: 1 }}>
                          1. Download CA cert → 2. Rename to .crt → 3. Double-click → Install Certificate
                        </Typography>
                        <CodeBlock code="certutil -addstore Root ca_cert.crt" title="Command:" />
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* macOS */}
                  <Grid item xs={12} md={6} lg={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <AppleIcon sx={{ color: "#555" }} />
                          <Typography variant="subtitle2" fontWeight={600}>macOS</Typography>
                        </Box>
                        <Typography variant="caption" component="div" sx={{ mb: 1 }}>
                          Open in Keychain Access → Add to System → Trust Settings → Always Trust
                        </Typography>
                        <CodeBlock code="sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca_cert.pem" title="Command:" />
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Linux */}
                  <Grid item xs={12} md={6} lg={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <TerminalIcon sx={{ color: "#f97316" }} />
                          <Typography variant="subtitle2" fontWeight={600}>Linux (Ubuntu/Debian)</Typography>
                        </Box>
                        <Typography variant="caption" component="div" sx={{ mb: 1 }}>
                          Copy to ca-certificates folder and update
                        </Typography>
                        <CodeBlock code="sudo cp ca_cert.pem /usr/local/share/ca-certificates/vragent.crt && sudo update-ca-certificates" title="Command:" />
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Firefox */}
                  <Grid item xs={12} md={6} lg={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <SecurityIcon sx={{ color: "#ff7139" }} />
                          <Typography variant="subtitle2" fontWeight={600}>Firefox</Typography>
                        </Box>
                        <Typography variant="caption" component="div">
                          Settings → Privacy & Security → View Certificates → Authorities → Import → Check "Trust this CA to identify websites"
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Android */}
                  <Grid item xs={12} md={6} lg={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <AndroidIcon sx={{ color: "#3ddc84" }} />
                          <Typography variant="subtitle2" fontWeight={600}>Android</Typography>
                        </Box>
                        <Typography variant="caption" component="div">
                          Settings → Security → Encryption → Install CA certificate → Select file
                        </Typography>
                        <Alert severity="warning" sx={{ mt: 1, py: 0 }}>
                          <Typography variant="caption">Android 7+ may require additional steps for apps targeting SDK 24+</Typography>
                        </Alert>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* iOS */}
                  <Grid item xs={12} md={6} lg={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <AppleIcon sx={{ color: "#555" }} />
                          <Typography variant="subtitle2" fontWeight={600}>iOS</Typography>
                        </Box>
                        <Typography variant="caption" component="div">
                          AirDrop/Email cert → Settings → General → Profile → Install → Settings → About → Certificate Trust Settings → Enable
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Tab 4: Proxy Modes (was Tab 2) */}
      {activeTab === 4 && (
        <Box>
          <Typography variant="h6" fontWeight={600} gutterBottom>
            Understanding Proxy Modes
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Choose the right mode based on your testing needs.
          </Typography>

          <Grid container spacing={3}>
            {PROXY_MODES.map((mode) => (
              <Grid item xs={12} md={4} key={mode.name}>
                <Card
                  sx={{
                    height: "100%",
                    border: `2px solid ${alpha(mode.color, 0.3)}`,
                    background: alpha(mode.color, 0.05),
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                      <Box
                        sx={{
                          width: 12,
                          height: 12,
                          borderRadius: "50%",
                          bgcolor: mode.color,
                        }}
                      />
                      <Typography variant="h6" fontWeight={600}>
                        {mode.name}
                      </Typography>
                    </Box>
                    <Typography variant="body2" paragraph>
                      {mode.description}
                    </Typography>
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <Typography variant="caption">
                        <strong>Best for:</strong> {mode.useCase}
                      </Typography>
                    </Alert>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 3, mt: 4 }}>
            <Typography variant="h6" fontWeight={600} gutterBottom>
              Mode Comparison
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell><strong>Feature</strong></TableCell>
                    <TableCell align="center"><strong>Passthrough</strong></TableCell>
                    <TableCell align="center"><strong>Intercept</strong></TableCell>
                    <TableCell align="center"><strong>Auto Modify</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell>View Traffic</TableCell>
                    <TableCell align="center"><CheckIcon color="success" /></TableCell>
                    <TableCell align="center"><CheckIcon color="success" /></TableCell>
                    <TableCell align="center"><CheckIcon color="success" /></TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>Manual Modification</TableCell>
                    <TableCell align="center"><ErrorIcon color="disabled" /></TableCell>
                    <TableCell align="center"><CheckIcon color="success" /></TableCell>
                    <TableCell align="center"><ErrorIcon color="disabled" /></TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>Automatic Rules</TableCell>
                    <TableCell align="center"><ErrorIcon color="disabled" /></TableCell>
                    <TableCell align="center"><ErrorIcon color="disabled" /></TableCell>
                    <TableCell align="center"><CheckIcon color="success" /></TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>Performance Impact</TableCell>
                    <TableCell align="center"><Chip label="Low" size="small" color="success" /></TableCell>
                    <TableCell align="center"><Chip label="High" size="small" color="warning" /></TableCell>
                    <TableCell align="center"><Chip label="Medium" size="small" color="info" /></TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Box>
      )}

      {/* Tab 5: Use Cases (was Tab 3) */}
      {activeTab === 5 && (
        <Box>
          <Typography variant="h6" fontWeight={600} gutterBottom>
            Common Use Cases
          </Typography>
          <Grid container spacing={3}>
            {USE_CASES.map((useCase) => (
              <Grid item xs={12} md={6} key={useCase.title}>
                <Card sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 2,
                          bgcolor: alpha("#eab308", 0.1),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          color: "#eab308",
                        }}
                      >
                        {useCase.icon}
                      </Box>
                      <Box>
                        <Typography variant="h6" fontWeight={600}>
                          {useCase.title}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {useCase.description}
                        </Typography>
                      </Box>
                    </Box>
                    <List dense>
                      {useCase.steps.map((step, idx) => (
                        <ListItem key={idx} sx={{ py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            <Chip label={idx + 1} size="small" sx={{ width: 24, height: 24 }} />
                          </ListItemIcon>
                          <ListItemText primary={step} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Tab 6: Quick Start (was Tab 4) */}
      {activeTab === 6 && (
        <Box>
          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="subtitle2">Ready to start?</Typography>
            Follow these steps to set up your first MITM proxy in under 5 minutes.
          </Alert>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight={600}>Step 1: Create a Proxy</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem>
                  <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Click 'New Proxy' button in the MITM Workbench" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Give it a unique ID (e.g., 'api-proxy')" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Set Listen Host to 127.0.0.1 and Port to 8080" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Set Target Host to your API server (e.g., api.example.com:443)" />
                </ListItem>
              </List>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight={600}>Step 2: Configure Your Client</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Route your application's traffic through the proxy:
              </Typography>
              
              <CodeBlock 
                title="Using curl"
                code={`curl -x http://127.0.0.1:8080 https://api.example.com/endpoint`}
              />
              
              <CodeBlock 
                title="Using environment variables"
                code={`export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080`}
              />

              <CodeBlock 
                title="Python requests"
                code={`import requests
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}
response = requests.get('https://api.example.com', proxies=proxies, verify=False)`}
              />
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight={600}>Step 3: Start Intercepting</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem>
                  <ListItemIcon><PlayIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Click 'Start' to begin the proxy" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><ViewIcon color="primary" /></ListItemIcon>
                  <ListItemText primary="Watch traffic appear in the Traffic Log tab" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SettingsIcon color="secondary" /></ListItemIcon>
                  <ListItemText primary="Change mode to 'Intercept' to modify requests" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><RuleIcon color="warning" /></ListItemIcon>
                  <ListItemText primary="Add custom rules or apply presets" />
                </ListItem>
              </List>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight={600}>Step 4: Analyze & Export</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem>
                  <ListItemIcon><AIIcon color="secondary" /></ListItemIcon>
                  <ListItemText 
                    primary="Click 'Analyze' for AI-powered security analysis"
                    secondary="Detects sensitive data, missing headers, and vulnerabilities"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><ExportIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary="Export reports in Markdown, PDF, or Word format"
                    secondary="Share findings with your team"
                  />
                </ListItem>
              </List>
            </AccordionDetails>
          </Accordion>

          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              component={Link}
              to="/network/mitm"
              variant="contained"
              size="large"
              startIcon={<MitmIcon />}
              sx={{
                background: "linear-gradient(135deg, #eab308 0%, #ca8a04 100%)",
                px: 4,
                py: 1.5,
              }}
            >
              Open MITM Workbench
            </Button>
          </Box>
        </Box>
      )}

      {/* Snackbar for copy feedback */}
      {copiedText && (
        <Alert 
          severity="success" 
          sx={{ 
            position: "fixed", 
            bottom: 20, 
            right: 20,
            zIndex: 9999,
          }}
>
          Copied to clipboard!
        </Alert>
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

export default MITMGuidePage;
