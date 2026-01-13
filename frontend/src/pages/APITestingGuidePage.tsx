import React, { useState } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Grid,
  Card,
  CardContent,
  Chip,
  Divider,
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
  IconButton,
  Tooltip,
  Alert,
  Button,
  Tabs,
  Tab,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ApiIcon from "@mui/icons-material/Api";
import SecurityIcon from "@mui/icons-material/Security";
import RadarIcon from "@mui/icons-material/Radar";
import ComputerIcon from "@mui/icons-material/Computer";
import SpeedIcon from "@mui/icons-material/Speed";
import WebhookIcon from "@mui/icons-material/Webhook";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import SchoolIcon from "@mui/icons-material/School";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import LearnPageLayout from "../components/LearnPageLayout";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import LockIcon from "@mui/icons-material/Lock";
import AssessmentIcon from "@mui/icons-material/Assessment";
import DownloadIcon from "@mui/icons-material/Download";

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

// Quick Start Steps
const quickStartSteps = [
  {
    label: "Open the API Tester",
    description: "Navigate to Network Analysis Hub → API Endpoint Tester, or directly to /network/api-tester",
  },
  {
    label: "Choose Your Testing Mode",
    description: "Pick from 7 specialized tabs: AI Auto-Test for automated scanning, Network Discovery for finding services, Test Builder for manual testing, or WebSocket/JWT for specialized protocols",
  },
  {
    label: "Configure Authentication",
    description: "Add Bearer token, API key, or Basic auth if the target requires authentication",
  },
  {
    label: "Run Your Tests",
    description: "Click 'Run Security Tests' and watch real-time progress. Results appear inline with severity breakdown, AI summary, and full findings list",
  },
  {
    label: "Export & Analyze",
    description: "Export findings as JSON, Markdown, PDF, or DOCX. Use AI Analysis for deeper insights on vulnerabilities",
  },
];

// Test types explained
const testTypes = [
  {
    name: "AI Auto-Test (CIDR Scanning)",
    description: "Automated security testing of entire networks. Enter a CIDR range and let AI discover and test all HTTP services",
    owasp: "Comprehensive Coverage",
    findings: ["Network-wide scanning", "Service discovery", "Batch vulnerability assessment"],
  },
  {
    name: "Network Discovery",
    description: "Scan IP ranges to discover HTTP/API services. Supports CIDR notation with configurable timeouts and concurrency",
    owasp: "API9:2023 - Improper Inventory Management",
    findings: ["Service enumeration", "Port detection", "Server fingerprinting"],
  },
  {
    name: "Authentication Testing",
    description: "Tests for auth bypass, missing auth, weak tokens, and improper session management",
    owasp: "API2:2023 - Broken Authentication",
    findings: ["Missing auth on endpoints", "Token exposure", "Session fixation"],
  },
  {
    name: "CORS Configuration",
    description: "Checks Cross-Origin Resource Sharing headers for misconfigurations",
    owasp: "API7:2023 - Server Side Request Forgery",
    findings: ["Wildcard origins", "Missing CORS headers", "Credential exposure"],
  },
  {
    name: "Input Validation",
    description: "Tests for SQL injection, XSS, path traversal, and command injection",
    owasp: "API8:2023 - Security Misconfiguration",
    findings: ["SQL injection points", "XSS reflection", "Path traversal"],
  },
  {
    name: "Rate Limiting",
    description: "Verifies rate limiting implementation to prevent abuse",
    owasp: "API4:2023 - Unrestricted Resource Consumption",
    findings: ["Missing rate limits", "Bypass via headers", "DoS potential"],
  },
  {
    name: "JWT Security Testing",
    description: "Dedicated JWT token analysis: decode headers/payload, detect weak algorithms, test for vulnerabilities",
    owasp: "API2:2023 - Broken Authentication",
    findings: ["Algorithm confusion", "Expired tokens", "Missing claims", "Weak signatures"],
  },
  {
    name: "WebSocket Security",
    description: "Test WebSocket endpoints for XSS, authentication bypass, and Cross-Site WebSocket Hijacking (CSWSH)",
    owasp: "API8:2023 - Security Misconfiguration",
    findings: ["Unencrypted ws://", "Missing auth", "Message injection"],
  },
];

// Air-gapped features
const airGappedFeatures = [
  {
    icon: <RadarIcon />,
    title: "AI Auto-Test with CIDR",
    description: "Enter a CIDR range (e.g., 192.168.1.0/24) for automated discovery and testing of all HTTP services",
    usage: "Supports networks up to /16, with configurable max hosts, timeouts, and concurrent connections",
  },
  {
    icon: <NetworkCheckIcon />,
    title: "Network Discovery",
    description: "Scan subnets to find HTTP/API services. Configure timeouts to prevent crashes on large scans",
    usage: "Set max_hosts and overall_timeout to control scan scope and prevent timeouts",
  },
  {
    icon: <BookmarkIcon />,
    title: "Target Presets",
    description: "Save frequently used targets for quick access in lab environments",
    usage: "Save VM IPs, ports, and auth configurations for one-click testing",
  },
  {
    icon: <ComputerIcon />,
    title: "Batch VM Testing",
    description: "Test multiple VMs simultaneously and compare security scores across all targets",
    usage: "Add discovered services or manually enter targets for parallel security testing",
  },
  {
    icon: <SecurityIcon />,
    title: "Multi-Format Export",
    description: "Export all test results (Auto-Test, Batch, JWT, WebSocket) in JSON, Markdown, PDF, or DOCX",
    usage: "Click export buttons on any results tab to download professional reports",
  },
];

// Common commands/payloads
const commonPayloads = [
  { category: "SQL Injection", payload: "' OR '1'='1", purpose: "Basic SQLi test" },
  { category: "SQL Injection", payload: "'; DROP TABLE users;--", purpose: "Destructive test (use carefully)" },
  { category: "XSS", payload: "<script>alert(1)</script>", purpose: "Basic reflected XSS" },
  { category: "XSS", payload: "<img src=x onerror=alert(1)>", purpose: "Event handler XSS" },
  { category: "Path Traversal", payload: "../../../etc/passwd", purpose: "Unix file read" },
  { category: "Path Traversal", payload: "....//....//etc/passwd", purpose: "Filter bypass" },
  { category: "Command Injection", payload: "; id", purpose: "Basic command injection" },
  { category: "SSRF", payload: "http://169.254.169.254/", purpose: "Cloud metadata access" },
];

export default function APITestingGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const pageContext = `This page is the VRAgent API Endpoint Tester Guide covering API security testing features, air-gapped environment testing, JWT analysis, WebSocket testing, authentication bypass techniques, OWASP API security checks, batch VM testing, and multi-format report exports.`;

  return (
    <LearnPageLayout pageTitle="API Endpoint Tester Guide" pageContext={pageContext}>
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Back Button */}
      <Chip
        component={Link}
        to="/learn"
        icon={<ArrowBackIcon />}
        label="Back to Learning Hub"
        clickable
        variant="outlined"
        sx={{ borderRadius: 2, mb: 3 }}
      />

      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <ApiIcon sx={{ fontSize: 48, color: "#22c55e" }} />
        <Box>
          <Typography variant="h3" fontWeight="bold">
            API Endpoint Tester Guide
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Comprehensive guide to VRAgent's API security testing tool - perfect for air-gapped environments
          </Typography>
        </Box>
        <Box sx={{ flexGrow: 1 }} />
        <Button
          variant="contained"
          startIcon={<PlayArrowIcon />}
          onClick={() => navigate("/network/api-tester")}
          sx={{ bgcolor: "#22c55e" }}
        >
          Open API Tester
        </Button>
      </Box>

      {/* Introduction Alert */}
      <Alert severity="info" sx={{ mb: 4 }} icon={<TipsAndUpdatesIcon />}>
        <Typography variant="body1">
          <strong>Air-Gapped Ready:</strong> All core features work without internet access. Network Discovery, Batch Testing, 
          and all security scans run locally. Only AI Analysis requires external API access (Gemini).
        </Typography>
      </Alert>

      {/* Navigation Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} variant="scrollable" scrollButtons="auto">
          <Tab icon={<RocketLaunchIcon />} label="Quick Start" />
          <Tab icon={<SecurityIcon />} label="Security Tests" />
          <Tab icon={<ComputerIcon />} label="Air-Gapped Features" />
          <Tab icon={<WebhookIcon />} label="Tabs Overview" />
          <Tab icon={<SmartToyIcon />} label="VRAgent AI Features" />
          <Tab icon={<SchoolIcon />} label="Best Practices" />
        </Tabs>
      </Paper>

      {/* Tab 0: Quick Start */}
      <TabPanel value={activeTab} index={0}>
        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <RocketLaunchIcon color="primary" />
                Getting Started
              </Typography>
              <Stepper orientation="vertical" sx={{ mt: 3 }}>
                {quickStartSteps.map((step, index) => (
                  <Step key={index} active expanded>
                    <StepLabel>
                      <Typography variant="subtitle1" fontWeight="bold">
                        {step.label}
                      </Typography>
                    </StepLabel>
                    <StepContent>
                      <Typography variant="body2" color="text.secondary">
                        {step.description}
                      </Typography>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SpeedIcon color="primary" />
                Quick Scan vs Full Test
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid item xs={6}>
                  <Card sx={{ bgcolor: alpha("#22c55e", 0.1), height: "100%" }}>
                    <CardContent>
                      <Typography variant="h6" color="success.main">Quick Scan</Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• Single endpoint" /></ListItem>
                        <ListItem><ListItemText primary="• Basic security checks" /></ListItem>
                        <ListItem><ListItemText primary="• Fast results (~5 sec)" /></ListItem>
                        <ListItem><ListItemText primary="• Great for quick recon" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6}>
                  <Card sx={{ bgcolor: alpha("#3b82f6", 0.1), height: "100%" }}>
                    <CardContent>
                      <Typography variant="h6" color="primary.main">Full Test</Typography>
                      <List dense>
                        <ListItem><ListItemText primary="• Multiple endpoints" /></ListItem>
                        <ListItem><ListItemText primary="• All security tests" /></ListItem>
                        <ListItem><ListItemText primary="• Configurable options" /></ListItem>
                        <ListItem><ListItemText primary="• OWASP API mapping" /></ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Paper>

            <Paper sx={{ p: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <InfoIcon color="primary" />
                Example Targets
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Target Type</TableCell>
                      <TableCell>Example URL</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { type: "Public API", url: "https://httpbin.org/get" },
                      { type: "Local Dev", url: "http://localhost:8080/api" },
                      { type: "VM Lab", url: "http://192.168.1.100:3000" },
                      { type: "Docker", url: "http://api-container:5000" },
                      { type: "GraphQL", url: "http://target/graphql" },
                    ].map((row, i) => (
                      <TableRow key={i}>
                        <TableCell>{row.type}</TableCell>
                        <TableCell>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                              {row.url}
                            </Typography>
                            <IconButton size="small" onClick={() => copyToClipboard(row.url)}>
                              <ContentCopyIcon fontSize="small" />
                            </IconButton>
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 1: Security Tests */}
      <TabPanel value={activeTab} index={1}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h5" gutterBottom>
              Security Tests Explained
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              The API Tester performs multiple security tests mapped to OWASP API Security Top 10 (2023).
            </Typography>
          </Grid>

          {testTypes.map((test, index) => (
            <Grid item xs={12} md={6} key={index}>
              <Card sx={{ height: "100%" }}>
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
                    <Typography variant="h6">{test.name}</Typography>
                    <Chip label={test.owasp.split(" - ")[0]} size="small" color="secondary" />
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {test.description}
                  </Typography>
                  <Typography variant="subtitle2" gutterBottom>Detects:</Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    {test.findings.map((finding, i) => (
                      <Chip key={i} label={finding} size="small" variant="outlined" />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}

          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Common Test Payloads
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Category</TableCell>
                      <TableCell>Payload</TableCell>
                      <TableCell>Purpose</TableCell>
                      <TableCell>Copy</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {commonPayloads.map((payload, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Chip label={payload.category} size="small" />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "background.default", p: 0.5, borderRadius: 1 }}>
                            {payload.payload}
                          </Typography>
                        </TableCell>
                        <TableCell>{payload.purpose}</TableCell>
                        <TableCell>
                          <IconButton size="small" onClick={() => copyToClipboard(payload.payload)}>
                            <ContentCopyIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 2: Air-Gapped Features */}
      <TabPanel value={activeTab} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Alert severity="success" sx={{ mb: 3 }}>
              <Typography variant="body1">
                <strong>Perfect for Isolated Environments:</strong> These features are designed for air-gapped networks, 
                VM labs, and environments without internet access.
              </Typography>
            </Alert>
          </Grid>

          {airGappedFeatures.map((feature, index) => (
            <Grid item xs={12} md={6} key={index}>
              <Card sx={{ height: "100%" }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Box sx={{ 
                      p: 1.5, 
                      borderRadius: 2, 
                      bgcolor: alpha("#22c55e", 0.1),
                      color: "#22c55e"
                    }}>
                      {feature.icon}
                    </Box>
                    <Typography variant="h6">{feature.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {feature.description}
                  </Typography>
                  <Alert severity="info" icon={<TipsAndUpdatesIcon />}>
                    <Typography variant="body2">
                      <strong>Usage:</strong> {feature.usage}
                    </Typography>
                  </Alert>
                </CardContent>
              </Card>
            </Grid>
          ))}

          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <RadarIcon color="primary" />
                Network Discovery Guide
              </Typography>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                    Subnet Formats
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Format</TableCell>
                          <TableCell>Example</TableCell>
                          <TableCell>Hosts</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { format: "CIDR /24", example: "192.168.1.0/24", hosts: "256" },
                          { format: "CIDR /28", example: "10.0.0.0/28", hosts: "16" },
                          { format: "IP Range", example: "192.168.1.1-50", hosts: "50" },
                          { format: "Single IP", example: "172.16.0.100", hosts: "1" },
                        ].map((row, i) => (
                          <TableRow key={i}>
                            <TableCell>{row.format}</TableCell>
                            <TableCell sx={{ fontFamily: "monospace" }}>{row.example}</TableCell>
                            <TableCell>{row.hosts}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                    Common API Ports
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {[
                      { port: "80", desc: "HTTP" },
                      { port: "443", desc: "HTTPS" },
                      { port: "8080", desc: "Alt HTTP" },
                      { port: "8443", desc: "Alt HTTPS" },
                      { port: "3000", desc: "Node.js" },
                      { port: "5000", desc: "Flask" },
                      { port: "8000", desc: "Django/FastAPI" },
                      { port: "9000", desc: "Various" },
                      { port: "4000", desc: "GraphQL" },
                    ].map((item, i) => (
                      <Chip 
                        key={i} 
                        label={`${item.port} (${item.desc})`} 
                        variant="outlined"
                        onClick={() => copyToClipboard(item.port)}
                      />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 3: Tabs Overview */}
      <TabPanel value={activeTab} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body1">
                <strong>7 Specialized Tabs:</strong> The API Endpoint Tester organizes functionality into dedicated tabs for different testing scenarios. Results appear inline in each tab.
              </Typography>
            </Alert>
          </Grid>

          {[
            { tab: "0: AI Auto-Test", icon: <SmartToyIcon />, color: "#8b5cf6", 
              desc: "Automated security testing with CIDR network scanning. Results, AI summary, and findings appear inline.",
              features: ["CIDR range scanning (up to /16)", "Inline AI security report", "Full findings list", "Export (JSON/MD/PDF/DOCX)"] },
            { tab: "1: Network Discovery", icon: <RadarIcon />, color: "#06b6d4",
              desc: "Scan IP ranges to find live HTTP/API services. Perfect for mapping your lab environment.",
              features: ["Subnet scanning", "Service fingerprinting", "Port detection", "Export discovered hosts"] },
            { tab: "2: Test Builder", icon: <SecurityIcon />, color: "#22c55e",
              desc: "Manual API security testing with full request configuration. Results appear inline.",
              features: ["Full HTTP method support", "Custom headers", "Authentication presets", "Inline results & export"] },
            { tab: "3: OpenAPI Import", icon: <ApiIcon />, color: "#f59e0b",
              desc: "Import OpenAPI/Swagger specifications to automatically test all documented endpoints.",
              features: ["JSON/YAML spec support", "Endpoint extraction", "Bulk testing", "Coverage analysis"] },
            { tab: "4: Batch Testing", icon: <ComputerIcon />, color: "#3b82f6",
              desc: "Test multiple endpoints simultaneously. Great for comparing security across services.",
              features: ["Parallel testing", "Aggregate scoring", "Multi-target results", "Export all findings"] },
            { tab: "5: WebSocket", icon: <WebhookIcon />, color: "#ec4899",
              desc: "Dedicated WebSocket security testing for real-time APIs.",
              features: ["ws:// and wss:// support", "XSS in messages", "CSWSH testing", "Auth bypass detection"] },
            { tab: "6: JWT Analyzer", icon: <LockIcon />, color: "#10b981",
              desc: "Analyze and test JWT tokens for security vulnerabilities.",
              features: ["Token decoding", "Algorithm confusion", "Claim validation", "Expiration checks"] },
          ].map((item, idx) => (
            <Grid item xs={12} md={6} lg={4} key={idx}>
              <Card sx={{ height: "100%", border: `1px solid ${alpha(item.color, 0.3)}` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha(item.color, 0.1), color: item.color }}>
                      {item.icon}
                    </Box>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>{item.tab}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {item.desc}
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {item.features.map((f, i) => (
                      <Chip key={i} label={f} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}

          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <DownloadIcon color="primary" />
                Export Capabilities
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Test Type</TableCell>
                      <TableCell>JSON</TableCell>
                      <TableCell>Markdown</TableCell>
                      <TableCell>PDF</TableCell>
                      <TableCell>DOCX</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { type: "AI Auto-Test Results", json: true, md: true, pdf: true, docx: true },
                      { type: "Test Builder Results", json: true, md: true, pdf: true, docx: true },
                      { type: "Batch Test Results", json: true, md: true, pdf: true, docx: true },
                      { type: "JWT Analysis", json: true, md: true, pdf: true, docx: true },
                      { type: "WebSocket Results", json: true, md: true, pdf: true, docx: true },
                    ].map((row, i) => (
                      <TableRow key={i}>
                        <TableCell>{row.type}</TableCell>
                        <TableCell>{row.json ? <CheckCircleIcon color="success" fontSize="small" /> : "-"}</TableCell>
                        <TableCell>{row.md ? <CheckCircleIcon color="success" fontSize="small" /> : "-"}</TableCell>
                        <TableCell>{row.pdf ? <CheckCircleIcon color="success" fontSize="small" /> : "-"}</TableCell>
                        <TableCell>{row.docx ? <CheckCircleIcon color="success" fontSize="small" /> : "-"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 4: VRAgent AI Features */}
      <TabPanel value={activeTab} index={4}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Alert severity="info" icon={<SmartToyIcon />} sx={{ mb: 2 }}>
              <Typography variant="body1">
                <strong>AI-Powered API Testing:</strong> VRAgent enhances traditional API testing with intelligent features 
                powered by Google Gemini. These features help automate security analysis and generate actionable insights.
              </Typography>
            </Alert>
          </Grid>

          {/* AI Features Overview */}
          {[
            {
              icon: <SmartToyIcon />,
              title: "Natural Language → API Request",
              color: "#8b5cf6",
              description: "Describe what you want to test in plain English, and AI generates the complete API request.",
              examples: ["\"Get all users with admin role\"", "\"Create a new product with price $50\"", "\"Delete user with ID 123\""],
              output: "Method, URL, headers, and body automatically generated",
            },
            {
              icon: <AssessmentIcon />,
              title: "AI Test/Assertion Generator",
              color: "#10b981",
              description: "Automatically generate test assertions based on API responses.",
              examples: ["Status code validation", "JSON path assertions", "Response time checks", "Schema validation"],
              output: "Ready-to-use test code for your test suite",
            },
            {
              icon: <SecurityIcon />,
              title: "Response Anomaly Detection",
              color: "#ef4444",
              description: "AI analyzes responses for security issues, performance problems, and data anomalies.",
              examples: ["Exposed credentials", "Error message info leaks", "Unusual response patterns", "Security header issues"],
              output: "Categorized anomalies with severity and recommendations",
            },
            {
              icon: <TipsAndUpdatesIcon />,
              title: "Smart Variable Detection",
              color: "#f59e0b",
              description: "AI suggests variables to extract from responses for use in subsequent requests.",
              examples: ["User IDs", "Auth tokens", "Pagination cursors", "Resource URLs"],
              output: "Variable definitions with JSON paths and sample values",
            },
          ].map((feature, idx) => (
            <Grid item xs={12} md={6} key={idx}>
              <Card sx={{ height: "100%", border: `1px solid ${alpha(feature.color, 0.3)}` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha(feature.color, 0.1), color: feature.color }}>
                      {feature.icon}
                    </Box>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>{feature.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {feature.description}
                  </Typography>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>Examples:</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                    {feature.examples.map((ex, i) => (
                      <Chip key={i} label={ex} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                    ))}
                  </Box>
                  <Typography variant="caption" color="text.secondary">
                    <strong>Output:</strong> {feature.output}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}

          {/* AI-Enhanced Security Analysis */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#ef4444" }} />
                AI Security Analysis Report Structure
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                When you run AI-powered security tests, VRAgent generates a comprehensive structured report:
              </Typography>
              <Grid container spacing={2}>
                {[
                  { title: "Executive Summary", desc: "High-level overview for stakeholders" },
                  { title: "Risk Score (0-100)", desc: "Quantified security posture" },
                  { title: "OWASP API Top 10 Mapping", desc: "Findings mapped to API1:2023 - API10:2023" },
                  { title: "CWE Classification", desc: "Weaknesses linked to CWE database" },
                  { title: "Exploitation Paths", desc: "How vulnerabilities could be chained" },
                  { title: "Remediation Priority", desc: "Ordered fix recommendations" },
                ].map((item, i) => (
                  <Grid item xs={12} sm={6} md={4} key={i}>
                    <Paper variant="outlined" sx={{ p: 1.5 }}>
                      <Typography variant="subtitle2" fontWeight="bold">{item.title}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          {/* OWASP API Top 10 Coverage */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#f59e0b" }} />
                OWASP API Security Top 10 (2023) Coverage
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>ID</TableCell>
                      <TableCell>Vulnerability</TableCell>
                      <TableCell>VRAgent Tests</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { id: "API1:2023", name: "Broken Object Level Authorization", tests: "IDOR detection, object access patterns" },
                      { id: "API2:2023", name: "Broken Authentication", tests: "JWT analysis, token exposure, session testing" },
                      { id: "API3:2023", name: "Broken Object Property Level Authorization", tests: "Mass assignment, excessive data exposure" },
                      { id: "API4:2023", name: "Unrestricted Resource Consumption", tests: "Rate limiting, DoS potential" },
                      { id: "API5:2023", name: "Broken Function Level Authorization", tests: "Privilege escalation, admin endpoint access" },
                      { id: "API6:2023", name: "Unrestricted Access to Sensitive Business Flows", tests: "Business logic abuse detection" },
                      { id: "API7:2023", name: "Server Side Request Forgery", tests: "SSRF payloads, URL parameter testing" },
                      { id: "API8:2023", name: "Security Misconfiguration", tests: "Headers, CORS, TLS, error messages" },
                      { id: "API9:2023", name: "Improper Inventory Management", tests: "Endpoint discovery, version detection" },
                      { id: "API10:2023", name: "Unsafe Consumption of APIs", tests: "Third-party API validation" },
                    ].map((row, i) => (
                      <TableRow key={i}>
                        <TableCell><Chip label={row.id} size="small" color="secondary" /></TableCell>
                        <TableCell>{row.name}</TableCell>
                        <TableCell><Typography variant="body2">{row.tests}</Typography></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          {/* Sensitive Data Detection */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#ef4444" }} />
                Automatic Sensitive Data Detection
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                VRAgent automatically scans responses for sensitive data patterns:
              </Typography>
              <List dense>
                {[
                  { pattern: "Email addresses", severity: "LOW" },
                  { pattern: "SSN patterns", severity: "CRITICAL" },
                  { pattern: "Credit card numbers", severity: "CRITICAL" },
                  { pattern: "API keys/secrets", severity: "HIGH" },
                  { pattern: "Passwords in responses", severity: "CRITICAL" },
                  { pattern: "JWT tokens", severity: "MEDIUM" },
                  { pattern: "Database connection strings", severity: "CRITICAL" },
                  { pattern: "AWS credentials", severity: "CRITICAL" },
                  { pattern: "Private keys", severity: "CRITICAL" },
                ].map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <Chip 
                        label={item.severity} 
                        size="small" 
                        sx={{ 
                          fontSize: "0.6rem", 
                          height: 18,
                          bgcolor: item.severity === "CRITICAL" ? alpha("#ef4444", 0.2) : 
                                   item.severity === "HIGH" ? alpha("#f59e0b", 0.2) : 
                                   item.severity === "MEDIUM" ? alpha("#3b82f6", 0.2) : alpha("#10b981", 0.2),
                          color: item.severity === "CRITICAL" ? "#ef4444" : 
                                 item.severity === "HIGH" ? "#f59e0b" : 
                                 item.severity === "MEDIUM" ? "#3b82f6" : "#10b981",
                        }} 
                      />
                    </ListItemIcon>
                    <ListItemText primary={item.pattern} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          {/* Injection Payload Library */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%" }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#8b5cf6" }} />
                Built-in Injection Payload Library
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Comprehensive payload sets for vulnerability testing:
              </Typography>
              <List dense>
                {[
                  { category: "SQL Injection", count: "8+ payloads", examples: "UNION, OR 1=1, DROP TABLE" },
                  { category: "XSS", count: "6+ payloads", examples: "script tags, event handlers, SVG" },
                  { category: "Command Injection", count: "6+ payloads", examples: "semicolon, pipe, backtick" },
                  { category: "Path Traversal", count: "5+ payloads", examples: "../, encoded variants" },
                  { category: "SSRF", count: "Cloud metadata, internal IPs", examples: "169.254.169.254" },
                ].map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon fontSize="small" sx={{ color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<span><strong>{item.category}:</strong> {item.count}</span>}
                      secondary={item.examples}
                      primaryTypographyProps={{ variant: "body2" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 5: Best Practices */}
      <TabPanel value={activeTab} index={5}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon color="success" />
                Testing Best Practices
              </Typography>
              <List>
                {[
                  {
                    title: "Start with reconnaissance",
                    desc: "Use Network Discovery to find all HTTP services before testing"
                  },
                  {
                    title: "Use Quick Scan first",
                    desc: "Get a baseline before running comprehensive tests"
                  },
                  {
                    title: "Save targets as presets",
                    desc: "Create presets for frequently tested VMs and APIs"
                  },
                  {
                    title: "Enable proxy for detailed analysis",
                    desc: "Route traffic through Burp/ZAP for request inspection"
                  },
                  {
                    title: "Test with and without auth",
                    desc: "Compare results to identify auth bypass vulnerabilities"
                  },
                  {
                    title: "Document findings",
                    desc: "Use AI Analysis to generate reports for your findings"
                  },
                ].map((item, i) => (
                  <ListItem key={i}>
                    <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                    <ListItemText primary={item.title} secondary={item.desc} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon color="warning" />
                Common Pitfalls
              </Typography>
              <List>
                {[
                  {
                    title: "Scanning production without permission",
                    desc: "Always get authorization before testing"
                  },
                  {
                    title: "Ignoring low-severity findings",
                    desc: "Low findings can chain into high-impact attacks"
                  },
                  {
                    title: "Testing only authenticated endpoints",
                    desc: "Unauthenticated endpoints may have hidden vulnerabilities"
                  },
                  {
                    title: "Skipping WebSocket testing",
                    desc: "WebSockets often have different security controls"
                  },
                ].map((item, i) => (
                  <ListItem key={i}>
                    <ListItemIcon><WarningIcon color="warning" /></ListItemIcon>
                    <ListItemText primary={item.title} secondary={item.desc} />
                  </ListItem>
                ))}
              </List>
            </Paper>

            <Paper sx={{ p: 3 }}>
              <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <TipsAndUpdatesIcon color="info" />
                Pro Tips
              </Typography>
              <List dense>
                {[
                  "Use batch testing to compare security across API versions",
                  "Chain findings: weak auth + CORS = account takeover",
                  "Test rate limiting with different IP headers (X-Forwarded-For)",
                  "GraphQL? Enable introspection testing for schema discovery",
                  "Check /health, /status, /metrics endpoints - often unprotected",
                ].map((tip, i) => (
                  <ListItem key={i}>
                    <ListItemIcon><InfoIcon color="info" /></ListItemIcon>
                    <ListItemText primary={tip} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          {/* Workflow Diagram */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h5" gutterBottom>
                Recommended Testing Workflow
              </Typography>
              <Stepper alternativeLabel sx={{ mt: 3 }}>
                {[
                  { label: "Discovery", desc: "Find targets" },
                  { label: "Quick Scan", desc: "Initial assessment" },
                  { label: "Full Test", desc: "Comprehensive scan" },
                  { label: "WebSocket", desc: "Real-time endpoints" },
                  { label: "AI Analysis", desc: "Generate insights" },
                  { label: "Report", desc: "Document findings" },
                ].map((step, i) => (
                  <Step key={i} active>
                    <StepLabel>
                      <Typography variant="subtitle2">{step.label}</Typography>
                      <Typography variant="caption" color="text.secondary">{step.desc}</Typography>
                    </StepLabel>
                  </Step>
                ))}
              </Stepper>
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
    </LearnPageLayout>
  );
}
