import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
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
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Divider,
} from "@mui/material";
import {
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
  Psychology as AIIcon,
  Http as HttpIcon,
  Lock as LockIcon,
  BugReport as BugIcon,
  School as LearnIcon,
  Cable as WebSocketIcon,
  VpnKey as CertIcon,
  Shield as ShieldIcon,
  Terminal as TerminalIcon,
  Storage as StorageIcon,
  History as HistoryIcon,
  Save as SaveIcon,
  Science as ScienceIcon,
  Memory as MemoryIcon,
  AutoAwesome as AutoIcon,
  Timeline as TimelineIcon,
  AccountTree as TreeIcon,
  Speed as SpeedIcon,
  Cookie as CookieIcon,
  Code as CodeIcon,
  Dns as DnsIcon,
  Fingerprint as FingerprintIcon,
  Explore as ExploreIcon,
  DataObject as DataIcon,
  NetworkCheck as NetworkIcon,
} from "@mui/icons-material";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div hidden={value !== index} style={{ padding: "16px 0" }}>
      {value === index && children}
    </div>
  );
}

const MITMGuidePage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [mainTab, setMainTab] = useState(0);
  const [toolTab, setToolTab] = useState(0);

  const attackTools = {
    sslStripping: [
      {
        id: "sslstrip",
        name: "SSL Strip Attack",
        risk: "critical",
        description: "Downgrades HTTPS connections to HTTP by rewriting secure links. When a website sends a page with HTTPS links, this tool rewrites them to HTTP, allowing credentials to be captured in plaintext.",
        howItWorks: "1. Intercepts HTTP responses containing HTML\n2. Finds all HTTPS URLs (href, src, action attributes)\n3. Rewrites them to HTTP equivalents\n4. Removes HSTS headers to prevent browser enforcement\n5. User's browser now makes requests over HTTP, exposing credentials",
        triggers: ["Missing HSTS header", "HTTP links on HTTPS pages"],
      },
      {
        id: "hsts_bypass",
        name: "HSTS Preload Bypass",
        risk: "high",
        description: "Attempts to bypass HTTP Strict Transport Security by removing the header before the browser caches it.",
        howItWorks: "1. Removes Strict-Transport-Security header from responses\n2. Also removes Public-Key-Pins headers\n3. On first visit, browser never learns about HSTS\n4. Subsequent visits remain vulnerable to SSL stripping",
        triggers: ["HSTS header present", "Short HSTS max-age"],
      },
    ],
    credentialHarvesting: [
      {
        id: "credential_sniffer",
        name: "Credential Sniffer",
        risk: "low",
        description: "Passively monitors traffic for credentials, API keys, tokens, and authentication data without modifying anything.",
        howItWorks: "1. Analyzes all HTTP headers for Authorization, API-Key, Bearer tokens\n2. Parses request bodies for username/password fields\n3. Detects JWT tokens and decodes their payloads\n4. Identifies hardcoded secrets in request parameters\n5. Logs all findings without alerting the user",
        triggers: ["Basic/Bearer auth detected", "Form with password field", "API key in header"],
      },
      {
        id: "cookie_hijacker",
        name: "Session Cookie Hijacker",
        risk: "high",
        description: "Captures session cookies and strips security flags to enable hijacking and XSS attacks.",
        howItWorks: "1. Intercepts Set-Cookie headers in responses\n2. Removes HttpOnly flag (enables JavaScript access)\n3. Removes Secure flag (allows HTTP transmission)\n4. Removes SameSite attribute (enables CSRF)\n5. Captured cookies can be used for session hijacking",
        triggers: ["Cookie missing HttpOnly", "Cookie missing Secure", "Cookie missing SameSite"],
      },
    ],
    headerManipulation: [
      {
        id: "csp_bypass",
        name: "CSP Bypass/Stripper",
        risk: "medium",
        description: "Removes Content-Security-Policy headers to enable XSS attacks that would otherwise be blocked.",
        howItWorks: "1. Removes Content-Security-Policy header\n2. Removes CSP-Report-Only variant\n3. Removes legacy X-Content-Security-Policy\n4. Without CSP, inline scripts execute freely\n5. External malicious scripts can be loaded",
        triggers: ["CSP header present", "Strict CSP policy"],
      },
      {
        id: "cors_manipulator",
        name: "CORS Policy Manipulator",
        risk: "medium",
        description: "Opens up CORS policy to allow cross-origin attacks and data theft from any domain.",
        howItWorks: "1. Sets Access-Control-Allow-Origin to *\n2. Allows all HTTP methods (GET, POST, PUT, DELETE)\n3. Allows all headers\n4. Enables credentials in cross-origin requests\n5. Attacker's website can now make authenticated requests",
        triggers: ["CORS misconfigured", "CORS reflects Origin header"],
      },
      {
        id: "x_frame_bypass",
        name: "Clickjacking Enabler",
        risk: "medium",
        description: "Removes X-Frame-Options and frame-ancestors CSP directives to enable clickjacking attacks.",
        howItWorks: "1. Removes X-Frame-Options header from responses\n2. Modifies frame-ancestors CSP directive to allow all\n3. Page can now be embedded in attacker's iframe\n4. Attacker overlays invisible clicks on visible buttons\n5. User unknowingly performs actions on target site",
        triggers: ["X-Frame-Options present", "frame-ancestors in CSP"],
      },
    ],
    contentInjection: [
      {
        id: "script_injector",
        name: "JavaScript Injector",
        risk: "critical",
        description: "Injects malicious JavaScript into HTML responses for keylogging, credential theft, or phishing.",
        howItWorks: "1. Intercepts HTML responses before they reach browser\n2. Injects <script> tag before </body>\n3. Injected code captures all keystrokes\n4. Hooks form submit events to capture credentials\n5. Data is logged/exfiltrated to attacker",
        triggers: ["HTML response detected", "Missing or weak CSP"],
      },
      {
        id: "phishing_injector",
        name: "Phishing Content Injector",
        risk: "critical",
        description: "Injects fake login forms or 'session expired' popups to trick users into re-entering credentials.",
        howItWorks: "1. Detects login pages or authenticated sessions\n2. Injects convincing 'Session Expired' overlay\n3. Presents fake login form matching site's style\n4. User enters credentials thinking it's legitimate\n5. Credentials captured and overlay removed seamlessly",
        triggers: ["HTML response", "Login page detected"],
      },
    ],
    protocolAttacks: [
      {
        id: "response_smuggling",
        name: "HTTP Response Smuggling",
        risk: "high",
        description: "Manipulates Content-Length and Transfer-Encoding headers to smuggle malicious responses.",
        howItWorks: "1. Adds conflicting Content-Length and Transfer-Encoding\n2. Different parsers interpret response boundaries differently\n3. Smuggled content appears as separate response\n4. Can poison caches with malicious content\n5. Bypasses security controls that inspect responses",
        triggers: ["HTTP/1.1 connection", "Chunked transfer encoding"],
      },
      {
        id: "slow_loris",
        name: "Slow Response Tester",
        risk: "medium",
        description: "Introduces artificial delays to test application timeout handling and identify race conditions.",
        howItWorks: "1. Intercepts server responses\n2. Holds response for configurable delay (e.g., 5 seconds)\n3. Tests how client handles slow responses\n4. Identifies timeout vulnerabilities\n5. Can reveal race condition windows",
        triggers: ["Any traffic"],
      },
    ],
    reconnaissance: [
      {
        id: "header_analyzer",
        name: "Security Header Analyzer",
        risk: "low",
        description: "Analyzes all HTTP security headers and identifies missing or weak configurations.",
        howItWorks: "1. Captures all response headers\n2. Checks for presence of security headers (CSP, HSTS, X-Frame-Options, etc.)\n3. Validates header values against best practices\n4. Rates overall security posture\n5. Generates detailed recommendations",
        triggers: ["Any traffic captured"],
      },
      {
        id: "tech_fingerprint",
        name: "Technology Fingerprinter",
        risk: "low",
        description: "Identifies server technologies, frameworks, and versions from response headers and content.",
        howItWorks: "1. Analyzes Server, X-Powered-By headers\n2. Detects framework signatures in HTML/JS\n3. Identifies CMS platforms (WordPress, Drupal, etc.)\n4. Matches version patterns in responses\n5. Cross-references with vulnerability databases",
        triggers: ["Any traffic"],
      },
      {
        id: "endpoint_mapper",
        name: "API Endpoint Mapper",
        risk: "low",
        description: "Automatically discovers and maps API endpoints, parameters, and authentication requirements.",
        howItWorks: "1. Captures all unique URL paths\n2. Identifies parameter patterns\n3. Detects authentication requirements per endpoint\n4. Maps HTTP methods supported\n5. Builds comprehensive API surface map",
        triggers: ["API traffic detected"],
      },
    ],
  };

  const attackPhases = [
    {
      name: "Observation",
      icon: <ViewIcon />,
      color: "#3b82f6",
      description: "Passive reconnaissance - the agent watches traffic without making any modifications.",
      allowedRisks: ["Low risk tools only"],
      objectives: "Capture baseline traffic patterns, identify technologies, map endpoints",
      duration: "Continues until sufficient traffic is captured",
      tools: ["credential_sniffer", "header_analyzer", "tech_fingerprint", "endpoint_mapper"],
    },
    {
      name: "Analysis",
      icon: <ScienceIcon />,
      color: "#8b5cf6",
      description: "Active analysis - the agent begins identifying specific vulnerabilities.",
      allowedRisks: ["Low and Medium risk tools"],
      objectives: "Identify security misconfigurations, weak headers, vulnerable cookies",
      duration: "Progresses when analysis objectives met",
      tools: ["csp_bypass", "cors_manipulator", "x_frame_bypass", "slow_loris"],
    },
    {
      name: "Exploitation",
      icon: <BugIcon />,
      color: "#ef4444",
      description: "Active exploitation - the agent attempts to exploit discovered vulnerabilities.",
      allowedRisks: ["All tools including High and Critical"],
      objectives: "Capture credentials, hijack sessions, inject content",
      duration: "Continues until exploitation succeeds or all avenues exhausted",
      tools: ["sslstrip", "cookie_hijacker", "script_injector", "phishing_injector"],
    },
    {
      name: "Persistence",
      icon: <StorageIcon />,
      color: "#f59e0b",
      description: "Maintain access - establish persistent interception rules for ongoing capture.",
      allowedRisks: ["All tools"],
      objectives: "Set up long-term credential harvesting, maintain session hijacking",
      duration: "Runs until manually stopped",
      tools: ["All tools remain active", "Rules persist across sessions"],
    },
  ];

  const reasoningSteps = [
    {
      step: 1,
      name: "Situation Assessment",
      description: "The agent analyzes the current attack surface: What traffic has been captured? What technologies are in use? What security headers are present or missing?",
      example: "Detected: HTTPS site without HSTS, jQuery 3.4.1 (CVE-2020-11022), session cookie missing HttpOnly flag",
    },
    {
      step: 2,
      name: "Hypothesis Generation",
      description: "Based on the assessment, the agent generates hypotheses about potential vulnerabilities and attack vectors.",
      example: "Hypothesis: SSL stripping attack viable due to missing HSTS. Cookie hijacking possible due to missing HttpOnly.",
    },
    {
      step: 3,
      name: "Tool Selection (Thompson Sampling)",
      description: "The agent uses Thompson Sampling to balance exploration (trying new tools) with exploitation (using proven tools). Each tool has success/failure statistics that inform selection probability.",
      example: "sslstrip: 15 successes, 3 failures (beta distribution favors selection). cookie_hijacker: 8 successes, 1 failure.",
    },
    {
      step: 4,
      name: "Execution & Observation",
      description: "The selected tool is executed, and the agent observes the results. Did credentials get captured? Did the attack succeed? What new information was revealed?",
      example: "Executed sslstrip. Result: 2 login forms now submitting over HTTP. Credentials captured: admin@example.com",
    },
    {
      step: 5,
      name: "Learning & Adaptation",
      description: "Results are recorded in the memory system. Success/failure statistics are updated. The agent adapts its strategy for the next iteration.",
      example: "Updated sslstrip stats: 16 successes, 3 failures. Memory stored for cross-session learning. Moving to exploitation phase.",
    },
  ];

  const pageContext = `This is the MITM Workbench learning guide covering Man-in-the-Middle attacks, traffic interception,
SSL stripping, credential harvesting, the Agentic AI system with Thompson Sampling, attack phases (Observation, Analysis,
Exploitation, Persistence), chain-of-thought reasoning, cross-session learning, security header analysis, and 28+ attack tools
across categories like SSL Stripping, Credential Harvesting, Header Manipulation, Content Injection, Protocol Attacks, and Reconnaissance.`;

  return (
    <LearnPageLayout
      pageTitle="MITM Workbench Guide"
      pageContext={pageContext}
    >
      <Box sx={{ minHeight: "100vh", bgcolor: "background.default", pb: 8 }}>
        {/* Header */}
        <Box sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05), py: 4, mb: 4 }}>
          <Box sx={{ maxWidth: 1200, mx: "auto", px: 3 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
              <MitmIcon sx={{ fontSize: 40, color: "primary.main" }} />
              <Typography variant="h3" fontWeight={700}>
                MITM Workbench
              </Typography>
            </Box>
            <Typography variant="h6" color="text.secondary" sx={{ mb: 2 }}>
              AI-Powered Traffic Interception and Security Analysis Platform
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              <Chip label="Dynamic Analysis" color="primary" size="small" />
              <Chip label="Intermediate" size="small" />
              <Chip label="MITM" size="small" variant="outlined" />
              <Chip label="Proxy" size="small" variant="outlined" />
              <Chip label="Traffic Analysis" size="small" variant="outlined" />
              <Chip label="AI" size="small" variant="outlined" />
              <Chip label="Credential Harvesting" size="small" variant="outlined" />
            </Box>
          </Box>
        </Box>

        <Box sx={{ maxWidth: 1200, mx: "auto", px: 3 }}>
      {/* Introduction Section */}
      <Box id="what-is-mitm" sx={{ mb: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" gutterBottom fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <MitmIcon color="primary" /> What is Man-in-the-Middle (MITM)?
        </Typography>

        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>For Beginners:</strong> Imagine you're passing notes in class. A MITM attack is like someone sitting between you and your friend,
            reading every note before passing it on - and potentially changing what the note says. In the digital world, this means intercepting
            network traffic between a user and a server.
          </Typography>
        </Alert>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
          <Typography variant="body1" paragraph>
            A <strong>Man-in-the-Middle (MITM) attack</strong> occurs when an attacker secretly intercepts and potentially alters
            communications between two parties who believe they are communicating directly with each other.
          </Typography>

          <Grid container spacing={2} sx={{ mt: 2 }}>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <ViewIcon color="primary" />
                    <Typography variant="subtitle1" fontWeight={600}>Eavesdropping</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Passively observe all traffic between client and server, capturing credentials, session tokens, and sensitive data.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <RuleIcon color="warning" />
                    <Typography variant="subtitle1" fontWeight={600}>Modification</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Actively modify requests and responses - inject scripts, strip security headers, downgrade encryption.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <BugIcon color="error" />
                    <Typography variant="subtitle1" fontWeight={600}>Exploitation</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Exploit discovered vulnerabilities - hijack sessions, capture credentials, perform injection attacks.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Paper>

        <Typography variant="h6" gutterBottom fontWeight={600}>
          Why Use the MITM Workbench?
        </Typography>
        <List>
          <ListItem>
            <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
            <ListItemText
              primary="Security Testing"
              secondary="Test your applications against real-world MITM attacks before malicious actors do"
            />
          </ListItem>
          <ListItem>
            <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
            <ListItemText
              primary="Vulnerability Discovery"
              secondary="Automatically identify missing security headers, weak cookies, and exploitable misconfigurations"
            />
          </ListItem>
          <ListItem>
            <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
            <ListItemText
              primary="Educational Learning"
              secondary="Understand how attacks work in a controlled environment with detailed explanations"
            />
          </ListItem>
          <ListItem>
            <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
            <ListItemText
              primary="AI-Powered Analysis"
              secondary="Let the intelligent agent automatically discover and exploit vulnerabilities while you learn"
            />
          </ListItem>
        </List>
      </Box>

      <Divider sx={{ my: 4 }} />

      {/* How the Proxy Works */}
      <Box id="how-proxy-works" sx={{ mb: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" gutterBottom fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <NetworkIcon color="primary" /> How the Proxy Works
        </Typography>

        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>For Beginners:</strong> A proxy is like a translator that sits between you and a website. Every message you send
            goes through the translator first, and every response comes back through them too. Our proxy can read, analyze, and
            optionally modify these messages.
          </Typography>
        </Alert>

        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom fontWeight={600}>Network Flow</Typography>
          <Box sx={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 2,
            p: 3,
            bgcolor: alpha(theme.palette.background.default, 0.5),
            borderRadius: 2,
            flexWrap: "wrap"
          }}>
            <Chip icon={<StorageIcon />} label="Your Browser" color="primary" />
            <Typography variant="h5">→</Typography>
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.1), border: `2px solid ${theme.palette.warning.main}` }}>
              <Typography variant="subtitle2" fontWeight={700} color="warning.main">MITM Proxy</Typography>
              <Typography variant="caption" display="block">Intercepts & Analyzes</Typography>
            </Paper>
            <Typography variant="h5">→</Typography>
            <Chip icon={<HttpIcon />} label="Target Server" color="secondary" />
          </Box>
        </Paper>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="h6" gutterBottom fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <LockIcon color="primary" /> TLS/SSL Interception
                </Typography>
                <Typography variant="body2" paragraph>
                  The proxy can intercept HTTPS traffic by acting as a certificate authority. When enabled:
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemText
                      primary="1. Proxy generates a certificate for the target domain"
                      secondary="Signed by the proxy's root CA certificate"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="2. Browser trusts the certificate"
                      secondary="After you install the proxy's CA certificate"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="3. Traffic is decrypted, analyzed, then re-encrypted"
                      secondary="Proxy maintains separate TLS sessions with client and server"
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="h6" gutterBottom fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <RuleIcon color="warning" /> Interception Modes
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><ViewIcon fontSize="small" /></ListItemIcon>
                    <ListItemText
                      primary="Passthrough Mode"
                      secondary="Observe traffic without modifications - pure reconnaissance"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><AutoIcon fontSize="small" color="warning" /></ListItemIcon>
                    <ListItemText
                      primary="Auto-Modify Mode (Default)"
                      secondary="Automatically apply attack rules based on AI recommendations"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><RuleIcon fontSize="small" color="error" /></ListItemIcon>
                    <ListItemText
                      primary="Manual Intercept Mode"
                      secondary="Pause each request/response for manual inspection and modification"
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      <Divider sx={{ my: 4 }} />

      {/* Attack Tools Library */}
      <Box id="attack-tools" sx={{ mb: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" gutterBottom fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <BugIcon color="primary" /> Attack Tools Library
        </Typography>

        <Alert severity="warning" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>28+ Attack Tools</strong> organized by category. Each tool is automatically selected by the AI agent based on
            discovered vulnerabilities, or can be manually triggered for specific testing scenarios.
          </Typography>
        </Alert>

        <Tabs value={toolTab} onChange={(_, v) => setToolTab(v)} sx={{ mb: 2 }}>
          <Tab label="SSL Stripping" icon={<LockIcon />} iconPosition="start" />
          <Tab label="Credential Harvesting" icon={<FingerprintIcon />} iconPosition="start" />
          <Tab label="Header Manipulation" icon={<CodeIcon />} iconPosition="start" />
          <Tab label="Content Injection" icon={<DataIcon />} iconPosition="start" />
          <Tab label="Protocol Attacks" icon={<NetworkIcon />} iconPosition="start" />
          <Tab label="Reconnaissance" icon={<ExploreIcon />} iconPosition="start" />
        </Tabs>

        <TabPanel value={toolTab} index={0}>
          {attackTools.sslStripping.map((tool) => (
            <Accordion key={tool.id} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography fontWeight={600}>{tool.name}</Typography>
                  <Chip
                    label={tool.risk}
                    size="small"
                    color={tool.risk === "critical" ? "error" : tool.risk === "high" ? "warning" : "default"}
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" paragraph>{tool.description}</Typography>
                <Typography variant="subtitle2" fontWeight={600}>How It Works:</Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), mb: 2 }}>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-line", fontFamily: "monospace" }}>
                    {tool.howItWorks}
                  </Typography>
                </Paper>
                <Typography variant="subtitle2" fontWeight={600}>Triggered By:</Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 1 }}>
                  {tool.triggers.map((t, i) => (
                    <Chip key={i} label={t} size="small" variant="outlined" />
                  ))}
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </TabPanel>

        <TabPanel value={toolTab} index={1}>
          {attackTools.credentialHarvesting.map((tool) => (
            <Accordion key={tool.id} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography fontWeight={600}>{tool.name}</Typography>
                  <Chip
                    label={tool.risk}
                    size="small"
                    color={tool.risk === "critical" ? "error" : tool.risk === "high" ? "warning" : tool.risk === "low" ? "success" : "default"}
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" paragraph>{tool.description}</Typography>
                <Typography variant="subtitle2" fontWeight={600}>How It Works:</Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), mb: 2 }}>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-line", fontFamily: "monospace" }}>
                    {tool.howItWorks}
                  </Typography>
                </Paper>
                <Typography variant="subtitle2" fontWeight={600}>Triggered By:</Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 1 }}>
                  {tool.triggers.map((t, i) => (
                    <Chip key={i} label={t} size="small" variant="outlined" />
                  ))}
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </TabPanel>

        <TabPanel value={toolTab} index={2}>
          {attackTools.headerManipulation.map((tool) => (
            <Accordion key={tool.id} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography fontWeight={600}>{tool.name}</Typography>
                  <Chip
                    label={tool.risk}
                    size="small"
                    color={tool.risk === "critical" ? "error" : tool.risk === "high" ? "warning" : "default"}
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" paragraph>{tool.description}</Typography>
                <Typography variant="subtitle2" fontWeight={600}>How It Works:</Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), mb: 2 }}>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-line", fontFamily: "monospace" }}>
                    {tool.howItWorks}
                  </Typography>
                </Paper>
                <Typography variant="subtitle2" fontWeight={600}>Triggered By:</Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 1 }}>
                  {tool.triggers.map((t, i) => (
                    <Chip key={i} label={t} size="small" variant="outlined" />
                  ))}
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </TabPanel>

        <TabPanel value={toolTab} index={3}>
          {attackTools.contentInjection.map((tool) => (
            <Accordion key={tool.id} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography fontWeight={600}>{tool.name}</Typography>
                  <Chip
                    label={tool.risk}
                    size="small"
                    color={tool.risk === "critical" ? "error" : tool.risk === "high" ? "warning" : "default"}
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" paragraph>{tool.description}</Typography>
                <Typography variant="subtitle2" fontWeight={600}>How It Works:</Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), mb: 2 }}>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-line", fontFamily: "monospace" }}>
                    {tool.howItWorks}
                  </Typography>
                </Paper>
                <Typography variant="subtitle2" fontWeight={600}>Triggered By:</Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 1 }}>
                  {tool.triggers.map((t, i) => (
                    <Chip key={i} label={t} size="small" variant="outlined" />
                  ))}
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </TabPanel>

        <TabPanel value={toolTab} index={4}>
          {attackTools.protocolAttacks.map((tool) => (
            <Accordion key={tool.id} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography fontWeight={600}>{tool.name}</Typography>
                  <Chip
                    label={tool.risk}
                    size="small"
                    color={tool.risk === "critical" ? "error" : tool.risk === "high" ? "warning" : "default"}
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" paragraph>{tool.description}</Typography>
                <Typography variant="subtitle2" fontWeight={600}>How It Works:</Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), mb: 2 }}>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-line", fontFamily: "monospace" }}>
                    {tool.howItWorks}
                  </Typography>
                </Paper>
                <Typography variant="subtitle2" fontWeight={600}>Triggered By:</Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 1 }}>
                  {tool.triggers.map((t, i) => (
                    <Chip key={i} label={t} size="small" variant="outlined" />
                  ))}
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </TabPanel>

        <TabPanel value={toolTab} index={5}>
          {attackTools.reconnaissance.map((tool) => (
            <Accordion key={tool.id} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography fontWeight={600}>{tool.name}</Typography>
                  <Chip
                    label={tool.risk}
                    size="small"
                    color="success"
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" paragraph>{tool.description}</Typography>
                <Typography variant="subtitle2" fontWeight={600}>How It Works:</Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), mb: 2 }}>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-line", fontFamily: "monospace" }}>
                    {tool.howItWorks}
                  </Typography>
                </Paper>
                <Typography variant="subtitle2" fontWeight={600}>Triggered By:</Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 1 }}>
                  {tool.triggers.map((t, i) => (
                    <Chip key={i} label={t} size="small" variant="outlined" />
                  ))}
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </TabPanel>
      </Box>

      <Divider sx={{ my: 4 }} />

      {/* Agentic AI System */}
      <Box id="agentic-ai" sx={{ mb: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" gutterBottom fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AIIcon color="primary" /> Agentic AI System
        </Typography>

        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>For Beginners:</strong> The AI agent is like having an expert pentester sitting next to you. It watches the traffic,
            identifies vulnerabilities, decides which attacks to try, learns from successes and failures, and progressively escalates
            from passive observation to active exploitation - all automatically.
          </Typography>
        </Alert>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.secondary.main, 0.05) }}>
          <Typography variant="h6" gutterBottom fontWeight={600}>
            How the Agent Thinks
          </Typography>
          <Typography variant="body2" paragraph>
            The MITM agent uses a sophisticated decision-making system combining multiple AI techniques:
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} color="primary">Chain-of-Thought Reasoning</Typography>
                  <Typography variant="body2" color="text.secondary">
                    5-step reasoning process that mimics how a human pentester would approach the target
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} color="primary">Thompson Sampling</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Probabilistic tool selection that balances trying new tools with using proven successful ones
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} color="primary">Cross-Session Learning</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Memories persist in database, so the agent learns from all previous testing sessions
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Paper>

        {/* Attack Phases */}
        <Box id="attack-phases" sx={{ mb: 4, scrollMarginTop: 80 }}>
          <Typography variant="h5" gutterBottom fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <TimelineIcon /> Attack Phases
          </Typography>
          <Typography variant="body2" paragraph color="text.secondary">
            The agent progresses through phases, starting with passive observation and escalating to active exploitation
            only after sufficient reconnaissance. This mimics real-world attacker behavior.
          </Typography>

          <Grid container spacing={2}>
            {attackPhases.map((phase, index) => (
              <Grid item xs={12} md={3} key={phase.name}>
                <Card
                  sx={{
                    height: "100%",
                    borderTop: `4px solid ${phase.color}`,
                    position: "relative",
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                      <Box sx={{ color: phase.color }}>{phase.icon}</Box>
                      <Typography variant="h6" fontWeight={600}>{phase.name}</Typography>
                    </Box>
                    <Typography variant="body2" paragraph>{phase.description}</Typography>
                    <Typography variant="caption" display="block" color="text.secondary">
                      <strong>Allowed:</strong> {phase.allowedRisks}
                    </Typography>
                    <Typography variant="caption" display="block" color="text.secondary" sx={{ mt: 1 }}>
                      <strong>Objectives:</strong> {phase.objectives}
                    </Typography>
                    {index < attackPhases.length - 1 && (
                      <Box sx={{ position: "absolute", right: -12, top: "50%", transform: "translateY(-50%)", display: { xs: "none", md: "block" } }}>
                        <Typography variant="h5" color="text.disabled">→</Typography>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Chain-of-Thought Reasoning */}
        <Box id="reasoning-engine" sx={{ mb: 4, scrollMarginTop: 80 }}>
          <Typography variant="h5" gutterBottom fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <TreeIcon /> Chain-of-Thought Reasoning
          </Typography>
          <Typography variant="body2" paragraph color="text.secondary">
            Each decision the agent makes follows a 5-step reasoning process, creating an auditable chain of logic.
          </Typography>

          <Stepper orientation="vertical">
            {reasoningSteps.map((step) => (
              <Step key={step.step} active expanded>
                <StepLabel>
                  <Typography variant="subtitle1" fontWeight={600}>{step.name}</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" paragraph>{step.description}</Typography>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                    <Typography variant="caption" color="text.secondary">Example:</Typography>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{step.example}</Typography>
                  </Paper>
                </StepContent>
              </Step>
            ))}
          </Stepper>
        </Box>

        {/* Thompson Sampling */}
        <Box id="thompson-sampling" sx={{ mb: 4, scrollMarginTop: 80 }}>
          <Typography variant="h5" gutterBottom fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <ScienceIcon /> Thompson Sampling
          </Typography>

          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="body2">
              <strong>For Beginners:</strong> Imagine you're at a casino with many slot machines. Some might pay out more than others,
              but you don't know which. Thompson Sampling is a smart strategy: it balances trying new machines (exploration) with
              playing machines that have paid out before (exploitation).
            </Typography>
          </Alert>

          <Paper sx={{ p: 3 }}>
            <Typography variant="body1" paragraph>
              Thompson Sampling is a probabilistic algorithm that solves the <strong>explore-exploit dilemma</strong>:
            </Typography>
            <List>
              <ListItem>
                <ListItemIcon><ExploreIcon color="primary" /></ListItemIcon>
                <ListItemText
                  primary="Exploration"
                  secondary="Try tools that haven't been tested much - they might be very effective against this target"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckIcon color="success" /></ListItemIcon>
                <ListItemText
                  primary="Exploitation"
                  secondary="Use tools that have proven successful in the past - higher probability of success"
                />
              </ListItem>
            </List>

            <Typography variant="subtitle2" fontWeight={600} sx={{ mt: 2 }}>How It Works (Technical):</Typography>
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), mt: 1 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                1. Each tool maintains success (α) and failure (β) counts{"\n"}
                2. For selection, sample from Beta(α + 1, β + 1) distribution{"\n"}
                3. Tool with highest sampled value is selected{"\n"}
                4. After execution, update α (success) or β (failure){"\n"}
                5. Tools with uncertain performance have higher variance → more exploration{"\n"}
                6. Tools with consistent success have higher mean → more exploitation
              </Typography>
            </Paper>
          </Paper>
        </Box>

        {/* Cross-Session Learning */}
        <Box id="cross-session-learning" sx={{ mb: 4, scrollMarginTop: 80 }}>
          <Typography variant="h5" gutterBottom fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <MemoryIcon /> Cross-Session Learning
          </Typography>

          <Paper sx={{ p: 3 }}>
            <Typography variant="body1" paragraph>
              The agent's memories are persisted in the database, enabling learning across sessions:
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle1" fontWeight={600}>What's Remembered</Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Tool effectiveness per target type" /></ListItem>
                      <ListItem><ListItemText primary="Attack surface patterns" /></ListItem>
                      <ListItem><ListItemText primary="Successful attack chains" /></ListItem>
                      <ListItem><ListItemText primary="Reasoning chains that led to discoveries" /></ListItem>
                      <ListItem><ListItemText primary="Credentials and tokens captured" /></ListItem>
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle1" fontWeight={600}>How It Helps</Typography>
                    <List dense>
                      <ListItem><ListItemText primary="New scans benefit from past experience" /></ListItem>
                      <ListItem><ListItemText primary="Similar targets get optimized tool selection" /></ListItem>
                      <ListItem><ListItemText primary="Failure patterns are avoided" /></ListItem>
                      <ListItem><ListItemText primary="Attack chains are replayed on similar targets" /></ListItem>
                      <ListItem><ListItemText primary="Overall efficiency improves over time" /></ListItem>
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Paper>
        </Box>
      </Box>

      <Divider sx={{ my: 4 }} />

      {/* AI Traffic Analysis */}
      <Box id="traffic-analysis" sx={{ mb: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" gutterBottom fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <ScienceIcon color="primary" /> AI Traffic Analysis
        </Typography>

        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="body1" paragraph>
            The workbench includes AI-powered analysis that examines captured traffic using Google's Gemini model:
          </Typography>

          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} color="primary">Security Assessment</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Analyzes headers, cookies, and responses to identify security misconfigurations
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} color="primary">Vulnerability Detection</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Cross-references findings with CVE databases and known exploit patterns
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} color="primary">Attack Path Generation</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Identifies multi-step attack chains combining multiple vulnerabilities
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Typography variant="subtitle2" fontWeight={600} sx={{ mt: 3, mb: 1 }}>Analysis Output Includes:</Typography>
          <List dense>
            <ListItem>
              <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
              <ListItemText primary="Risk score and severity assessment" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
              <ListItemText primary="Detailed findings with exploitation steps" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
              <ListItemText primary="CVE references for identified vulnerabilities" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
              <ListItemText primary="Exploit references from public databases" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
              <ListItemText primary="Remediation recommendations" />
            </ListItem>
          </List>
        </Paper>
      </Box>

      <Divider sx={{ my: 4 }} />

      {/* Getting Started */}
      <Box id="getting-started" sx={{ mb: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" gutterBottom fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <PlayIcon color="primary" /> Getting Started
        </Typography>

        <Stepper orientation="vertical">
          <Step active expanded>
            <StepLabel><Typography fontWeight={600}>Create a New Proxy</Typography></StepLabel>
            <StepContent>
              <Typography variant="body2" paragraph>
                Click "New Proxy" and configure your target. The proxy listens on your machine and forwards traffic to the target server.
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Listen Port: Where your browser connects (e.g., 8080)" /></ListItem>
                <ListItem><ListItemText primary="Target Host: The server you're testing (e.g., example.com)" /></ListItem>
                <ListItem><ListItemText primary="Target Port: Usually 80 (HTTP) or 443 (HTTPS)" /></ListItem>
                <ListItem><ListItemText primary="TLS Enabled: Check for HTTPS targets" /></ListItem>
              </List>
            </StepContent>
          </Step>

          <Step active expanded>
            <StepLabel><Typography fontWeight={600}>Configure Your Browser</Typography></StepLabel>
            <StepContent>
              <Typography variant="body2" paragraph>
                Point your browser's proxy settings to the MITM proxy:
              </Typography>
              <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                  HTTP Proxy: 127.0.0.1:8080{"\n"}
                  HTTPS Proxy: 127.0.0.1:8080
                </Typography>
              </Paper>
              <Alert severity="info" sx={{ mt: 2 }}>
                For HTTPS interception, you'll need to install the proxy's CA certificate in your browser.
                Go to the "Certificates" tab in the workbench to download it.
              </Alert>
            </StepContent>
          </Step>

          <Step active expanded>
            <StepLabel><Typography fontWeight={600}>Start the Agentic Session</Typography></StepLabel>
            <StepContent>
              <Typography variant="body2" paragraph>
                Click "Start Agentic Session" to let the AI agent take over. It will:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Begin in observation phase (passive)" /></ListItem>
                <ListItem><ListItemText primary="Analyze traffic as it flows through" /></ListItem>
                <ListItem><ListItemText primary="Identify vulnerabilities automatically" /></ListItem>
                <ListItem><ListItemText primary="Progress through phases based on findings" /></ListItem>
                <ListItem><ListItemText primary="Execute appropriate attack tools" /></ListItem>
              </List>
            </StepContent>
          </Step>

          <Step active expanded>
            <StepLabel><Typography fontWeight={600}>Browse the Target</Typography></StepLabel>
            <StepContent>
              <Typography variant="body2" paragraph>
                Navigate through the target application in your browser. Every request flows through the proxy:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Log in to capture authentication traffic" /></ListItem>
                <ListItem><ListItemText primary="Submit forms to capture POST data" /></ListItem>
                <ListItem><ListItemText primary="Navigate different sections to discover endpoints" /></ListItem>
              </List>
            </StepContent>
          </Step>

          <Step active expanded>
            <StepLabel><Typography fontWeight={600}>Review Results</Typography></StepLabel>
            <StepContent>
              <Typography variant="body2" paragraph>
                Stop the session to view the comprehensive report:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Captured credentials and tokens" /></ListItem>
                <ListItem><ListItemText primary="Identified vulnerabilities with severity" /></ListItem>
                <ListItem><ListItemText primary="Attack paths and exploit chains" /></ListItem>
                <ListItem><ListItemText primary="Decision log showing agent reasoning" /></ListItem>
                <ListItem><ListItemText primary="Tools used and their effectiveness" /></ListItem>
              </List>
              <Alert severity="success" sx={{ mt: 2 }}>
                Reports are auto-saved when you stop the proxy. If opened from a project, they're automatically
                associated and appear in Combined Analysis.
              </Alert>
            </StepContent>
          </Step>
        </Stepper>
      </Box>

      <Divider sx={{ my: 4 }} />

      {/* Best Practices */}
      <Box id="best-practices" sx={{ mb: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" gutterBottom fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <ShieldIcon color="primary" /> Best Practices
        </Typography>

        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="h6" fontWeight={600} color="success.main" gutterBottom>
                  Do's
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Only test applications you own or have explicit permission to test" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Use a dedicated testing environment or browser profile" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Start with observation mode to understand the application" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Review the decision log to understand what the agent found" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Use projects to organize related scans" />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="h6" fontWeight={600} color="error.main" gutterBottom>
                  Don'ts
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><ErrorIcon color="error" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Never test production systems without authorization" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><ErrorIcon color="error" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Don't use critical mode on systems you don't control" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><ErrorIcon color="error" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Avoid testing sensitive financial or healthcare systems" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><ErrorIcon color="error" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Don't leave the proxy running when not actively testing" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><ErrorIcon color="error" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Never store captured credentials insecurely" />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* CTA */}
      <Paper sx={{ p: 4, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
        <Typography variant="h5" gutterBottom fontWeight={600}>
          Ready to Start Testing?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Launch the MITM Workbench and let the AI agent discover vulnerabilities in your applications.
        </Typography>
        <Button
          variant="contained"
          size="large"
          startIcon={<PlayIcon />}
          onClick={() => navigate("/mitm-workbench")}
          sx={{ mr: 2 }}
        >
          Open MITM Workbench
        </Button>
        <Button
          variant="outlined"
          size="large"
          startIcon={<LearnIcon />}
          onClick={() => navigate("/learn")}
        >
          Back to Learning Hub
        </Button>
      </Paper>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default MITMGuidePage;
