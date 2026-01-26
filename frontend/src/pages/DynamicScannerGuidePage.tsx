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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  keyframes,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SpeedIcon from "@mui/icons-material/Speed";
import SearchIcon from "@mui/icons-material/Search";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SchoolIcon from "@mui/icons-material/School";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningIcon from "@mui/icons-material/Warning";
import LayersIcon from "@mui/icons-material/Layers";
import FlagIcon from "@mui/icons-material/Flag";
import CodeIcon from "@mui/icons-material/Code";
import AnalyticsIcon from "@mui/icons-material/Analytics";
import ShieldIcon from "@mui/icons-material/Shield";
import PsychologyIcon from "@mui/icons-material/Psychology";
import DataObjectIcon from "@mui/icons-material/DataObject";
import HttpIcon from "@mui/icons-material/Http";
import StorageIcon from "@mui/icons-material/Storage";
import KeyIcon from "@mui/icons-material/Key";
import ApiIcon from "@mui/icons-material/Api";
import LearnPageLayout from "../components/LearnPageLayout";

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
`;

const aiGlow = keyframes`
  0%, 100% { box-shadow: 0 0 20px rgba(139, 92, 246, 0.3); }
  50% { box-shadow: 0 0 40px rgba(139, 92, 246, 0.6); }
`;

export default function DynamicScannerGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const integratedTools = [
    {
      name: "Nmap",
      purpose: "Network reconnaissance & port discovery",
      phase: "Always first",
      color: "#3b82f6",
      icon: <NetworkCheckIcon />,
      description: "Discovers hosts, open ports, and running services"
    },
    {
      name: "OWASP ZAP",
      purpose: "Web vulnerability scanning",
      phase: "HTTP/HTTPS targets",
      color: "#f59e0b",
      icon: <HttpIcon />,
      description: "Active DAST for injection, XSS, auth bypass, and more"
    },
    {
      name: "Nuclei",
      purpose: "CVE detection & template scanning",
      phase: "Network services",
      color: "#22c55e",
      icon: <BugReportIcon />,
      description: "Template-based detection of known vulnerabilities"
    },
    {
      name: "OpenVAS",
      purpose: "Network vulnerability assessment",
      phase: "Deep network scan",
      color: "#10b981",
      icon: <StorageIcon />,
      description: "Comprehensive network service vulnerability scanning"
    },
    {
      name: "SQLMap",
      purpose: "SQL injection testing",
      phase: "SQL endpoints",
      color: "#ef4444",
      icon: <DataObjectIcon />,
      description: "Automated SQL injection exploitation and database enumeration"
    },
    {
      name: "Wapiti",
      purpose: "Web vulnerability scanner",
      phase: "Parallel web scan",
      color: "#8b5cf6",
      icon: <SecurityIcon />,
      description: "Alternative web scanner for comprehensive coverage"
    },
    {
      name: "Gobuster",
      purpose: "Directory enumeration",
      phase: "Web targets",
      color: "#06b6d4",
      icon: <SearchIcon />,
      description: "Brute-force hidden directories and files on web servers"
    },
    {
      name: "ExploitDB",
      purpose: "Exploit mapping",
      phase: "After findings",
      color: "#dc2626",
      icon: <CodeIcon />,
      description: "Links CVEs to publicly available exploits"
    },
  ];

  const scanningPhases = [
    { phase: "INITIALIZING", description: "Setup and validation of scan parameters", icon: <PlayArrowIcon />, color: "#6b7280" },
    { phase: "RECONNAISSANCE", description: "Nmap discovers hosts, ports, and services", icon: <NetworkCheckIcon />, color: "#3b82f6" },
    { phase: "ROUTING", description: "AI determines which scanners to use for which targets", icon: <PsychologyIcon />, color: "#8b5cf6" },
    { phase: "DIRECTORY_ENUMERATION", description: "Discover hidden paths with Gobuster/Dirbuster", icon: <SearchIcon />, color: "#06b6d4" },
    { phase: "WEB_SCANNING", description: "ZAP performs active web vulnerability scanning", icon: <HttpIcon />, color: "#f59e0b" },
    { phase: "WAPITI_SCANNING", description: "Alternative web scanner for additional coverage", icon: <SecurityIcon />, color: "#8b5cf6" },
    { phase: "SQLMAP_SCANNING", description: "SQL injection testing on discovered endpoints", icon: <DataObjectIcon />, color: "#ef4444" },
    { phase: "OPENVAS_SCANNING", description: "Deep network vulnerability assessment", icon: <StorageIcon />, color: "#10b981" },
    { phase: "CVE_SCANNING", description: "Nuclei template-based CVE detection", icon: <BugReportIcon />, color: "#22c55e" },
    { phase: "EXPLOIT_MAPPING", description: "Link findings to available exploits in ExploitDB", icon: <CodeIcon />, color: "#dc2626" },
    { phase: "AI_ANALYSIS", description: "Generate attack narratives and recommendations", icon: <PsychologyIcon />, color: "#8b5cf6" },
    { phase: "COMPLETED", description: "Scan finished successfully", icon: <CheckCircleIcon />, color: "#10b981" },
  ];

  const advancedFeatures = [
    {
      title: "🔐 Authenticated Scanning",
      description: "Scan behind login pages with multiple authentication methods",
      features: [
        "Form-based authentication (username/password)",
        "JSON-based authentication for APIs",
        "HTTP Basic authentication",
        "Script-based custom auth workflows",
        "Multiple auth profiles for role-based scanning",
        "OpenVAS credential integration (SSH, SMB, SNMP)",
      ],
      color: "#f59e0b",
    },
    {
      title: "🌐 API Discovery & Testing",
      description: "Comprehensive API security testing with schema support",
      features: [
        "OpenAPI/Swagger spec import and seeding",
        "GraphQL schema analysis and endpoint generation",
        "Automatic endpoint discovery from specs",
        "API parameter fuzzing and injection testing",
        "RESTful API vulnerability detection",
        "Base URL override for flexible testing",
      ],
      color: "#06b6d4",
    },
    {
      title: "🎭 Dynamic Content Handling",
      description: "Handle JavaScript-heavy SPAs and dynamic content",
      features: [
        "Headless browser crawling with Playwright",
        "Login automation with CSS selectors",
        "HAR (HTTP Archive) capture and import",
        "JavaScript endpoint extraction",
        "Query/form parameter discovery",
        "Max page and duration limits for control",
      ],
      color: "#8b5cf6",
    },
    {
      title: "📡 Out-of-Band Testing",
      description: "Detect blind vulnerabilities via callback payloads",
      features: [
        "Configurable callback domain/port/protocol",
        "Blind SQL injection detection",
        "SSRF and XXE validation via callbacks",
        "Command injection confirmation",
        "Callback receipt validation and tracking",
        "Supports HTTP, HTTPS, and DNS protocols",
      ],
      color: "#ef4444",
    },
    {
      title: "✅ Vulnerability Validation",
      description: "Separate validation pass to reduce false positives",
      features: [
        "Re-verify high/critical findings",
        "Evidence collection and analysis",
        "False positive marking and filtering",
        "Validated vs unvalidated tracking",
        "Configurable max findings to validate",
        "Increases confidence in results",
      ],
      color: "#22c55e",
    },
    {
      title: "🔍 Discovery & Reconnaissance",
      description: "Enhanced target discovery beyond basic crawling",
      features: [
        "JavaScript source code parsing for endpoints",
        "Automatic URL discovery from multiple sources",
        "Parameter discovery from forms and queries",
        "Coverage tracking and statistics",
        "Sitemap and robots.txt parsing",
        "Comment extraction for sensitive data",
      ],
      color: "#3b82f6",
    },
  ];

  const aiFeatures = [
    {
      title: "Intelligent Scan Planning",
      description: "AI analyzes your target and context to determine the optimal scanning strategy",
      capabilities: [
        "Auto-detects target type (IP, domain, URL, CIDR)",
        "Selects appropriate scan depth based on context",
        "Chooses tools intelligently based on services",
        "Adaptive replanning based on findings",
      ],
    },
    {
      title: "Service-Based Routing",
      description: "AI automatically routes discovered services to the right scanners",
      capabilities: [
        "Web services → ZAP, Wapiti, SQLMap",
        "Database services → Nuclei, OpenVAS",
        "SSH/RDP → Credential testing, version checks",
        "Custom NSE script selection per service",
      ],
    },
    {
      title: "Attack Narrative Generation",
      description: "AI creates a cohesive story of how attacks could unfold",
      capabilities: [
        "Executive summaries for stakeholders",
        "Step-by-step attack chain construction",
        "Impact and likelihood assessments",
        "Prioritized remediation roadmap",
      ],
    },
    {
      title: "Exploit Chain Construction",
      description: "AI identifies sequences of vulnerabilities that can be chained together",
      capabilities: [
        "Multi-stage attack path identification",
        "Privilege escalation opportunities",
        "Lateral movement potential",
        "Combined exploitation scenarios",
      ],
    },
  ];

  const gettingStartedSteps = [
    {
      label: "Navigate to Dynamic Scanner",
      description: "From the Dynamic Analysis Hub, click the 'Dynamic Scanner' tab to access the AI-orchestrated scanning interface.",
      icon: <NetworkCheckIcon />,
      tips: ["Located in the Dynamic Analysis Hub", "Tab-based interface for easy access"],
    },
    {
      label: "Enter Your Target",
      description: "Specify what you want to scan. Can be an IP address, hostname, domain, or full URL. CIDR ranges supported for network scanning.",
      icon: <SearchIcon />,
      tips: ["192.168.1.1 (single IP)", "example.com (domain)", "https://app.example.com (URL)", "192.168.1.0/24 (network)"],
    },
    {
      label: "Choose AI-Led Mode (Recommended)",
      description: "Enable AI-Led scanning and optionally provide context like 'production e-commerce site' or 'internal development server' to guide the AI.",
      icon: <PsychologyIcon />,
      tips: ["AI decides scan strategy automatically", "Provide context for better targeting", "Adaptive based on findings"],
    },
    {
      label: "Configure Advanced Options (Optional)",
      description: "Optionally enable authentication, API specs, browser crawling, OOB testing, or validation. AI-Led mode handles most configurations.",
      icon: <LayersIcon />,
      tips: ["Auth profiles for login-protected apps", "OpenAPI specs for API testing", "Browser crawl for SPAs"],
    },
    {
      label: "Start the Scan",
      description: "Click 'Start Scan' to begin. Monitor real-time progress via WebSocket updates showing current phase and findings count.",
      icon: <RocketLaunchIcon />,
      tips: ["Real-time progress tracking", "Can cancel anytime", "Results saved automatically"],
    },
    {
      label: "Review AI Analysis",
      description: "Once complete, review the comprehensive report with executive summary, vulnerability findings, exploit chains, and prioritized remediation steps.",
      icon: <AnalyticsIcon />,
      tips: ["Executive summary for management", "Technical details for engineers", "Export to PDF/DOCX/Markdown"],
    },
  ];

  const realWorldScenarios = [
    {
      title: "🛡️ Full Enterprise Network Audit",
      description: "Comprehensive security assessment of an entire network segment",
      setup: {
        target: "10.0.0.0/24",
        ai_led: true,
        context: "production enterprise network with web apps and databases",
        include_openvas: true,
        aggressive: true,
      },
      outcome: "Discovers all hosts, identifies vulnerable services, maps exploits, generates network topology",
      icon: <NetworkCheckIcon />,
      color: "#3b82f6",
    },
    {
      title: "🌐 Web Application Penetration Test",
      description: "Deep security testing of a web application with authentication",
      setup: {
        target: "https://app.example.com",
        ai_led: true,
        zap_auth: "form-based with login credentials",
        include_sqlmap: true,
        browser_crawl: true,
      },
      outcome: "Tests authenticated endpoints, finds SQL injection, XSS, auth bypass, generates attack chains",
      icon: <HttpIcon />,
      color: "#f59e0b",
    },
    {
      title: "🔌 API Security Assessment",
      description: "Test a RESTful or GraphQL API with schema validation",
      setup: {
        target: "https://api.example.com",
        openapi_spec: "imported from /swagger.json",
        include_sqlmap: true,
        oob_testing: true,
      },
      outcome: "Tests all documented endpoints, validates input handling, finds injection flaws",
      icon: <ApiIcon />,
      color: "#06b6d4",
    },
    {
      title: "🕵️ Stealth Security Audit",
      description: "Low-detection scanning for sensitive production environments",
      setup: {
        target: "production.example.com",
        ai_led: true,
        context: "production system, use stealth techniques",
        aggressive: false,
        nmap_type: "stealth",
      },
      outcome: "Minimal footprint while identifying critical vulnerabilities, avoids service disruption",
      icon: <ShieldIcon />,
      color: "#8b5cf6",
    },
    {
      title: "🔍 Vulnerability Validation",
      description: "Verify and validate previously identified security issues",
      setup: {
        target: "192.168.1.50",
        validation_pass: true,
        include_cve_scan: true,
        include_exploit_mapping: true,
      },
      outcome: "Confirms exploitability, reduces false positives, provides proof-of-concept evidence",
      icon: <CheckCircleIcon />,
      color: "#22c55e",
    },
    {
      title: "📊 Compliance Scanning",
      description: "Security assessment aligned with compliance requirements",
      setup: {
        target: "https://healthcare-portal.example.com",
        ai_led: true,
        context: "HIPAA-compliant healthcare application",
        include_openvas: true,
        validation_pass: true,
      },
      outcome: "Identifies compliance gaps, vulnerable encryption, access control issues, generates audit report",
      icon: <WarningIcon />,
      color: "#dc2626",
    },
  ];

  const pageContext = `Dynamic Scanner Complete Guide - AI-orchestrated automated pentesting workflow. Covers: integrated tools (Nmap, OWASP ZAP, Nuclei, OpenVAS, SQLMap, Wapiti, Gobuster, ExploitDB), scanning phases (reconnaissance, routing, web scanning, CVE detection, exploit mapping, AI analysis), AI-Led vs Manual modes, authenticated scanning (form/JSON/HTTP/script-based), API testing (OpenAPI/GraphQL), dynamic content handling (headless browser, HAR capture, JS extraction), out-of-band testing (callback payloads), vulnerability validation (false positive filtering), real-world pentesting scenarios, and comprehensive output generation.`;

  return (
    <LearnPageLayout pageTitle="Dynamic Scanner Guide" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Link */}
      <Box sx={{ mb: 3 }}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2 }}
        />
      </Box>

      {/* Hero Header */}
      <Paper
        sx={{
          p: 5,
          mb: 5,
          borderRadius: 4,
          background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.15)} 0%, ${alpha("#6366f1", 0.1)} 50%, ${alpha("#3b82f6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
          position: "relative",
          overflow: "hidden",
        }}
      >
        <Box
          sx={{
            position: "absolute",
            top: -50,
            right: -50,
            width: 200,
            height: 200,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.2)} 0%, transparent 70%)`,
            animation: `${float} 6s ease-in-out infinite`,
          }}
        />
        <Box
          sx={{
            position: "absolute",
            bottom: -30,
            left: "20%",
            width: 150,
            height: 150,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#6366f1", 0.15)} 0%, transparent 70%)`,
            animation: `${float} 5s ease-in-out infinite`,
            animationDelay: "1s",
          }}
        />

        <Box sx={{ position: "relative", zIndex: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#8b5cf6", 0.4)}`,
                animation: `${aiGlow} 3s ease-in-out infinite`,
              }}
            >
              <AutoAwesomeIcon sx={{ fontSize: 44, color: "white" }} />
            </Box>
            <Box>
              <Typography
                variant="h3"
                sx={{
                  fontWeight: 800,
                  background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 50%, #3b82f6 100%)`,
                  backgroundSize: "200% auto",
                  backgroundClip: "text",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  animation: `${shimmer} 4s linear infinite`,
                }}
              >
                Dynamic Scanner
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                AI-Orchestrated Automated Penetration Testing Workflow
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ maxWidth: 700, mb: 3, fontSize: "1.1rem", lineHeight: 1.7 }}>
            The Dynamic Scanner combines the power of 8+ industry-leading security tools with artificial
            intelligence to perform comprehensive penetration testing. From network reconnaissance to
            exploitation research, the AI makes intelligent decisions about scanning strategy, tool selection,
            and attack path construction.
          </Typography>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Button
              variant="contained"
              startIcon={<RocketLaunchIcon />}
              onClick={() => navigate("/dynamic")}
              sx={{
                background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)`,
                px: 3,
                py: 1.5,
                fontWeight: 600,
                boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.4)}`,
                "&:hover": {
                  boxShadow: `0 6px 30px ${alpha("#8b5cf6", 0.5)}`,
                },
              }}
            >
              Open Dynamic Scanner
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Stats Bar */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { label: "8+", subtitle: "Integrated Tools", icon: <LayersIcon />, color: "#3b82f6" },
          { label: "12", subtitle: "Scanning Phases", icon: <PlayArrowIcon />, color: "#8b5cf6" },
          { label: "AI-Powered", subtitle: "Intelligent Routing", icon: <PsychologyIcon />, color: "#f59e0b" },
          { label: "Multi-Stage", subtitle: "Exploit Chains", icon: <CodeIcon />, color: "#ef4444" },
        ].map((stat) => (
          <Grid item xs={6} md={3} key={stat.label}>
            <Paper
              sx={{
                p: 2,
                textAlign: "center",
                borderRadius: 2,
                border: `1px solid ${alpha(stat.color, 0.2)}`,
                background: alpha(stat.color, 0.03),
              }}
            >
              <Box sx={{ color: stat.color, mb: 0.5 }}>{stat.icon}</Box>
              <Typography variant="h5" sx={{ fontWeight: 700, color: stat.color }}>
                {stat.label}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {stat.subtitle}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* What is Dynamic Scanner */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SchoolIcon sx={{ color: "#8b5cf6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            What is the Dynamic Scanner?
          </Typography>
        </Box>
        <Typography variant="body1" paragraph sx={{ fontSize: "1.05rem" }}>
          The <strong>Dynamic Scanner</strong> is an AI-orchestrated automated pentesting workflow that combines
          multiple security tools into a unified scanning pipeline. Unlike traditional scanners that require manual
          configuration and tool switching, the Dynamic Scanner uses artificial intelligence to:
        </Typography>
        <List dense sx={{ mb: 2 }}>
          {[
            "Automatically determine the optimal scanning strategy based on your target",
            "Intelligently route services to appropriate specialized scanners",
            "Perform reconnaissance, vulnerability scanning, and exploitation research",
            "Generate attack narratives showing how vulnerabilities can be chained",
            "Provide executive summaries alongside technical remediation guidance",
          ].map((item) => (
            <ListItem key={item}>
              <ListItemIcon>
                <CheckCircleIcon sx={{ color: "#8b5cf6" }} />
              </ListItemIcon>
              <ListItemText primary={item} />
            </ListItem>
          ))}
        </List>
        <Paper
          sx={{
            p: 2,
            borderRadius: 2,
            bgcolor: alpha("#8b5cf6", 0.05),
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>💡 Key Advantage:</strong> Instead of running Nmap, then ZAP, then Nuclei manually,
            the Dynamic Scanner orchestrates the entire workflow automatically—making intelligent decisions
            about which tools to use, when to use them, and how deep to scan based on what it discovers.
          </Typography>
        </Paper>
      </Paper>

      {/* Integrated Tools */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <LayersIcon sx={{ color: "#3b82f6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Integrated Security Tools
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          The Dynamic Scanner integrates 8+ best-in-class security tools, each specialized for different attack surfaces:
        </Typography>
        <Grid container spacing={2}>
          {integratedTools.map((tool) => (
            <Grid item xs={12} md={6} key={tool.name}>
              <Card
                sx={{
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(tool.color, 0.2)}`,
                  borderLeft: `4px solid ${tool.color}`,
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                    <Box sx={{ color: tool.color }}>{tool.icon}</Box>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: tool.color }}>
                      {tool.name}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    <strong>{tool.purpose}</strong>
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    {tool.description}
                  </Typography>
                  <Chip
                    label={tool.phase}
                    size="small"
                    sx={{
                      bgcolor: alpha(tool.color, 0.1),
                      color: tool.color,
                      fontWeight: 600,
                    }}
                  />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Scanning Phases */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <PlayArrowIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Scanning Phases Pipeline
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Scans progress through sequential phases, each building on the previous discoveries:
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Phase</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scanningPhases.map((phase) => (
                <TableRow key={phase.phase} hover>
                  <TableCell>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Box sx={{ color: phase.color }}>{phase.icon}</Box>
                      <code style={{
                        backgroundColor: alpha(phase.color, 0.1),
                        padding: "4px 10px",
                        borderRadius: 4,
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        color: phase.color,
                      }}>
                        {phase.phase}
                      </code>
                    </Box>
                  </TableCell>
                  <TableCell>{phase.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* AI Features */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}`, background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)} 0%, ${alpha("#6366f1", 0.02)} 100%)` }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <PsychologyIcon sx={{ color: "#8b5cf6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            AI-Powered Intelligence
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Artificial intelligence makes the Dynamic Scanner truly autonomous and adaptive:
        </Typography>
        <Grid container spacing={3}>
          {aiFeatures.map((feature, idx) => (
            <Grid item xs={12} md={6} key={idx}>
              <Card sx={{ height: "100%", borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                <CardContent>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                    {feature.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {feature.description}
                  </Typography>
                  <List dense>
                    {feature.capabilities.map((cap, capIdx) => (
                      <ListItem key={capIdx} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                        </ListItemIcon>
                        <ListItemText primary={cap} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Getting Started */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <RocketLaunchIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Getting Started: Your First Scan
          </Typography>
        </Box>
        <Stepper orientation="vertical">
          {gettingStartedSteps.map((step, index) => (
            <Step key={step.label} active={true}>
              <StepLabel
                StepIconComponent={() => (
                  <Box
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: "50%",
                      bgcolor: alpha("#10b981", 0.1),
                      color: "#10b981",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                      fontSize: "1rem",
                    }}
                  >
                    {index + 1}
                  </Box>
                )}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ color: "#10b981" }}>{step.icon}</Box>
                  {step.label}
                </Typography>
              </StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {step.description}
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {step.tips.map((tip, idx) => (
                    <Chip
                      key={idx}
                      label={tip}
                      size="small"
                      sx={{
                        bgcolor: alpha("#10b981", 0.1),
                        color: "#10b981",
                        fontSize: "0.75rem",
                      }}
                    />
                  ))}
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {/* Advanced Features */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <KeyIcon sx={{ color: "#f59e0b", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Advanced Features
          </Typography>
        </Box>
        <Grid container spacing={3}>
          {advancedFeatures.map((feature) => (
            <Grid item xs={12} md={6} key={feature.title}>
              <Accordion
                sx={{
                  borderRadius: 2,
                  border: `1px solid ${alpha(feature.color, 0.2)}`,
                  "&:before": { display: "none" },
                  overflow: "hidden",
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  sx={{ bgcolor: alpha(feature.color, 0.05) }}
                >
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {feature.title}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {feature.description}
                    </Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {feature.features.map((feat, idx) => (
                      <ListItem key={idx} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: feature.color }} />
                        </ListItemIcon>
                        <ListItemText primary={feat} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Real World Scenarios */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <BugReportIcon sx={{ color: "#6366f1", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Real-World Penetration Testing Scenarios
          </Typography>
        </Box>
        <Grid container spacing={3}>
          {realWorldScenarios.map((scenario) => (
            <Grid item xs={12} md={6} key={scenario.title}>
              <Card
                sx={{
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(scenario.color, 0.2)}`,
                  borderTop: `4px solid ${scenario.color}`,
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ color: scenario.color }}>{scenario.icon}</Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {scenario.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {scenario.description}
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: alpha(scenario.color, 0.05), borderRadius: 2, mb: 2 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 1 }}>
                      Configuration:
                    </Typography>
                    {Object.entries(scenario.setup).map(([key, value]) => (
                      <Typography key={key} variant="caption" display="block" sx={{ fontFamily: "monospace" }}>
                        {key}: {typeof value === 'boolean' ? (value ? 'true' : 'false') : value}
                      </Typography>
                    ))}
                  </Paper>
                  <Typography variant="body2" sx={{ fontWeight: 600, color: scenario.color }}>
                    Outcome: {scenario.outcome}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Output & Reports */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <AnalyticsIcon sx={{ color: "#06b6d4", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Comprehensive Output & Reports
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Every scan generates detailed, multi-layered output designed for different audiences:
        </Typography>
        <Grid container spacing={2}>
          {[
            {
              title: "Executive Summary",
              description: "Management-friendly overview of risk posture, key findings, and business impact",
              color: "#8b5cf6",
            },
            {
              title: "Technical Findings",
              description: "Detailed vulnerability listings with CVE IDs, CVSS scores, evidence, and remediation steps",
              color: "#ef4444",
            },
            {
              title: "Attack Narratives",
              description: "AI-generated stories showing how attackers could exploit discovered vulnerabilities",
              color: "#f59e0b",
            },
            {
              title: "Exploit Chains",
              description: "Multi-stage attack paths combining vulnerabilities for privilege escalation or RCE",
              color: "#dc2626",
            },
            {
              title: "Remediation Roadmap",
              description: "Prioritized action items with effort estimates and criticality ratings",
              color: "#10b981",
            },
            {
              title: "Export Formats",
              description: "JSON for integrations, Markdown for docs, HTML for viewing, PDF/DOCX for reporting",
              color: "#06b6d4",
            },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.title}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  bgcolor: alpha(item.color, 0.03),
                  height: "100%",
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                  {item.title}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {item.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Tips & Best Practices */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)}, ${alpha("#f59e0b", 0.05)})`,
          border: `1px solid ${alpha("#f59e0b", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <TipsAndUpdatesIcon sx={{ color: "#f59e0b", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Pro Tips & Best Practices
          </Typography>
        </Box>
        <Grid container spacing={2}>
          {[
            { tip: "Always start with AI-Led mode—let the AI decide the strategy, you can switch to manual later", icon: <PsychologyIcon /> },
            { tip: "Provide context hints like 'production system' or 'development server' to guide AI decisions", icon: <TipsAndUpdatesIcon /> },
            { tip: "Use authentication profiles for login-protected apps—finds 3-5x more vulnerabilities", icon: <KeyIcon /> },
            { tip: "Enable validation pass for high/critical findings to reduce false positives before reporting", icon: <CheckCircleIcon /> },
            { tip: "Import OpenAPI/GraphQL schemas for comprehensive API testing—covers all endpoints", icon: <ApiIcon /> },
            { tip: "Enable browser crawling for JavaScript-heavy SPAs—discovers dynamic endpoints", icon: <HttpIcon /> },
            { tip: "Use OOB testing for blind vulnerabilities—confirms SSRF, XXE, and blind SQL injection", icon: <BugReportIcon /> },
            { tip: "Always get written authorization before scanning—unauthorized testing is illegal", icon: <WarningIcon /> },
            { tip: "Review AI-generated exploit chains—shows realistic attack paths, not just isolated issues", icon: <CodeIcon /> },
            { tip: "Export to PDF/DOCX for stakeholder reports, JSON for integration with SIEM/ticketing", icon: <AnalyticsIcon /> },
          ].map((item, idx) => (
            <Grid item xs={12} md={6} key={idx}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Box sx={{ color: "#f59e0b", mt: 0.25 }}>{item.icon}</Box>
                <Typography variant="body2">{item.tip}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* CTA Footer */}
      <Paper
        sx={{
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)} 0%, ${alpha("#6366f1", 0.05)} 100%)`,
          border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
        }}
      >
        <AutoAwesomeIcon sx={{ fontSize: 48, color: "#8b5cf6", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Ready to Start AI-Powered Pentesting?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: "auto" }}>
          Launch the Dynamic Scanner and let AI orchestrate a comprehensive security assessment of your
          infrastructure. From reconnaissance to exploit research, it's fully automated.
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<RocketLaunchIcon />}
            onClick={() => navigate("/dynamic")}
            sx={{
              background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)`,
              px: 4,
              py: 1.5,
              fontWeight: 700,
              fontSize: "1rem",
              boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.4)}`,
              "&:hover": {
                boxShadow: `0 6px 30px ${alpha("#8b5cf6", 0.5)}`,
              },
            }}
          >
            Open Dynamic Scanner
          </Button>
          <Button
            variant="outlined"
            size="large"
            component={Link}
            to="/learn"
            sx={{
              borderColor: alpha("#06b6d4", 0.5),
              color: "#22d3ee",
              px: 3,
              py: 1.5,
              "&:hover": {
                borderColor: "#06b6d4",
                bgcolor: alpha("#06b6d4", 0.1),
              },
            }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
