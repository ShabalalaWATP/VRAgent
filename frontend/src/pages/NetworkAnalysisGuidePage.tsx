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
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  keyframes,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import HubIcon from "@mui/icons-material/Hub";
import RadarIcon from "@mui/icons-material/Radar";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import SecurityIcon from "@mui/icons-material/Security";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import StorageIcon from "@mui/icons-material/Storage";
import ChatIcon from "@mui/icons-material/Chat";
import DownloadIcon from "@mui/icons-material/Download";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import AssessmentIcon from "@mui/icons-material/Assessment";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import VisibilityIcon from "@mui/icons-material/Visibility";
import TimelineIcon from "@mui/icons-material/Timeline";
import SpeedIcon from "@mui/icons-material/Speed";
import WarningIcon from "@mui/icons-material/Warning";
import GppGoodIcon from "@mui/icons-material/GppGood";
import LockIcon from "@mui/icons-material/Lock";
import DnsIcon from "@mui/icons-material/Dns";
import RouteIcon from "@mui/icons-material/Route";
import ApiIcon from "@mui/icons-material/Api";
import BoltIcon from "@mui/icons-material/Bolt";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import MemoryIcon from "@mui/icons-material/Memory";

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const pulse = keyframes`
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.05); opacity: 0.9; }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

export default function NetworkAnalysisGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const pageContext = `This page is the Network Analysis Hub learning guide covering:
- API Endpoint Tester: OWASP API Top 10 2023 security testing with 10 test categories
- Nmap Scanner: Port scanning, 30+ high-risk port detection, 9 scan profiles
- PCAP Analyzer: 7 capture profiles, live capture, deep packet inspection
- SSL/TLS Analysis: 12 CVE vulnerability checks, cipher suite analysis
- DNS Intelligence: 9 record types, 150+ subdomain enumeration, email security
- Traceroute: Cross-platform network path analysis with hop visualization
- Security Fuzzer: Web application fuzzing with Smart Detection and 500+ payloads
- Agentic Fuzzer: AI-powered autonomous vulnerability discovery
- Binary Fuzzer: Native code fuzzing with AFL++, Honggfuzz, and libFuzzer
- MITM Workbench: Traffic interception with AI-powered rule creation
- AI-enhanced analysis powered by Google Gemini for all 10 network tools`;

  const features = [
    {
      title: "API Endpoint Tester",
      icon: <ApiIcon sx={{ fontSize: 32 }} />,
      color: "#22c55e",
      gradient: "linear-gradient(135deg, #22c55e 0%, #16a34a 100%)",
      description: "OWASP API Top 10 2023 security testing with 10 test categories and AI-powered network scanning.",
      capabilities: [
        "OWASP API Top 10 2023: BOLA, BFLA, Injection, SSRF, Mass Assignment",
        "AI Auto-Test: CIDR network scanning with automatic service discovery",
        "10 Test Categories: Authentication, Authorization, Injection, SSRF, Rate Limiting",
        "WebSocket & JWT security testing with token analysis",
        "Export results as JSON, Markdown, PDF, or DOCX",
      ],
      link: "/network/api-tester",
    },
    {
      title: "Nmap Scanner & Analyzer",
      icon: <RadarIcon sx={{ fontSize: 32 }} />,
      color: "#8b5cf6",
      gradient: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)",
      description: "Industry-standard port scanning with 30+ high-risk port detection and AI-powered insights.",
      capabilities: [
        "9+ Scan profiles: Basic, Quick, Full, Service, Aggressive, Stealth, UDP, Comprehensive",
        "30+ high-risk ports automatically flagged (SSH, RDP, SMB, databases, etc.)",
        "Upload and analyze existing Nmap XML output files",
        "Target validation for IPs, CIDR ranges, and hostnames",
        "Real-time scan progress with live output streaming",
      ],
      link: "/network/nmap",
    },
    {
      title: "PCAP Analyzer",
      icon: <NetworkCheckIcon sx={{ fontSize: 32 }} />,
      color: "#06b6d4",
      gradient: "linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)",
      description: "Deep packet inspection with 7 capture profiles and live traffic capture support.",
      capabilities: [
        "7 Capture profiles: All Traffic, HTTP, DNS, Auth, Email, Database, Suspicious",
        "Live capture support with tshark integration",
        "Protocol distribution analysis (TCP, UDP, HTTP, DNS, TLS, etc.)",
        "Automatic cleartext credential detection and suspicious pattern ID",
        "Connection mapping and traffic flow visualization",
      ],
      link: "/network/pcap",
    },
    {
      title: "SSL/TLS Scanner",
      icon: <LockIcon sx={{ fontSize: 32 }} />,
      color: "#10b981",
      gradient: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
      description: "12 CVE vulnerability checks and comprehensive cipher suite analysis.",
      capabilities: [
        "12 Known vulnerabilities: POODLE, BEAST, CRIME, BREACH, Heartbleed, FREAK",
        "LOGJAM, DROWN, ROBOT, LUCKY13, SWEET32, ROCA detection",
        "Weak cipher identification (RC4, DES, 3DES, NULL, EXPORT, MD5)",
        "Certificate chain validation and expiry checking",
        "Perfect Forward Secrecy (PFS) verification",
      ],
      link: "/network/ssl",
    },
    {
      title: "DNS Reconnaissance",
      icon: <DnsIcon sx={{ fontSize: 32 }} />,
      color: "#f59e0b",
      gradient: "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)",
      description: "DNS enumeration with 9 record types, 150+ subdomain wordlist, and email security analysis.",
      capabilities: [
        "9 DNS record types: A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA",
        "150+ common subdomains + extended 250+ subdomain enumeration",
        "Zone transfer vulnerability testing (AXFR)",
        "Email security scoring: SPF, DMARC, DKIM, DNSSEC analysis",
        "WHOIS lookup integration for domains and IPs",
      ],
      link: "/network/dns",
    },
    {
      title: "Traceroute Visualization",
      icon: <RouteIcon sx={{ fontSize: 32 }} />,
      color: "#ec4899",
      gradient: "linear-gradient(135deg, #ec4899 0%, #db2777 100%)",
      description: "Network path analysis with hop-by-hop latency and packet loss visualization.",
      capabilities: [
        "Cross-platform: Windows tracert, Linux/macOS traceroute, MTR fallback",
        "Configurable: max hops (1-64), timeout, queries per hop (1-10)",
        "ICMP and UDP probe support with hostname resolution",
        "ASN and geographic location enrichment (when available)",
        "Interactive path visualization with AI bottleneck analysis",
      ],
      link: "/network/traceroute",
    },
    {
      title: "Security Fuzzer",
      icon: <BoltIcon sx={{ fontSize: 32 }} />,
      color: "#f97316",
      gradient: "linear-gradient(135deg, #f97316 0%, #ea580c 100%)",
      description: "Web application fuzzing with Smart Detection, 500+ payloads, and session management.",
      capabilities: [
        "Smart Detection: 50+ signatures for SQLi, XSS, RCE, SSTI, XXE, LFI",
        "Payload modes: Quick SQLi, Quick XSS, Comprehensive, AI-Generated, Custom",
        "Session management: Save, restore, and export fuzzing sessions",
        "Real-time results with status codes, response sizes, and timing",
        "Full request/response logging with vulnerability classification",
      ],
      link: "/network/fuzzer",
    },
    {
      title: "Agentic Fuzzer",
      icon: <SmartToyIcon sx={{ fontSize: 32 }} />,
      color: "#8b5cf6",
      gradient: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)",
      description: "AI-powered autonomous vulnerability discovery with endpoint discovery and adaptive attacks.",
      capabilities: [
        "Endpoint Discovery: Intelligent crawling and hidden path enumeration",
        "Tech Fingerprinting: Server, framework, and WAF detection",
        "Adaptive Attacks: Response-based strategy adjustment and bypass generation",
        "5-Phase pipeline: Recon → Fingerprint → Discover → Validate → Report",
        "AI-generated findings with remediation advice",
      ],
      link: "/network/agentic-fuzzer",
    },
    {
      title: "Binary Fuzzer",
      icon: <MemoryIcon sx={{ fontSize: 32 }} />,
      color: "#10b981",
      gradient: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
      description: "Native code vulnerability discovery with coverage-guided fuzzing and crash analysis.",
      capabilities: [
        "Fuzzing engines: AFL++, Honggfuzz, libFuzzer",
        "Detects: Buffer overflow, UAF, integer overflow, format string, double-free",
        "Automatic crash triage and deduplication",
        "Stack trace analysis with exploitability assessment",
        "PoC generation with minimal reproducer inputs",
      ],
      link: "/network/binary-fuzzer",
    },
    {
      title: "MITM Workbench",
      icon: <SwapHorizIcon sx={{ fontSize: 32 }} />,
      color: "#a855f7",
      gradient: "linear-gradient(135deg, #a855f7 0%, #9333ea 100%)",
      description: "Intercept, inspect, and modify network traffic between application components.",
      capabilities: [
        "3 Interception modes: Passthrough, Intercept, Auto-Modify",
        "HTTP, HTTPS, TCP, and WebSocket protocol support",
        "Custom interception rules with regex matching",
        "Request/response modification and replay capabilities",
        "Traffic tagging, filtering, and session notes",
      ],
      link: "/network/mitm",
    },
    {
      title: "AI Security Analysis",
      icon: <SmartToyIcon sx={{ fontSize: 32 }} />,
      color: "#3b82f6",
      gradient: "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)",
      description: "Google Gemini AI transforms raw network data into actionable intelligence.",
      capabilities: [
        "Executive summary with key findings and risk overview",
        "Risk scoring (0-100) with Critical/High/Medium/Low classification",
        "Attack surface assessment and exposure analysis",
        "Vulnerable service identification with CVE references",
        "Prioritized remediation recommendations",
      ],
      link: null,
    },
    {
      title: "Interactive AI Chat",
      icon: <ChatIcon sx={{ fontSize: 32 }} />,
      color: "#14b8a6",
      gradient: "linear-gradient(135deg, #14b8a6 0%, #0d9488 100%)",
      description: "Conversational AI assistant for deep-dive analysis of your network findings.",
      capabilities: [
        "Context-aware follow-up questions about specific findings",
        "Environment-specific remediation guidance",
        "Attack scenario exploration and impact assessment",
        "Deeper analysis on specific hosts, ports, or services",
        "Full conversation history maintained per report",
      ],
      link: null,
    },
    {
      title: "Report Management",
      icon: <StorageIcon sx={{ fontSize: 32 }} />,
      color: "#6366f1",
      gradient: "linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)",
      description: "Centralized storage for all network analysis reports with filtering and search.",
      capabilities: [
        "Automatic save of all scan results to PostgreSQL database",
        "Filter by type: Nmap, PCAP, SSL, DNS, Traceroute, Fuzzer, MITM",
        "Track security posture changes over time",
        "Quick view, delete, and re-analyze capabilities",
        "Project-based organization and tagging",
      ],
      link: "/network",
    },
    {
      title: "Professional Exports",
      icon: <DownloadIcon sx={{ fontSize: 32 }} />,
      color: "#ef4444",
      gradient: "linear-gradient(135deg, #ef4444 0%, #dc2626 100%)",
      description: "Generate professional reports for stakeholders and compliance documentation.",
      capabilities: [
        "Markdown (.md) for technical documentation and wikis",
        "PDF for formal reporting and executive presentations",
        "Word (.docx) for editing and customization",
        "JSON for programmatic integration and automation",
      ],
      link: null,
    },
  ];

  const workflowSteps = [
    {
      label: "Choose Your Analysis Type",
      description: "Select from 10 specialized tools: Nmap for port scanning, PCAP for traffic analysis, SSL/TLS for certificates, DNS for domain reconnaissance, Traceroute for path analysis, API Tester for endpoint security, Security Fuzzer, Agentic Fuzzer, Binary Fuzzer for vulnerability discovery, or MITM for traffic interception.",
      icon: <HubIcon />,
    },
    {
      label: "Provide Input Data",
      description: "Enter targets (IPs, domains, CIDR ranges) or upload existing files (Nmap XML, PCAP). Each tool has quick-start options and pre-configured targets for testing.",
      icon: <CloudUploadIcon />,
    },
    {
      label: "Configure & Execute",
      description: "Choose scan profiles, attack modes, or interception rules. Watch real-time progress as your data is processed with live output streaming.",
      icon: <PlayArrowIcon />,
    },
    {
      label: "AI Analysis",
      description: "Google Gemini AI automatically analyzes results, generating comprehensive security reports with risk scores, CVE references, and severity classifications.",
      icon: <SmartToyIcon />,
    },
    {
      label: "Review & Investigate",
      description: "Explore structured reports with executive summaries, detailed findings, and recommendations. Use the AI chat panel to dig deeper into specific security issues.",
      icon: <AssessmentIcon />,
    },
    {
      label: "Export & Share",
      description: "Download professional reports in Markdown, PDF, DOCX, or JSON format. All reports are automatically saved to the database for future reference and tracking.",
      icon: <DownloadIcon />,
    },
  ];

  const useCases = [
    {
      title: "Penetration Testing",
      icon: <BugReportIcon />,
      color: "#ef4444",
      description: "Use Nmap to discover attack surface and PCAP to analyze test traffic",
    },
    {
      title: "Security Audits",
      icon: <ShieldIcon />,
      color: "#8b5cf6",
      description: "Document network exposure with AI-generated compliance-ready reports",
    },
    {
      title: "Incident Response",
      icon: <WarningIcon />,
      color: "#f59e0b",
      description: "Analyze captured traffic to understand breach scope and attacker behavior",
    },
    {
      title: "Network Monitoring",
      icon: <VisibilityIcon />,
      color: "#06b6d4",
      description: "Regular scans to track changes in your network's security posture",
    },
  ];

  return (
    <LearnPageLayout pageTitle="Network Analysis Hub" pageContext={pageContext}>
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
          background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.15)} 0%, ${alpha("#6366f1", 0.1)} 50%, ${alpha("#8b5cf6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#0ea5e9", 0.3)}`,
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Floating background elements */}
        <Box
          sx={{
            position: "absolute",
            top: -50,
            right: -50,
            width: 200,
            height: 200,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#0ea5e9", 0.2)} 0%, transparent 70%)`,
            animation: `${float} 6s ease-in-out infinite`,
          }}
        />
        <Box
          sx={{
            position: "absolute",
            bottom: -30,
            left: "30%",
            width: 150,
            height: 150,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.15)} 0%, transparent 70%)`,
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
                background: `linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#0ea5e9", 0.4)}`,
                animation: `${float} 4s ease-in-out infinite`,
              }}
            >
              <HubIcon sx={{ fontSize: 44, color: "white" }} />
            </Box>
            <Box>
              <Typography
                variant="h3"
                sx={{
                  fontWeight: 800,
                  background: `linear-gradient(135deg, #0ea5e9 0%, #6366f1 50%, #8b5cf6 100%)`,
                  backgroundSize: "200% auto",
                  backgroundClip: "text",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  animation: `${shimmer} 4s linear infinite`,
                }}
              >
                Network Analysis Hub
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                AI-Powered Network Security Analysis
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ maxWidth: 700, mb: 3, fontSize: "1.1rem", lineHeight: 1.7 }}>
            The Network Analysis Hub combines industry-standard tools like <strong>Nmap</strong> and{" "}
            <strong>Wireshark</strong> with Google <strong>Gemini AI</strong> to deliver comprehensive 
            security insights. Scan networks, analyze traffic, and get actionable intelligence—all in one place.
          </Typography>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Button
              variant="contained"
              startIcon={<RocketLaunchIcon />}
              onClick={() => navigate("/network")}
              sx={{
                background: `linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)`,
                px: 3,
                py: 1.5,
                fontWeight: 600,
                boxShadow: `0 4px 20px ${alpha("#0ea5e9", 0.4)}`,
                "&:hover": {
                  boxShadow: `0 6px 30px ${alpha("#0ea5e9", 0.5)}`,
                },
              }}
            >
              Launch Network Hub
            </Button>
            <Button
              variant="outlined"
              startIcon={<RadarIcon />}
              component={Link}
              to="/learn/nmap"
              sx={{
                borderColor: alpha("#8b5cf6", 0.5),
                color: "#a78bfa",
                "&:hover": {
                  borderColor: "#8b5cf6",
                  bgcolor: alpha("#8b5cf6", 0.1),
                },
              }}
            >
              Learn Nmap
            </Button>
            <Button
              variant="outlined"
              startIcon={<NetworkCheckIcon />}
              component={Link}
              to="/learn/wireshark"
              sx={{
                borderColor: alpha("#06b6d4", 0.5),
                color: "#22d3ee",
                "&:hover": {
                  borderColor: "#06b6d4",
                  bgcolor: alpha("#06b6d4", 0.1),
                },
              }}
            >
              Learn Wireshark
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Key Stats */}
      <Grid container spacing={3} sx={{ mb: 5 }}>
        {[
          { value: "10", label: "Analysis Tools", icon: <HubIcon />, color: "#0ea5e9" },
          { value: "10", label: "API Test Categories", icon: <ApiIcon />, color: "#22c55e" },
          { value: "AI", label: "Powered Analysis", icon: <SmartToyIcon />, color: "#10b981" },
          { value: "4", label: "Export Formats", icon: <DownloadIcon />, color: "#f59e0b" },
        ].map((stat, idx) => (
          <Grid item xs={6} md={3} key={idx}>
            <Paper
              sx={{
                p: 3,
                textAlign: "center",
                borderRadius: 3,
                border: `1px solid ${alpha(stat.color, 0.2)}`,
                background: `linear-gradient(135deg, ${alpha(stat.color, 0.05)} 0%, transparent 100%)`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 8px 30px ${alpha(stat.color, 0.2)}`,
                },
              }}
            >
              <Box sx={{ color: stat.color, mb: 1 }}>{stat.icon}</Box>
              <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                {stat.value}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {stat.label}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Use Cases */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
          <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
          Use Cases
        </Typography>
        <Grid container spacing={2}>
          {useCases.map((useCase, idx) => (
            <Grid item xs={12} sm={6} md={3} key={idx}>
              <Paper
                sx={{
                  p: 2.5,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(useCase.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    borderColor: useCase.color,
                    bgcolor: alpha(useCase.color, 0.05),
                  },
                }}
              >
                <Box sx={{ color: useCase.color, mb: 1.5 }}>{useCase.icon}</Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>
                  {useCase.title}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {useCase.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Features Grid */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
        <SpeedIcon sx={{ color: "#6366f1" }} />
        Capabilities
      </Typography>
      <Grid container spacing={3} sx={{ mb: 5 }}>
        {features.map((feature) => (
          <Grid item xs={12} md={6} key={feature.title}>
            <Card
              sx={{
                height: "100%",
                borderRadius: 3,
                border: `1px solid ${alpha(feature.color, 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  borderColor: feature.color,
                  boxShadow: `0 8px 30px ${alpha(feature.color, 0.2)}`,
                },
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 56,
                      height: 56,
                      borderRadius: 2,
                      background: feature.gradient,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "white",
                      boxShadow: `0 4px 15px ${alpha(feature.color, 0.4)}`,
                    }}
                  >
                    {feature.icon}
                  </Box>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>
                      {feature.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {feature.description}
                    </Typography>
                  </Box>
                </Box>
                <Divider sx={{ my: 2 }} />
                <List dense disablePadding>
                  {feature.capabilities.map((cap, idx) => (
                    <ListItem key={idx} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 18, color: feature.color }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={cap}
                        primaryTypographyProps={{ variant: "body2" }}
                      />
                    </ListItem>
                  ))}
                </List>
                {feature.link && (
                  <Button
                    component={Link}
                    to={feature.link}
                    size="small"
                    sx={{
                      mt: 2,
                      color: feature.color,
                      "&:hover": {
                        bgcolor: alpha(feature.color, 0.1),
                      },
                    }}
                  >
                    Go to {feature.title} →
                  </Button>
                )}
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Workflow Stepper */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
          <TimelineIcon sx={{ color: "#10b981" }} />
          How It Works
        </Typography>
        <Stepper orientation="vertical">
          {workflowSteps.map((step, index) => (
            <Step key={step.label} active={true}>
              <StepLabel
                StepIconComponent={() => (
                  <Box
                    sx={{
                      width: 36,
                      height: 36,
                      borderRadius: "50%",
                      bgcolor: alpha("#10b981", 0.1),
                      color: "#10b981",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
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
                <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                  {step.description}
                </Typography>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {/* CTA Footer */}
      <Paper
        sx={{
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)} 0%, ${alpha("#0ea5e9", 0.05)} 100%)`,
          border: `1px solid ${alpha("#10b981", 0.2)}`,
        }}
      >
        <GppGoodIcon sx={{ fontSize: 48, color: "#10b981", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Ready to Analyze Your Network?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Start discovering vulnerabilities and security issues in your network infrastructure with AI-powered analysis.
        </Typography>
        <Button
          variant="contained"
          size="large"
          startIcon={<RocketLaunchIcon />}
          onClick={() => navigate("/network")}
          sx={{
            background: `linear-gradient(135deg, #10b981 0%, #0ea5e9 100%)`,
            px: 4,
            py: 1.5,
            fontWeight: 700,
            fontSize: "1rem",
            boxShadow: `0 4px 20px ${alpha("#10b981", 0.4)}`,
            "&:hover": {
              boxShadow: `0 6px 30px ${alpha("#10b981", 0.5)}`,
            },
          }}
        >
          Launch Network Analysis Hub
        </Button>
      </Paper>

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
