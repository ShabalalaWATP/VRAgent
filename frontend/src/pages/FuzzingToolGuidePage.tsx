import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  IconButton,
  Grid,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Button,
} from "@mui/material";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import BugReportIcon from "@mui/icons-material/BugReport";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SettingsIcon from "@mui/icons-material/Settings";
import PsychologyIcon from "@mui/icons-material/Psychology";
import HistoryIcon from "@mui/icons-material/History";
import SaveIcon from "@mui/icons-material/Save";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import HttpIcon from "@mui/icons-material/Http";
import SpeedIcon from "@mui/icons-material/Speed";
import BarChartIcon from "@mui/icons-material/BarChart";
import StorageIcon from "@mui/icons-material/Storage";
import TimelineIcon from "@mui/icons-material/Timeline";
import VisibilityIcon from "@mui/icons-material/Visibility";
import LearnPageLayout from "../components/LearnPageLayout";
import CodeIcon from "@mui/icons-material/Code";
import LinkIcon from "@mui/icons-material/Link";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import LocalOfferIcon from "@mui/icons-material/LocalOffer";
import DownloadIcon from "@mui/icons-material/Download";
import RestoreIcon from "@mui/icons-material/Restore";
import FilterAltIcon from "@mui/icons-material/FilterAlt";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import MemoryIcon from "@mui/icons-material/Memory";
import RadarIcon from "@mui/icons-material/Radar";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import TerminalIcon from "@mui/icons-material/Terminal";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import PauseIcon from "@mui/icons-material/Pause";
import StopIcon from "@mui/icons-material/Stop";
import ShieldIcon from "@mui/icons-material/Shield";
import TrackChangesIcon from "@mui/icons-material/TrackChanges";
import TuneIcon from "@mui/icons-material/Tune";
import SyncIcon from "@mui/icons-material/Sync";
import ExtensionIcon from "@mui/icons-material/Extension";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import ScienceIcon from "@mui/icons-material/Science";
import ScheduleIcon from "@mui/icons-material/Schedule";
import TimerIcon from "@mui/icons-material/Timer";
import TransformIcon from "@mui/icons-material/Transform";
import FilterListIcon from "@mui/icons-material/FilterList";
import FolderIcon from "@mui/icons-material/Folder";
import MergeIcon from "@mui/icons-material/Merge";
import GroupIcon from "@mui/icons-material/Group";
import AssessmentIcon from "@mui/icons-material/Assessment";

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

// Feature Card Component
interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  color: string;
  tips?: string[];
}

function FeatureCard({ icon, title, description, color, tips }: FeatureCardProps) {
  const theme = useTheme();
  return (
    <Card
      sx={{
        height: "100%",
        borderRadius: 3,
        border: `1px solid ${alpha(color, 0.2)}`,
        transition: "all 0.3s ease",
        "&:hover": {
          transform: "translateY(-4px)",
          boxShadow: `0 8px 30px ${alpha(color, 0.2)}`,
          borderColor: color,
        },
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Box
          sx={{
            width: 56,
            height: 56,
            borderRadius: 2,
            bgcolor: alpha(color, 0.1),
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            mb: 2,
            color: color,
          }}
        >
          {icon}
        </Box>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
          {title}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.6 }}>
          {description}
        </Typography>
        {tips && tips.length > 0 && (
          <Box sx={{ mt: 2 }}>
            {tips.map((tip, i) => (
              <Chip
                key={i}
                label={tip}
                size="small"
                sx={{ mr: 0.5, mb: 0.5, fontSize: "0.7rem", bgcolor: alpha(color, 0.1), color: color }}
              />
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

// Tab Data
const tabConfig = [
  { name: "Security Fuzzer", icon: <SecurityIcon /> },
  { name: "Agentic Fuzzer", icon: <SmartToyIcon /> },
  { name: "Binary Fuzzer", icon: <MemoryIcon /> },
  { name: "Smart Detection", icon: <PsychologyIcon /> },
  { name: "Sessions", icon: <HistoryIcon /> },
  { name: "Pro Tips", icon: <TipsAndUpdatesIcon /> },
];

// Smart Detection signatures
const smartDetectionSignatures = [
  { category: "SQL Injection", count: 10, severity: "Critical", examples: ["error in your SQL syntax", "ORA-01756", "SQLSTATE"] },
  { category: "XSS", count: 8, severity: "High", examples: ["<script>", "onerror=", "javascript:"] },
  { category: "Command Injection", count: 6, severity: "Critical", examples: ["root:x:0:0:", "uid=", "volume serial number"] },
  { category: "Path Traversal", count: 5, severity: "High", examples: ["root:x:", "\\[boot loader\\]", "/etc/passwd"] },
  { category: "SSTI", count: 7, severity: "High", examples: ["49", "7777777", "{{config}}"] },
  { category: "XXE", count: 4, severity: "High", examples: ["SYSTEM", "<!ENTITY", "file://"] },
  { category: "LDAP Injection", count: 3, severity: "Medium", examples: ["cn=", "objectClass=", "dn:"] },
  { category: "Info Disclosure", count: 7, severity: "Medium", examples: ["stack trace", "debug mode", "internal error"] },
];

export default function FuzzingToolGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page is the VRAgent Fuzzing Tool Guide covering all three fuzzing tools: Security Fuzzer for web application testing with smart detection, Agentic Fuzzer for AI-powered autonomous vulnerability discovery with 4 AutoPilot modes (DISABLED, ASSISTED, SEMI_AUTO, FULL_AUTO), 16+ scan profiles (Quick, Standard, Full, OWASP Top 10, API, Auth, Stealth, Aggressive, Compliance), 80+ attack techniques across 10 categories, intelligent coverage tracking, WAF detection and evasion (Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva, F5), 5 scan depth levels (Minimal 25, Light 50, Standard 150, Thorough 500, Exhaustive 1500 iterations), stealth mode with IP renewal and timing controls, real-time SSE progress tracking with ETA estimation and phase timeline, auto-save reports with MD/PDF/DOCX export, and Binary Fuzzer for memory corruption and native code vulnerability detection with AFL++, Honggfuzz, and libFuzzer. Covers offensive wordlist categories (SQLi, XSS, SSTI, NoSQLi, SSRF, XXE), integrated services (JWT attacks, HTTP smuggling, race conditions, CORS analysis), scan control features, authentication support, and advanced fuzzing techniques.`;

  return (
    <LearnPageLayout pageTitle="Fuzzing Tools Guide" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
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
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <Box
            sx={{
              width: 80,
              height: 80,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${alpha("#f97316", 0.2)}, ${alpha("#ef4444", 0.2)})`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: `0 8px 32px ${alpha("#f97316", 0.3)}`,
            }}
          >
            <BugReportIcon sx={{ fontSize: 40, color: "#f97316" }} />
          </Box>
          <Box>
            <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
              VRAgent Fuzzing Tools Guide
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Master Security Fuzzer, Agentic Fuzzer & Binary Fuzzer for comprehensive vulnerability discovery
            </Typography>
          </Box>
        </Box>

        {/* Three Fuzzer Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={4}>
            <Paper
              sx={{
                p: 2,
                borderRadius: 3,
                border: `2px solid ${alpha("#f97316", 0.3)}`,
                bgcolor: alpha("#f97316", 0.05),
                cursor: "pointer",
                transition: "all 0.3s",
                "&:hover": { borderColor: "#f97316", transform: "translateY(-2px)" },
              }}
              onClick={() => navigate("/network/fuzzer")}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                <SecurityIcon sx={{ color: "#f97316", fontSize: 28 }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316" }}>
                  Security Fuzzer
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Web application fuzzing with Smart Detection, 500+ payloads, SQLi/XSS/RCE detection
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper
              sx={{
                p: 2,
                borderRadius: 3,
                border: `2px solid ${alpha("#8b5cf6", 0.3)}`,
                bgcolor: alpha("#8b5cf6", 0.05),
                cursor: "pointer",
                transition: "all 0.3s",
                "&:hover": { borderColor: "#8b5cf6", transform: "translateY(-2px)" },
              }}
              onClick={() => navigate("/network/agentic-fuzzer")}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                <SmartToyIcon sx={{ color: "#8b5cf6", fontSize: 28 }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                  Agentic Fuzzer
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                AI-powered autonomous fuzzing with endpoint discovery, tech fingerprinting & adaptive attacks
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper
              sx={{
                p: 2,
                borderRadius: 3,
                border: `2px solid ${alpha("#10b981", 0.3)}`,
                bgcolor: alpha("#10b981", 0.05),
                cursor: "pointer",
                transition: "all 0.3s",
                "&:hover": { borderColor: "#10b981", transform: "translateY(-2px)" },
              }}
              onClick={() => navigate("/network/binary-fuzzer")}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                <MemoryIcon sx={{ color: "#10b981", fontSize: 28 }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981" }}>
                  Binary Fuzzer
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Native binary fuzzing with AFL++/Honggfuzz, crash analysis & memory corruption detection
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* Quick Stats */}
        <Paper
          sx={{
            p: 2,
            borderRadius: 3,
            display: "flex",
            flexWrap: "wrap",
            gap: 3,
            justifyContent: "center",
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          {[
            { value: "3", label: "Fuzzing Tools" },
            { value: "80+", label: "Attack Techniques" },
            { value: "4", label: "AutoPilot Modes" },
            { value: "16", label: "Scan Profiles" },
            { value: "12+", label: "Wordlist Categories" },
            { value: "8+", label: "WAF Detections" },
          ].map((stat, i) => (
            <Box key={i} sx={{ textAlign: "center", minWidth: 80 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#f97316" }}>
                {stat.value}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {stat.label}
              </Typography>
            </Box>
          ))}
        </Paper>
      </Box>

      {/* Navigation Tabs */}
      <Paper sx={{ borderRadius: 3, overflow: "hidden", mb: 4 }}>
        <Tabs
          value={tabValue}
          onChange={(_, v) => setTabValue(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none", minHeight: 56 },
          }}
        >
          <Tab label="🔐 Security Fuzzer" />
          <Tab label="🤖 Agentic Fuzzer" />
          <Tab label="💾 Binary Fuzzer" />
          <Tab label="🧠 Smart Detection" />
          <Tab label="📁 Sessions" />
          <Tab label="💡 Pro Tips" />
        </Tabs>
      </Paper>

      {/* Tab 0: Security Fuzzer */}
      <TabPanel value={tabValue} index={0}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1.5 }}>
          <SecurityIcon sx={{ color: "#f97316" }} />
          Security Fuzzer - Web Application Testing
        </Typography>

        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
            border: `1px solid ${alpha("#f97316", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <RocketLaunchIcon sx={{ color: "#f97316" }} />
            What is Security Fuzzer?
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            The Security Fuzzer is a powerful web application testing tool that automatically sends malicious payloads 
            to your target endpoints to discover vulnerabilities. It features <strong>Smart Detection</strong> for automatic 
            vulnerability classification, <strong>500+ built-in payloads</strong>, and <strong>Session Management</strong> 
            to save and restore your testing sessions.
          </Typography>
        </Paper>

        {/* Key Features */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Key Features
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {tabConfig.map((tab, i) => (
            <Grid item xs={6} sm={4} md={3} key={i}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  textAlign: "center",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  transition: "all 0.2s",
                  "&:hover": {
                    borderColor: "#f97316",
                    bgcolor: alpha("#f97316", 0.05),
                  },
                }}
              >
                <Box sx={{ color: "#f97316", mb: 1 }}>{tab.icon}</Box>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {tab.name}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Payload Modes */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Payload Modes
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "Quick - SQLi", desc: "100+ SQL injection payloads", color: "#ef4444" },
            { name: "Quick - XSS", desc: "100+ XSS payloads", color: "#f59e0b" },
            { name: "Comprehensive", desc: "500+ all attack types", color: "#8b5cf6" },
            { name: "Custom Wordlist", desc: "Upload your own", color: "#10b981" },
            { name: "AI-Generated", desc: "Context-aware payloads", color: "#06b6d4" },
            { name: "Number Range", desc: "IDOR testing", color: "#ec4899" },
          ].map((mode, i) => (
            <Grid item xs={6} sm={4} md={2} key={i}>
              <Paper sx={{ p: 1.5, borderRadius: 2, border: `1px solid ${alpha(mode.color, 0.3)}`, bgcolor: alpha(mode.color, 0.05), textAlign: "center" }}>
                <Typography variant="body2" sx={{ fontWeight: 700, color: mode.color }}>{mode.name}</Typography>
                <Typography variant="caption" color="text.secondary">{mode.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Attack Categories - EXPANDED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Attack Categories
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { cat: "SQL Injection", payloads: "100+", severity: "Critical", techniques: ["Union-based", "Boolean blind", "Time blind", "Error-based", "Stacked queries"] },
            { cat: "Cross-Site Scripting", payloads: "100+", severity: "High", techniques: ["Reflected XSS", "DOM-based", "Polyglot", "Event handlers", "SVG/IMG injection"] },
            { cat: "Command Injection", payloads: "50+", severity: "Critical", techniques: ["Shell metachar", "Backticks", "Pipeline", "Newline injection", "OS detection"] },
            { cat: "Path Traversal", payloads: "75+", severity: "High", techniques: ["Directory climb", "Null byte", "URL encoding", "Double encoding", "UTF-8 bypass"] },
            { cat: "SSTI", payloads: "50+", severity: "Critical", techniques: ["Jinja2", "Twig", "Freemarker", "Velocity", "Thymeleaf", "Pebble"] },
            { cat: "Header Injection", payloads: "40+", severity: "Medium", techniques: ["CRLF", "Host header", "X-Forwarded-For", "Referer spoofing"] },
          ].map((cat, i) => (
            <Grid item xs={12} sm={6} md={4} key={i}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(cat.severity === "Critical" ? "#ef4444" : cat.severity === "High" ? "#f97316" : "#f59e0b", 0.3)}`, bgcolor: alpha(cat.severity === "Critical" ? "#ef4444" : cat.severity === "High" ? "#f97316" : "#f59e0b", 0.05) }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{cat.cat}</Typography>
                  <Chip label={cat.severity} size="small" sx={{ bgcolor: alpha(cat.severity === "Critical" ? "#ef4444" : cat.severity === "High" ? "#f97316" : "#f59e0b", 0.1), color: cat.severity === "Critical" ? "#ef4444" : cat.severity === "High" ? "#f97316" : "#f59e0b", fontWeight: 600, fontSize: "0.7rem" }} />
                </Box>
                <Typography variant="caption" color="text.secondary">{cat.payloads} payloads</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
                  {cat.techniques.map((t, j) => (
                    <Chip key={j} label={t} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Request Configuration - NEW */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Request Configuration
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "HTTP Methods", options: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], icon: <HttpIcon /> },
            { name: "Body Formats", options: ["Form Data", "JSON", "XML", "Raw Text", "Multipart"], icon: <CodeIcon /> },
            { name: "Rate Limiting", options: ["1-1000 req/s", "Custom delay", "Burst control", "Adaptive throttle"], icon: <SpeedIcon /> },
            { name: "Encoding Options", options: ["URL encode", "Double encode", "Unicode", "Base64", "HTML entities"], icon: <TransformIcon /> },
          ].map((cfg, i) => (
            <Grid item xs={12} sm={6} md={3} key={i}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box sx={{ color: "#f97316" }}>{cfg.icon}</Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{cfg.name}</Typography>
                </Box>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {cfg.options.map((opt, j) => (
                    <Chip key={j} label={opt} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Response Analysis - NEW */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Response Analysis & Filtering
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <FilterListIcon sx={{ color: "#f97316" }} /> Filter Options
              </Typography>
              <List dense>
                <ListItem><ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Status Code Filtering" secondary="Filter by 2xx, 3xx, 4xx, 5xx responses" /></ListItem>
                <ListItem><ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Response Size Filtering" secondary="Hide/show based on content length" /></ListItem>
                <ListItem><ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Response Time Analysis" secondary="Identify time-based injection points" /></ListItem>
                <ListItem><ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Regex Pattern Matching" secondary="Custom patterns for vulnerability indicators" /></ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <VisibilityIcon sx={{ color: "#f97316" }} /> Smart Detection
              </Typography>
              <List dense>
                <ListItem><ListItemIcon><AutoAwesomeIcon sx={{ color: "#8b5cf6", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Auto-Classification" secondary="Automatic vulnerability type detection" /></ListItem>
                <ListItem><ListItemIcon><AutoAwesomeIcon sx={{ color: "#8b5cf6", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Risk Score Calculation" secondary="0-100 severity score per finding" /></ListItem>
                <ListItem><ListItemIcon><AutoAwesomeIcon sx={{ color: "#8b5cf6", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Evidence Extraction" secondary="Highlight vulnerable response patterns" /></ListItem>
                <ListItem><ListItemIcon><AutoAwesomeIcon sx={{ color: "#8b5cf6", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="False Positive Reduction" secondary="Context-aware result validation" /></ListItem>
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* Quick Start */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Quick Start Guide
        </Typography>
        <Stepper orientation="vertical" sx={{ mb: 4 }}>
          <Step active><StepLabel><Typography sx={{ fontWeight: 600 }}>Configure Target URL</Typography></StepLabel>
            <StepContent><Typography variant="body2" color="text.secondary">Enter URL with <code>FUZZ</code> placeholder: <code>https://target.com/search?q=FUZZ</code></Typography></StepContent></Step>
          <Step active><StepLabel><Typography sx={{ fontWeight: 600 }}>Select Payload Mode</Typography></StepLabel>
            <StepContent><Typography variant="body2" color="text.secondary">Choose Quick SQLi/XSS, Comprehensive, Custom, or AI-Generated payloads</Typography></StepContent></Step>
          <Step active><StepLabel><Typography sx={{ fontWeight: 600 }}>Configure Request Options</Typography></StepLabel>
            <StepContent><Typography variant="body2" color="text.secondary">Set HTTP method, headers, authentication, rate limiting</Typography></StepContent></Step>
          <Step active><StepLabel><Typography sx={{ fontWeight: 600 }}>Start Fuzzing</Typography></StepLabel>
            <StepContent><Typography variant="body2" color="text.secondary">Click Start and monitor real-time results and Smart Detection</Typography></StepContent></Step>
        </Stepper>

        {/* Session Management - NEW */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Session Management
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#10b981", 0.2)}`, bgcolor: alpha("#10b981", 0.03) }}>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Security Fuzzer supports <strong>full session persistence</strong> allowing you to save and restore your fuzzing sessions:
          </Typography>
          <Grid container spacing={2}>
            {[
              { icon: <SaveIcon />, title: "Save Sessions", desc: "Persist fuzzing configuration, results, and progress" },
              { icon: <RestoreIcon />, title: "Restore Sessions", desc: "Continue interrupted scans from where you left off" },
              { icon: <StorageIcon />, title: "Export Results", desc: "Export findings to JSON, CSV, or PDF reports" },
              { icon: <HistoryIcon />, title: "Session History", desc: "Browse and compare previous fuzzing runs" },
            ].map((item, i) => (
              <Grid item xs={12} sm={6} md={3} key={i}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                  <Box sx={{ color: "#10b981" }}>{item.icon}</Box>
                  <Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Access */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.info.main, 0.1), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <LinkIcon sx={{ color: theme.palette.info.main }} /> Access Path
          </Typography>
          <Typography variant="body2">Network Analysis Hub → Security Fuzzer or <code>/network/fuzzer</code></Typography>
          <Button variant="contained" size="small" sx={{ mt: 2, bgcolor: "#f97316" }} onClick={() => navigate("/network/fuzzer")}>Open Security Fuzzer</Button>
        </Paper>
      </TabPanel>

      {/* Tab 1: Agentic Fuzzer - CYBERPUNK STYLED */}
      <TabPanel value={tabValue} index={1}>
        {/* 🔥 CYBERPUNK Header Banner - matching the actual tool page 🔥 */}
        <Box
          sx={{
            position: "relative",
            p: 4,
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.95) 50%, rgba(15, 26, 46, 0.95) 100%)",
            border: "2px solid transparent",
            borderImage: "linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff) 1",
            clipPath: "polygon(0 0, calc(100% - 20px) 0, 100% 20px, 100% 100%, 20px 100%, 0 calc(100% - 20px))",
            overflow: "hidden",
            borderRadius: 0,
            "&::before": {
              content: '""',
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              height: "2px",
              background: "linear-gradient(90deg, transparent, #00ffff, #ff00ff, transparent)",
              animation: "scanLine 3s linear infinite",
            },
            "@keyframes scanLine": {
              "0%": { transform: "translateX(-100%)" },
              "100%": { transform: "translateX(100%)" },
            },
            "@keyframes glitchText": {
              "0%": { textShadow: "2px 0 #ff00ff, -2px 0 #00ffff" },
              "25%": { textShadow: "-2px 0 #ff00ff, 2px 0 #00ffff" },
              "50%": { textShadow: "2px 2px #ff00ff, -2px -2px #00ffff" },
              "75%": { textShadow: "-2px 2px #ff00ff, 2px -2px #00ffff" },
              "100%": { textShadow: "2px 0 #ff00ff, -2px 0 #00ffff" },
            },
            "@keyframes iconPulse": {
              "0%, 100%": { filter: "drop-shadow(0 0 8px #ff00ff) drop-shadow(0 0 16px #00ffff)", transform: "scale(1)" },
              "50%": { filter: "drop-shadow(0 0 16px #ff00ff) drop-shadow(0 0 32px #00ffff)", transform: "scale(1.05)" },
            },
          }}
        >
          {/* Corner Decorations */}
          <Box sx={{ position: "absolute", top: 0, left: 0, width: 40, height: 40, borderTop: "3px solid #00ffff", borderLeft: "3px solid #00ffff" }} />
          <Box sx={{ position: "absolute", top: 0, right: 0, width: 40, height: 40, borderTop: "3px solid #ff00ff", borderRight: "3px solid #ff00ff" }} />
          <Box sx={{ position: "absolute", bottom: 0, left: 0, width: 40, height: 40, borderBottom: "3px solid #ff00ff", borderLeft: "3px solid #ff00ff" }} />
          <Box sx={{ position: "absolute", bottom: 0, right: 0, width: 40, height: 40, borderBottom: "3px solid #00ffff", borderRight: "3px solid #00ffff" }} />

          <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative", zIndex: 1 }}>
            {/* Hexagonal Icon Container */}
            <Box
              sx={{
                width: 70,
                height: 70,
                background: "linear-gradient(135deg, #ff00ff 0%, #00ffff 100%)",
                clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                animation: "iconPulse 2s ease-in-out infinite",
                boxShadow: "0 0 30px rgba(255, 0, 255, 0.5), 0 0 60px rgba(0, 255, 255, 0.3)",
              }}
            >
              <SmartToyIcon sx={{ fontSize: 40, color: "#0a0a0f" }} />
            </Box>

            <Box sx={{ flex: 1 }}>
              <Typography
                variant="h4"
                sx={{
                  fontWeight: "bold",
                  fontFamily: "'Orbitron', 'Roboto Mono', monospace",
                  background: "linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff)",
                  backgroundClip: "text",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  textTransform: "uppercase",
                  letterSpacing: "4px",
                  animation: "glitchText 4s ease-in-out infinite",
                }}
              >
                AGENTIC FUZZER
              </Typography>
              <Typography
                variant="body1"
                sx={{
                  color: "#00ffff",
                  mt: 0.5,
                  fontFamily: "'Orbitron', 'Roboto Mono', monospace",
                  letterSpacing: "2px",
                  opacity: 0.9,
                  fontSize: "0.85rem",
                }}
              >
                LLM-DRIVEN AUTONOMOUS FUZZING WITH INTELLIGENT DECISION-MAKING
              </Typography>
            </Box>

            <Box sx={{ display: "flex", gap: 1 }}>
              <Chip
                icon={<AutoAwesomeIcon sx={{ color: "#ff00ff !important" }} />}
                label="AI-POWERED"
                sx={{
                  background: "rgba(255, 0, 255, 0.1)",
                  border: "1px solid #ff00ff",
                  color: "#ff00ff",
                  fontFamily: "'Orbitron', monospace",
                  fontWeight: "bold",
                  boxShadow: "0 0 15px rgba(255, 0, 255, 0.3)",
                }}
              />
              <Chip
                label="80+ TECHNIQUES"
                sx={{
                  background: "rgba(0, 255, 255, 0.1)",
                  border: "1px solid #00ffff",
                  color: "#00ffff",
                  fontFamily: "'Orbitron', monospace",
                  boxShadow: "0 0 15px rgba(0, 255, 255, 0.3)",
                }}
              />
            </Box>
          </Box>
        </Box>

        {/* What is Agentic Fuzzer - Cyberpunk Card */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(26, 10, 46, 0.8) 100%)",
            border: "1px solid rgba(0, 255, 255, 0.3)",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 15px) 0, 100% 15px, 100% 100%, 15px 100%, 0 calc(100% - 15px))",
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
            <AutoAwesomeIcon sx={{ color: "#ff00ff" }} />
            WHAT IS AGENTIC FUZZER?
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8, color: "rgba(255, 255, 255, 0.9)" }}>
            The Agentic Fuzzer is an <strong style={{ color: "#ff00ff" }}>AI-powered autonomous security testing tool</strong> featuring{" "}
            <strong style={{ color: "#00ffff" }}>4 AutoPilot modes</strong>,{" "}
            <strong style={{ color: "#ff00ff" }}>16+ scan profiles</strong>,{" "}
            <strong style={{ color: "#00ffff" }}>80+ attack techniques</strong>, and{" "}
            <strong style={{ color: "#ff00ff" }}>intelligent coverage tracking</strong>.
            It automatically discovers endpoints, fingerprints technologies, detects WAFs, adapts attack strategies, and learns from
            responses to find deeper vulnerabilities with minimal human intervention.
          </Typography>
          <Divider sx={{ my: 2, borderColor: "rgba(0, 255, 255, 0.2)" }} />
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Circuit Breakers", "Rate Limiting", "Watchdog Recovery", "Graceful Degradation", "Session Checkpoints", "Multi-Model AI"].map((feat, i) => (
              <Chip
                key={i}
                label={feat}
                size="small"
                sx={{
                  bgcolor: i % 2 === 0 ? "rgba(255, 0, 255, 0.15)" : "rgba(0, 255, 255, 0.15)",
                  color: i % 2 === 0 ? "#ff00ff" : "#00ffff",
                  border: `1px solid ${i % 2 === 0 ? "rgba(255, 0, 255, 0.3)" : "rgba(0, 255, 255, 0.3)"}`,
                  fontSize: "0.7rem",
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* AutoPilot Modes - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <SyncIcon sx={{ color: "#ff00ff" }} />
          AUTOPILOT MODES
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { mode: "DISABLED", desc: "Manual control only. Full user control over all decisions.", color: "#6b7280", glowColor: "rgba(107, 114, 128, 0.5)", icon: <StopIcon /> },
            { mode: "ASSISTED", desc: "AI suggests actions but user approves each step.", color: "#00ffff", glowColor: "rgba(0, 255, 255, 0.3)", icon: <TuneIcon /> },
            { mode: "SEMI_AUTO", desc: "AI handles routine tasks, user approves critical decisions.", color: "#f59e0b", glowColor: "rgba(245, 158, 11, 0.3)", icon: <SpeedIcon /> },
            { mode: "FULL_AUTO", desc: "Complete autonomous operation. AI handles everything.", color: "#ff00ff", glowColor: "rgba(255, 0, 255, 0.3)", icon: <RocketLaunchIcon /> },
          ].map((ap, i) => (
            <Grid item xs={6} md={3} key={i}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(26, 10, 46, 0.6) 100%)",
                  border: `2px solid ${ap.color}`,
                  borderRadius: 0,
                  clipPath: "polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px))",
                  boxShadow: `0 0 20px ${ap.glowColor}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    boxShadow: `0 0 30px ${ap.glowColor}, inset 0 0 20px ${ap.glowColor}`,
                    transform: "translateY(-2px)",
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box sx={{ color: ap.color, filter: `drop-shadow(0 0 6px ${ap.color})` }}>{ap.icon}</Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: ap.color, fontFamily: "'Orbitron', monospace", letterSpacing: "1px" }}>{ap.mode}</Typography>
                </Box>
                <Typography variant="caption" sx={{ color: "rgba(255, 255, 255, 0.7)" }}>{ap.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Scan Profiles - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <ShieldIcon sx={{ color: "#ff00ff" }} />
          SCAN PROFILES (16+ PRESETS)
        </Typography>
        <TableContainer
          component={Paper}
          sx={{
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
            border: "1px solid rgba(0, 255, 255, 0.3)",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px))",
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow sx={{ background: "linear-gradient(90deg, rgba(255, 0, 255, 0.2), rgba(0, 255, 255, 0.2))" }}>
                <TableCell sx={{ fontWeight: 700, color: "#00ffff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>PROFILE</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#00ffff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>SPEED</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#00ffff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>RISK</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#00ffff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>DESCRIPTION</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                ["Quick Scan", "Fast", "Low", "CI/CD pipelines, critical vulns only"],
                ["Standard", "Normal", "Medium", "Balanced coverage and speed"],
                ["Full Scan", "Normal", "High", "All 80+ techniques, test environments only"],
                ["OWASP Top 10", "Normal", "Medium", "2021 OWASP vulnerabilities"],
                ["OWASP API Top 10", "Normal", "Medium", "2023 API security vulnerabilities"],
                ["API Focused", "Normal", "Medium", "REST, GraphQL, WebSocket testing"],
                ["Auth Focused", "Polite", "Medium", "Authentication/authorization testing"],
                ["Injection Focused", "Normal", "High", "SQLi, CMDi, SSTI, XXE, NoSQLi"],
                ["XSS Focused", "Normal", "Low", "Cross-site scripting variants"],
                ["Passive Only", "Polite", "Minimal", "Non-intrusive analysis only"],
                ["Stealth", "Sneaky", "Low", "WAF/IDS evasion, 2s delays"],
                ["Aggressive", "Insane", "Critical", "Max speed, isolated environments"],
                ["PCI Compliance", "Polite", "Medium", "PCI-DSS requirements"],
                ["HIPAA Compliance", "Polite", "Medium", "Healthcare security standards"],
              ].map(([name, speed, risk, desc], i) => (
                <TableRow
                  key={i}
                  sx={{
                    "&:hover": { background: "rgba(0, 255, 255, 0.05)" },
                    borderBottom: "1px solid rgba(0, 255, 255, 0.1)",
                  }}
                >
                  <TableCell sx={{ fontWeight: 600, color: "#fff", borderBottom: "1px solid rgba(0, 255, 255, 0.1)" }}>{name}</TableCell>
                  <TableCell sx={{ borderBottom: "1px solid rgba(0, 255, 255, 0.1)" }}>
                    <Chip
                      label={speed}
                      size="small"
                      sx={{
                        fontSize: "0.65rem",
                        bgcolor: "rgba(0, 255, 255, 0.1)",
                        color: "#00ffff",
                        border: "1px solid rgba(0, 255, 255, 0.3)",
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ borderBottom: "1px solid rgba(0, 255, 255, 0.1)" }}>
                    <Chip
                      label={risk}
                      size="small"
                      sx={{
                        fontSize: "0.65rem",
                        bgcolor: `rgba(${risk === "Critical" ? "255, 0, 255" : risk === "High" ? "245, 158, 11" : risk === "Medium" ? "0, 255, 255" : risk === "Low" ? "16, 185, 129" : "107, 114, 128"}, 0.15)`,
                        color: risk === "Critical" ? "#ff00ff" : risk === "High" ? "#f59e0b" : risk === "Medium" ? "#00ffff" : risk === "Low" ? "#10b981" : "#6b7280",
                        border: `1px solid ${risk === "Critical" ? "rgba(255, 0, 255, 0.5)" : risk === "High" ? "rgba(245, 158, 11, 0.5)" : risk === "Medium" ? "rgba(0, 255, 255, 0.5)" : risk === "Low" ? "rgba(16, 185, 129, 0.5)" : "rgba(107, 114, 128, 0.5)"}`,
                        boxShadow: risk === "Critical" ? "0 0 8px rgba(255, 0, 255, 0.3)" : "none",
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "rgba(255, 255, 255, 0.7)", borderBottom: "1px solid rgba(0, 255, 255, 0.1)" }}>{desc}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Attack Techniques - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#ff00ff", fontFamily: "'Orbitron', monospace" }}>
          <ScienceIcon sx={{ color: "#00ffff" }} />
          ATTACK TECHNIQUE CATEGORIES (80+)
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { cat: "Injection", techs: ["SQL", "NoSQL", "Command", "LDAP", "XPath", "GraphQL", "CRLF"], color: "#ff00ff" },
            { cat: "XSS Variants", techs: ["Reflected", "Stored", "DOM", "SSTI", "CSS Injection"], color: "#00ffff" },
            { cat: "Auth Attacks", techs: ["JWT", "OAuth", "SAML", "Session Fixation", "MFA Bypass"], color: "#ff00ff" },
            { cat: "Request Attacks", techs: ["HTTP Smuggling", "Race Condition", "HTTP/2", "Request Splitting"], color: "#00ffff" },
            { cat: "SSRF/XXE", techs: ["Blind SSRF", "Blind XXE", "OOB Exfil", "Cloud Metadata"], color: "#ff00ff" },
            { cat: "Cache/CDN", techs: ["Cache Poisoning", "Cache Deception", "CDN Bypass"], color: "#00ffff" },
            { cat: "Deserialization", techs: ["Java", "PHP", "Python Pickle", ".NET"], color: "#ff00ff" },
            { cat: "API Security", techs: ["BOLA", "BFLA", "Mass Assignment", "Data Exposure"], color: "#00ffff" },
            { cat: "File Attacks", techs: ["Upload", "Inclusion", "Zip Slip", "SVG XSS"], color: "#ff00ff" },
            { cat: "Client-Side", techs: ["Prototype Pollution", "DOM Clobbering", "Clickjacking", "PostMessage"], color: "#00ffff" },
          ].map((category, i) => (
            <Grid item xs={6} md={4} lg={3} key={i}>
              <Paper
                sx={{
                  p: 2,
                  background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(26, 10, 46, 0.6) 100%)",
                  border: `1px solid ${category.color}`,
                  borderRadius: 0,
                  clipPath: "polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))",
                  boxShadow: `0 0 15px rgba(${category.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.2)`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    boxShadow: `0 0 25px rgba(${category.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.4)`,
                  },
                }}
              >
                <Typography
                  variant="subtitle2"
                  sx={{
                    fontWeight: 700,
                    color: category.color,
                    mb: 1,
                    fontFamily: "'Orbitron', monospace",
                    letterSpacing: "1px",
                    fontSize: "0.75rem",
                  }}
                >
                  {category.cat.toUpperCase()}
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {category.techs.map((t, j) => (
                    <Chip
                      key={j}
                      label={t}
                      size="small"
                      sx={{
                        fontSize: "0.6rem",
                        height: 18,
                        bgcolor: `rgba(${category.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.1)`,
                        color: category.color,
                        border: `1px solid rgba(${category.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.3)`,
                      }}
                    />
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Offensive Wordlists - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <LocalOfferIcon sx={{ color: "#ff00ff" }} />
          OFFENSIVE WORDLIST CATEGORIES
        </Typography>
        <Grid container spacing={1} sx={{ mb: 4 }}>
          {[
            { name: "SQLi", desc: "Comprehensive SQL injection" },
            { name: "XSS", desc: "Cross-site scripting" },
            { name: "Path Traversal", desc: "LFI/RFI payloads" },
            { name: "Command Injection", desc: "OS command execution" },
            { name: "SSTI", desc: "Template injection" },
            { name: "NoSQLi", desc: "MongoDB, Redis, etc." },
            { name: "SSRF", desc: "Server-side requests" },
            { name: "XXE", desc: "XML external entities" },
            { name: "Directories", desc: "Hidden paths/files" },
            { name: "GraphQL", desc: "Query injection" },
            { name: "Passwords", desc: "Top 10k passwords" },
            { name: "Custom", desc: "User uploads" },
          ].map((wl, i) => (
            <Grid item xs={4} sm={3} md={2} key={i}>
              <Paper
                sx={{
                  p: 1.5,
                  textAlign: "center",
                  background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(26, 10, 46, 0.6) 100%)",
                  border: `1px solid ${i % 2 === 0 ? "rgba(255, 0, 255, 0.4)" : "rgba(0, 255, 255, 0.4)"}`,
                  borderRadius: 0,
                  clipPath: "polygon(0 0, calc(100% - 6px) 0, 100% 6px, 100% 100%, 6px 100%, 0 calc(100% - 6px))",
                  transition: "all 0.3s ease",
                  "&:hover": {
                    boxShadow: `0 0 15px ${i % 2 === 0 ? "rgba(255, 0, 255, 0.3)" : "rgba(0, 255, 255, 0.3)"}`,
                  },
                }}
              >
                <Typography variant="caption" sx={{ fontWeight: 700, color: i % 2 === 0 ? "#ff00ff" : "#00ffff", fontFamily: "'Orbitron', monospace", fontSize: "0.7rem" }}>{wl.name}</Typography>
                <Typography variant="caption" display="block" sx={{ color: "rgba(255, 255, 255, 0.6)", fontSize: "0.6rem" }}>{wl.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* WAF Detection - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <ShieldIcon sx={{ color: "#ff00ff" }} />
          WAF DETECTION & EVASION
        </Typography>
        <Paper
          sx={{
            p: 3,
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
            border: "1px solid rgba(16, 185, 129, 0.5)",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 15px) 0, 100% 15px, 100% 100%, 15px 100%, 0 calc(100% - 15px))",
            boxShadow: "0 0 20px rgba(16, 185, 129, 0.2)",
          }}
        >
          <Typography variant="body2" sx={{ color: "rgba(255, 255, 255, 0.8)", mb: 2 }}>
            Automatically detects and attempts to bypass these Web Application Firewalls:
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Cloudflare", "AWS WAF", "Akamai", "ModSecurity", "Imperva", "F5 BIG-IP", "Sucuri", "Fortinet"].map((waf, i) => (
              <Chip
                key={i}
                label={waf}
                icon={<ShieldIcon sx={{ fontSize: 14, color: "#10b981 !important" }} />}
                sx={{
                  bgcolor: "rgba(16, 185, 129, 0.1)",
                  color: "#10b981",
                  border: "1px solid rgba(16, 185, 129, 0.4)",
                  fontFamily: "'Orbitron', monospace",
                  fontSize: "0.7rem",
                  boxShadow: "0 0 8px rgba(16, 185, 129, 0.2)",
                }}
              />
            ))}
          </Box>
          <Divider sx={{ my: 2, borderColor: "rgba(16, 185, 129, 0.2)" }} />
          <Typography variant="body2" sx={{ fontStyle: "italic", color: "rgba(16, 185, 129, 0.9)" }}>
            ⚡ When WAF is detected, the fuzzer automatically applies evasion techniques: encoding variations, case manipulation, comment injection, and chunked payloads.
          </Typography>
        </Paper>

        {/* Coverage Tracking - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <TrackChangesIcon sx={{ color: "#ff00ff" }} />
          INTELLIGENT COVERAGE TRACKING
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                height: "100%",
                background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(0, 100, 150, 0.3) 100%)",
                border: "1px solid rgba(0, 255, 255, 0.4)",
                borderRadius: 0,
                clipPath: "polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))",
              }}
            >
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>COVERAGE STATE TRACKING</Typography>
              <List dense>
                {[
                  { primary: "Techniques Tested", secondary: "Tracks which attack techniques have been applied" },
                  { primary: "Parameters Covered", secondary: "Monitors tested URL/body parameters" },
                  { primary: "Headers Tested", secondary: "Tracks injected headers (Host, X-Forwarded-For, etc.)" },
                  { primary: "HTTP Methods", secondary: "Coverage across GET, POST, PUT, DELETE, PATCH" },
                ].map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.5 }}>
                    <ListItemIcon><CheckCircleIcon sx={{ color: "#00ffff", filter: "drop-shadow(0 0 4px #00ffff)" }} /></ListItemIcon>
                    <ListItemText
                      primary={<Typography sx={{ color: "#fff", fontWeight: 600 }}>{item.primary}</Typography>}
                      secondary={<Typography variant="caption" sx={{ color: "rgba(255, 255, 255, 0.6)" }}>{item.secondary}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                height: "100%",
                background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(100, 0, 150, 0.3) 100%)",
                border: "1px solid rgba(255, 0, 255, 0.4)",
                borderRadius: 0,
                clipPath: "polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))",
              }}
            >
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#ff00ff", fontFamily: "'Orbitron', monospace" }}>PRIORITY AUTOMATION ENGINE</Typography>
              <List dense>
                {[
                  { primary: "Parameter Priority", secondary: "id, token, password, query, file ranked highest" },
                  { primary: "Technique Priority", secondary: "SQL injection, auth bypass, command injection first" },
                  { primary: "Adaptive Scoring", secondary: "Adjusts based on discovered technologies" },
                  { primary: "ETA Estimation", secondary: "Real-time scan completion predictions" },
                ].map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.5 }}>
                    <ListItemIcon><ExtensionIcon sx={{ color: "#ff00ff", filter: "drop-shadow(0 0 4px #ff00ff)" }} /></ListItemIcon>
                    <ListItemText
                      primary={<Typography sx={{ color: "#fff", fontWeight: 600 }}>{item.primary}</Typography>}
                      secondary={<Typography variant="caption" sx={{ color: "rgba(255, 255, 255, 0.6)" }}>{item.secondary}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* AI Capabilities - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          AI-POWERED CAPABILITIES
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {[
            {
              icon: <RadarIcon sx={{ fontSize: 36 }} />,
              title: "ENDPOINT DISCOVERY",
              description: "Automatically crawls and discovers hidden endpoints, parameters, and attack surfaces using intelligent path fuzzing and sitemap analysis.",
              color: "#ff00ff",
              features: ["Auto-crawling", "Hidden paths", "Parameter detection", "Sitemap parsing"],
            },
            {
              icon: <FingerprintIcon sx={{ fontSize: 36 }} />,
              title: "TECH FINGERPRINTING",
              description: "Identifies server technologies, frameworks, WAF presence, and software versions to tailor attack payloads for maximum effectiveness.",
              color: "#00ffff",
              features: ["Server detection", "WAF bypass", "Framework ID", "Version detection"],
            },
            {
              icon: <AccountTreeIcon sx={{ fontSize: 36 }} />,
              title: "ADAPTIVE ATTACKS",
              description: "Learns from responses and dynamically adjusts attack strategies. If one approach fails, it automatically tries alternative techniques.",
              color: "#ff00ff",
              features: ["Response learning", "Strategy adaptation", "Bypass generation", "Payload mutation"],
            },
            {
              icon: <PsychologyIcon sx={{ fontSize: 36 }} />,
              title: "MULTI-MODEL REASONING",
              description: "Leverages multiple AI models for intelligent decision-making, vulnerability correlation, and attack chain optimization.",
              color: "#00ffff",
              features: ["Chain analysis", "Vuln correlation", "Priority scoring", "Risk assessment"],
            },
          ].map((cap, i) => (
            <Grid item xs={12} md={6} lg={3} key={i}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.7) 100%)",
                  border: `2px solid ${cap.color}`,
                  borderRadius: 0,
                  clipPath: "polygon(0 0, calc(100% - 15px) 0, 100% 15px, 100% 100%, 15px 100%, 0 calc(100% - 15px))",
                  boxShadow: `0 0 25px rgba(${cap.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.25)`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    boxShadow: `0 0 40px rgba(${cap.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.4), inset 0 0 30px rgba(${cap.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.1)`,
                    transform: "translateY(-4px)",
                  },
                }}
              >
                <Box sx={{ color: cap.color, mb: 2, filter: `drop-shadow(0 0 10px ${cap.color})` }}>{cap.icon}</Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: cap.color, mb: 1, fontFamily: "'Orbitron', monospace", fontSize: "0.85rem" }}>
                  {cap.title}
                </Typography>
                <Typography variant="body2" sx={{ color: "rgba(255, 255, 255, 0.75)", mb: 2, fontSize: "0.8rem", lineHeight: 1.6 }}>
                  {cap.description}
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {cap.features.map((f, j) => (
                    <Chip
                      key={j}
                      label={f}
                      size="small"
                      sx={{
                        fontSize: "0.6rem",
                        height: 18,
                        bgcolor: `rgba(${cap.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.15)`,
                        color: cap.color,
                        border: `1px solid rgba(${cap.color === "#ff00ff" ? "255, 0, 255" : "0, 255, 255"}, 0.3)`,
                      }}
                    />
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Integrated Services - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#ff00ff", fontFamily: "'Orbitron', monospace" }}>
          <ExtensionIcon sx={{ color: "#00ffff" }} />
          INTEGRATED SECURITY SERVICES
        </Typography>
        <Paper
          sx={{
            p: 3,
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(26, 10, 46, 0.6) 100%)",
            border: "1px solid rgba(0, 255, 255, 0.3)",
            borderRadius: 0,
          }}
        >
          <Grid container spacing={1}>
            {[
              "JWT Attack Service", "HTTP Smuggling Detector", "Race Condition Tester",
              "CORS Analyzer", "Intelligent Crawler", "Response Diff Engine",
              "Payload Mutation Engine", "Vulnerability Correlator", "Multi-Model AI Reasoning",
              "ETA Estimation Service", "Technology Fingerprinter", "WAF Evasion Engine",
              "Session Checkpoint Manager", "Circuit Breaker System", "Dead Letter Queue",
              "Watchdog Recovery", "Attack Chain Builder", "Deduplication Engine"
            ].map((svc, i) => (
              <Grid item xs={6} sm={4} md={3} lg={2} key={i}>
                <Chip
                  label={svc}
                  size="small"
                  sx={{
                    width: "100%",
                    justifyContent: "flex-start",
                    bgcolor: i % 2 === 0 ? "rgba(255, 0, 255, 0.1)" : "rgba(0, 255, 255, 0.1)",
                    color: i % 2 === 0 ? "#ff00ff" : "#00ffff",
                    border: `1px solid ${i % 2 === 0 ? "rgba(255, 0, 255, 0.3)" : "rgba(0, 255, 255, 0.3)"}`,
                    fontFamily: "'Roboto Mono', monospace",
                    fontSize: "0.65rem",
                    height: 28,
                    "& .MuiChip-label": {
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    },
                  }}
                />
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Attack Phases - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          AUTONOMOUS ATTACK PHASES
        </Typography>
        <TableContainer
          component={Paper}
          sx={{
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
            border: "1px solid rgba(255, 0, 255, 0.4)",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px))",
          }}
        >
          <Table>
            <TableHead>
              <TableRow sx={{ background: "linear-gradient(90deg, rgba(255, 0, 255, 0.2), rgba(0, 255, 255, 0.2))" }}>
                <TableCell sx={{ fontWeight: 700, color: "#ff00ff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(255, 0, 255, 0.3)" }}>PHASE</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#ff00ff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(255, 0, 255, 0.3)" }}>DESCRIPTION</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#ff00ff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(255, 0, 255, 0.3)" }}>AI ROLE</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                ["Reconnaissance", "Crawl target, discover endpoints, identify technologies", "Intelligent path enumeration"],
                ["Fingerprinting", "Detect server, framework, WAF, and version info", "Tech stack identification"],
                ["Vulnerability Discovery", "Test discovered endpoints with adaptive payloads", "Payload mutation & optimization"],
                ["Exploitation Validation", "Confirm vulnerabilities and assess exploitability", "Context-aware verification"],
                ["Attack Chaining", "Link vulnerabilities for maximum impact assessment", "Chain correlation analysis"],
                ["Reporting", "Generate detailed findings with remediation advice", "AI-powered executive summary"],
              ].map(([phase, desc, ai], i) => (
                <TableRow key={i} sx={{ "&:hover": { background: "rgba(255, 0, 255, 0.05)" } }}>
                  <TableCell sx={{ fontWeight: 600, color: "#fff", borderBottom: "1px solid rgba(255, 0, 255, 0.1)" }}>{phase}</TableCell>
                  <TableCell sx={{ color: "rgba(255, 255, 255, 0.8)", borderBottom: "1px solid rgba(255, 0, 255, 0.1)" }}>{desc}</TableCell>
                  <TableCell sx={{ borderBottom: "1px solid rgba(255, 0, 255, 0.1)" }}>
                    <Chip
                      label={ai}
                      size="small"
                      sx={{
                        bgcolor: "rgba(0, 255, 255, 0.1)",
                        color: "#00ffff",
                        border: "1px solid rgba(0, 255, 255, 0.3)",
                        fontSize: "0.7rem",
                      }}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Real-Time Progress Tracking - NEW SECTION */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <TimelineIcon sx={{ color: "#ff00ff" }} />
          REAL-TIME PROGRESS TRACKING (SSE)
        </Typography>
        <Paper
          sx={{
            p: 3,
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(0, 50, 100, 0.5) 100%)",
            border: "1px solid rgba(0, 255, 255, 0.4)",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))",
            boxShadow: "0 0 20px rgba(0, 255, 255, 0.15)",
          }}
        >
          <Typography variant="body2" sx={{ color: "rgba(255, 255, 255, 0.8)", mb: 2 }}>
            Monitor scan progress in real-time via Server-Sent Events (SSE) streaming:
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#00ffff", mb: 1, fontFamily: "'Orbitron', monospace" }}>LIVE METRICS</Typography>
              <List dense>
                {[
                  { primary: "ETA Estimation", secondary: "Real-time completion time predictions with confidence levels" },
                  { primary: "Phase Timeline", secondary: "Visual stepper showing current and completed phases" },
                  { primary: "Iteration Counter", secondary: "Progress bar with current/total iterations" },
                  { primary: "Findings Counter", secondary: "Live count of discovered vulnerabilities by severity" },
                ].map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.5 }}>
                    <ListItemIcon><CheckCircleIcon sx={{ color: "#00ffff", filter: "drop-shadow(0 0 4px #00ffff)", fontSize: 18 }} /></ListItemIcon>
                    <ListItemText
                      primary={<Typography sx={{ color: "#fff", fontWeight: 600, fontSize: "0.85rem" }}>{item.primary}</Typography>}
                      secondary={<Typography variant="caption" sx={{ color: "rgba(255, 255, 255, 0.6)" }}>{item.secondary}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff00ff", mb: 1, fontFamily: "'Orbitron', monospace" }}>ACTIVITY LOG</Typography>
              <List dense>
                {[
                  { primary: "Tech Fingerprinting", secondary: "Server, framework, WAF detection updates" },
                  { primary: "Endpoint Discovery", secondary: "Newly found URLs, parameters, and methods" },
                  { primary: "Attack Events", secondary: "Current technique, payload, and response status" },
                  { primary: "AI Reasoning", secondary: "LLM decisions and strategy adaptations" },
                ].map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.5 }}>
                    <ListItemIcon><AutoAwesomeIcon sx={{ color: "#ff00ff", filter: "drop-shadow(0 0 4px #ff00ff)", fontSize: 18 }} /></ListItemIcon>
                    <ListItemText
                      primary={<Typography sx={{ color: "#fff", fontWeight: 600, fontSize: "0.85rem" }}>{item.primary}</Typography>}
                      secondary={<Typography variant="caption" sx={{ color: "rgba(255, 255, 255, 0.6)" }}>{item.secondary}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
          <Divider sx={{ my: 2, borderColor: "rgba(0, 255, 255, 0.2)" }} />
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Requests Made", "Endpoints Discovered", "Techniques Tested", "Time Elapsed", "Time Remaining", "Errors Count"].map((metric, i) => (
              <Chip
                key={i}
                label={metric}
                size="small"
                sx={{
                  bgcolor: i % 2 === 0 ? "rgba(0, 255, 255, 0.1)" : "rgba(255, 0, 255, 0.1)",
                  color: i % 2 === 0 ? "#00ffff" : "#ff00ff",
                  border: `1px solid ${i % 2 === 0 ? "rgba(0, 255, 255, 0.3)" : "rgba(255, 0, 255, 0.3)"}`,
                  fontSize: "0.65rem",
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* Robustness Features - NEW CYBERPUNK SECTION */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#10b981", fontFamily: "'Orbitron', monospace" }}>
          <ShieldIcon sx={{ color: "#10b981" }} />
          ENTERPRISE ROBUSTNESS FEATURES
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "Circuit Breakers", desc: "Auto-pause on repeated failures", icon: <SecurityIcon />, color: "#ff00ff" },
            { name: "Rate Limiting", desc: "Respect target rate limits", icon: <SpeedIcon />, color: "#00ffff" },
            { name: "Watchdog Recovery", desc: "Auto-restart stuck scans", icon: <RestoreIcon />, color: "#10b981" },
            { name: "Graceful Degradation", desc: "Fallback on service failures", icon: <TimelineIcon />, color: "#f59e0b" },
            { name: "Session Checkpoints", desc: "Resume from any point", icon: <SaveIcon />, color: "#ff00ff" },
            { name: "Dead Letter Queue", desc: "Track failed requests", icon: <StorageIcon />, color: "#00ffff" },
          ].map((feat, i) => (
            <Grid item xs={6} md={4} lg={2} key={i}>
              <Paper
                sx={{
                  p: 2,
                  textAlign: "center",
                  background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(26, 10, 46, 0.5) 100%)",
                  border: `1px solid ${feat.color}`,
                  borderRadius: 0,
                  clipPath: "polygon(0 0, calc(100% - 6px) 0, 100% 6px, 100% 100%, 6px 100%, 0 calc(100% - 6px))",
                  boxShadow: `0 0 10px rgba(${feat.color === "#ff00ff" ? "255, 0, 255" : feat.color === "#00ffff" ? "0, 255, 255" : feat.color === "#10b981" ? "16, 185, 129" : "245, 158, 11"}, 0.2)`,
                }}
              >
                <Box sx={{ color: feat.color, mb: 1, filter: `drop-shadow(0 0 4px ${feat.color})` }}>{feat.icon}</Box>
                <Typography variant="body2" sx={{ fontWeight: 700, color: "#fff", fontSize: "0.75rem" }}>{feat.name}</Typography>
                <Typography variant="caption" sx={{ color: "rgba(255, 255, 255, 0.6)", fontSize: "0.6rem" }}>{feat.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Authentication Support - NEW CYBERPUNK SECTION */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#f59e0b", fontFamily: "'Orbitron', monospace" }}>
          <VpnKeyIcon sx={{ color: "#f59e0b" }} />
          AUTHENTICATION SUPPORT
        </Typography>
        <Paper
          sx={{
            p: 3,
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(100, 50, 0, 0.3) 100%)",
            border: "1px solid rgba(245, 158, 11, 0.4)",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))",
          }}
        >
          <Typography variant="body2" sx={{ color: "rgba(255, 255, 255, 0.8)", mb: 2 }}>
            Configure authentication for fuzzing sessions to test authenticated endpoints:
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Basic Auth", "Bearer Token", "API Key", "JWT", "OAuth2", "Session Cookies", "Custom Headers", "SAML"].map((auth, i) => (
              <Chip
                key={i}
                label={auth}
                icon={<VpnKeyIcon sx={{ fontSize: 14, color: "#f59e0b !important" }} />}
                sx={{
                  bgcolor: "rgba(245, 158, 11, 0.1)",
                  color: "#f59e0b",
                  border: "1px solid rgba(245, 158, 11, 0.4)",
                  fontFamily: "'Roboto Mono', monospace",
                  fontSize: "0.7rem",
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* Report Management - NEW SECTION */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#10b981", fontFamily: "'Orbitron', monospace" }}>
          <AssessmentIcon sx={{ color: "#10b981" }} />
          REPORT MANAGEMENT
        </Typography>
        <Paper
          sx={{
            p: 3,
            mb: 4,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.9) 0%, rgba(0, 80, 50, 0.3) 100%)",
            border: "1px solid rgba(16, 185, 129, 0.4)",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))",
          }}
        >
          <Typography variant="body2" sx={{ color: "rgba(255, 255, 255, 0.8)", mb: 2 }}>
            Reports are <strong style={{ color: "#10b981" }}>automatically saved</strong> to the database when scans complete. Access and export your reports:
          </Typography>
          <Grid container spacing={2}>
            {[
              { name: "Auto-Save", desc: "Reports persist automatically on completion", icon: <SaveIcon />, color: "#10b981" },
              { name: "Saved Reports Panel", desc: "Browse, view, and delete past scans", icon: <HistoryIcon />, color: "#00ffff" },
              { name: "Markdown Export", desc: "Clean .md format for documentation", icon: <CodeIcon />, color: "#ff00ff" },
              { name: "PDF Export", desc: "Professional reports for stakeholders", icon: <AssessmentIcon />, color: "#f59e0b" },
              { name: "DOCX Export", desc: "Editable Word documents", icon: <DownloadIcon />, color: "#00ffff" },
              { name: "AI Summary", desc: "Executive summary with key findings", icon: <AutoAwesomeIcon />, color: "#ff00ff" },
            ].map((item, i) => (
              <Grid item xs={6} md={4} lg={2} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ color: item.color, filter: `drop-shadow(0 0 4px ${item.color})` }}>{item.icon}</Box>
                  <Box>
                    <Typography variant="body2" sx={{ fontWeight: 700, color: "#fff", fontSize: "0.75rem" }}>{item.name}</Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255, 255, 255, 0.6)", fontSize: "0.6rem" }}>{item.desc}</Typography>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Access - CYBERPUNK STYLED */}
        <Paper
          sx={{
            p: 3,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.9) 100%)",
            border: "2px solid transparent",
            borderImage: "linear-gradient(90deg, #ff00ff, #00ffff) 1",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 15px) 0, 100% 15px, 100% 100%, 15px 100%, 0 calc(100% - 15px))",
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
            <LinkIcon sx={{ color: "#ff00ff" }} /> ACCESS PATH
          </Typography>
          <Typography variant="body2" sx={{ color: "rgba(255, 255, 255, 0.8)" }}>
            Network Analysis Hub → Agentic Fuzzer or <code style={{ color: "#00ffff", background: "rgba(0, 255, 255, 0.1)", padding: "2px 6px", borderRadius: 2 }}>/network/agentic-fuzzer</code>
          </Typography>
          <Button
            variant="contained"
            size="small"
            onClick={() => navigate("/network/agentic-fuzzer")}
            sx={{
              mt: 2,
              background: "linear-gradient(90deg, #ff00ff, #00ffff)",
              color: "#0a0a0f",
              fontWeight: 700,
              fontFamily: "'Orbitron', monospace",
              letterSpacing: "2px",
              boxShadow: "0 0 20px rgba(255, 0, 255, 0.5)",
              "&:hover": {
                boxShadow: "0 0 30px rgba(0, 255, 255, 0.7)",
              },
            }}
          >
            ⚡ LAUNCH AGENTIC FUZZER
          </Button>
        </Paper>
      </TabPanel>

      {/* Tab 2: Binary Fuzzer */}
      <TabPanel value={tabValue} index={2}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1.5 }}>
          <MemoryIcon sx={{ color: "#10b981" }} />
          Binary Fuzzer - Native Code Vulnerability Discovery
        </Typography>

        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon sx={{ color: "#10b981" }} />
            What is Binary Fuzzer?
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            The Binary Fuzzer is designed for finding vulnerabilities in <strong>native executables, libraries, and firmware</strong>. 
            It uses coverage-guided fuzzing techniques with tools like <strong>AFL++</strong>, <strong>Honggfuzz</strong>, and <strong>libFuzzer</strong> to 
            discover memory corruption bugs, buffer overflows, use-after-free, and other low-level vulnerabilities that can lead to code execution.
          </Typography>
        </Paper>

        {/* Fuzzer Engines */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Supported Fuzzing Engines
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#ef4444", 0.3)}`, bgcolor: alpha("#ef4444", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>AFL++</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Industry-standard coverage-guided fuzzer with genetic algorithms. Instruments code at compile time for maximum efficiency.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Key Features:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["Coverage-guided", "QEMU mode", "Persistent mode", "Custom mutators", "Deferred fork", "CMPLOG"].map(t => <Chip key={t} label={t} size="small" sx={{ fontSize: "0.7rem" }} />)}
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#f59e0b", 0.3)}`, bgcolor: alpha("#f59e0b", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Honggfuzz</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Multi-process fuzzer with hardware-based code coverage via Intel BTS/PT. Excellent for parallel fuzzing.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Key Features:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["Hardware coverage", "Multi-process", "Intel PT support", "Persistent mode", "NetDriver", "Sanitizer aware"].map(t => <Chip key={t} label={t} size="small" sx={{ fontSize: "0.7rem" }} />)}
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#8b5cf6", 0.3)}`, bgcolor: alpha("#8b5cf6", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>libFuzzer</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                LLVM's in-process, coverage-guided fuzzer. Links directly with target code for fast iteration.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Key Features:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["In-process", "LLVM integration", "Fast cycles", "Dictionary support", "Value profiles", "Merge mode"].map(t => <Chip key={t} label={t} size="small" sx={{ fontSize: "0.7rem" }} />)}
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Instrumentation Modes - NEW */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Instrumentation Modes
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "Source Instrumentation", desc: "Compile-time coverage (fastest)", icon: <CodeIcon />, color: "#10b981" },
            { name: "QEMU Mode", desc: "Binary-only coverage via emulation", icon: <MemoryIcon />, color: "#8b5cf6" },
            { name: "Frida Mode", desc: "Dynamic instrumentation for closed binaries", icon: <BugReportIcon />, color: "#f59e0b" },
            { name: "Intel PT", desc: "Hardware-based coverage tracing", icon: <SpeedIcon />, color: "#ef4444" },
          ].map((mode, i) => (
            <Grid item xs={12} sm={6} md={3} key={i}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(mode.color, 0.3)}`, bgcolor: alpha(mode.color, 0.05) }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box sx={{ color: mode.color }}>{mode.icon}</Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{mode.name}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">{mode.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Vulnerability Types */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Detectable Vulnerability Types
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "Buffer Overflow", desc: "Stack/Heap overflows leading to code execution", color: "#ef4444", severity: "Critical" },
            { name: "Use-After-Free", desc: "Memory safety bugs exploitable for RCE", color: "#f59e0b", severity: "Critical" },
            { name: "Integer Overflow", desc: "Arithmetic errors causing memory corruption", color: "#8b5cf6", severity: "High" },
            { name: "Format String", desc: "Printf vulnerabilities for info leak/RCE", color: "#10b981", severity: "High" },
            { name: "Null Pointer Deref", desc: "Dereference crashes (DOS potential)", color: "#06b6d4", severity: "Medium" },
            { name: "Double Free", desc: "Memory corruption via heap manipulation", color: "#ec4899", severity: "Critical" },
            { name: "Out-of-Bounds Read", desc: "Info leak via memory disclosure", color: "#3b82f6", severity: "Medium" },
            { name: "Race Condition", desc: "TOCTOU and threading issues", color: "#f97316", severity: "High" },
          ].map((vuln, i) => (
            <Grid item xs={6} sm={4} md={3} key={i}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(vuln.color, 0.3)}`, bgcolor: alpha(vuln.color, 0.05), height: "100%" }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 0.5 }}>
                  <Typography variant="body2" sx={{ fontWeight: 700, color: vuln.color }}>{vuln.name}</Typography>
                  <Chip label={vuln.severity} size="small" sx={{ fontSize: "0.6rem", height: 18, bgcolor: alpha(vuln.color, 0.1), color: vuln.color }} />
                </Box>
                <Typography variant="caption" color="text.secondary">{vuln.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Sanitizers - NEW */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Sanitizer Integration
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Binary Fuzzer integrates with compiler sanitizers to detect bugs at runtime:
          </Typography>
          <Grid container spacing={2}>
            {[
              { name: "AddressSanitizer (ASan)", desc: "Detects buffer overflows, use-after-free, double-free", flags: "-fsanitize=address", color: "#ef4444" },
              { name: "MemorySanitizer (MSan)", desc: "Detects uninitialized memory reads", flags: "-fsanitize=memory", color: "#8b5cf6" },
              { name: "UndefinedBehaviorSanitizer", desc: "Detects undefined behavior (integer overflow, etc)", flags: "-fsanitize=undefined", color: "#f59e0b" },
              { name: "ThreadSanitizer (TSan)", desc: "Detects data races in multi-threaded code", flags: "-fsanitize=thread", color: "#10b981" },
            ].map((san, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(san.color, 0.2)}`, bgcolor: alpha(san.color, 0.03) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: san.color }}>{san.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{san.desc}</Typography>
                  <Chip label={san.flags} size="small" sx={{ fontSize: "0.7rem", fontFamily: "monospace", bgcolor: alpha(san.color, 0.1), color: san.color }} />
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Corpus Management - NEW */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Corpus Management
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { icon: <FolderIcon />, title: "Seed Corpus", desc: "Initial test inputs to bootstrap fuzzing" },
            { icon: <AutoAwesomeIcon />, title: "Corpus Minimization", desc: "Remove redundant inputs preserving coverage" },
            { icon: <MergeIcon />, title: "Corpus Merging", desc: "Combine corpora from multiple fuzzing runs" },
            { icon: <SyncIcon />, title: "Corpus Synchronization", desc: "Share findings across parallel instances" },
          ].map((item, i) => (
            <Grid item xs={12} sm={6} md={3} key={i}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box sx={{ color: "#10b981" }}>{item.icon}</Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Crash Analysis Features */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Crash Analysis Features
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4 }}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem><ListItemIcon><BugReportIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Automatic Crash Triage" secondary="Deduplicates and categorizes crashes by root cause using stack hashes" /></ListItem>
                <ListItem><ListItemIcon><CodeIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Stack Trace Analysis" secondary="Parses and highlights relevant crash locations with source mapping" /></ListItem>
                <ListItem><ListItemIcon><SecurityIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Exploitability Assessment" secondary="Estimates severity and exploitation potential (GDB exploitable)" /></ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem><ListItemIcon><SaveIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="PoC Generation" secondary="Saves minimal reproducer inputs for each unique crash" /></ListItem>
                <ListItem><ListItemIcon><TimelineIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Crash Timeline" secondary="Track when crashes were first discovered and their frequency" /></ListItem>
                <ListItem><ListItemIcon><AssessmentIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Coverage Visualization" secondary="View code coverage heatmaps and identify untested paths" /></ListItem>
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* Performance Tuning - NEW */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Performance Tuning
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#8b5cf6", 0.2)}`, bgcolor: alpha("#8b5cf6", 0.03) }}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <SpeedIcon sx={{ color: "#8b5cf6" }} /> Execution Speed
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Persistent mode for 10-20x speedup" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Deferred forkserver initialization" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="In-memory test case passing" /></ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon sx={{ color: "#8b5cf6" }} /> Resource Management
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Memory limits per instance" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Timeout configuration" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="CPU core pinning" /></ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <GroupIcon sx={{ color: "#8b5cf6" }} /> Parallel Fuzzing
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Multi-instance coordination" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Distributed fuzzing support" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Crash result aggregation" /></ListItem>
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* Access */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#10b981", 0.1), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <LinkIcon sx={{ color: "#10b981" }} /> Access Path
          </Typography>
          <Typography variant="body2">Network Analysis Hub → Binary Fuzzer or <code>/network/binary-fuzzer</code></Typography>
          <Button variant="contained" size="small" sx={{ mt: 2, bgcolor: "#10b981" }} onClick={() => navigate("/network/binary-fuzzer")}>Open Binary Fuzzer</Button>
        </Paper>
      </TabPanel>

      {/* Tab 3: Smart Detection */}
      <TabPanel value={tabValue} index={3}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          🧠 Smart Detection
        </Typography>

        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <AutoAwesomeIcon sx={{ color: "#8b5cf6" }} />
            What is Smart Detection?
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Smart Detection automatically analyzes all fuzzing responses using <strong>50+ pattern signatures</strong> to 
            identify vulnerabilities without manual review. It classifies findings by severity, calculates a risk score, 
            and provides remediation recommendations.
          </Typography>
        </Paper>

        {/* Detection Categories */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Detection Categories & Signatures
        </Typography>
        <TableContainer component={Paper} sx={{ borderRadius: 3, mb: 4 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Signatures</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Severity</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Example Patterns</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {smartDetectionSignatures.map((sig, i) => (
                <TableRow key={i}>
                  <TableCell sx={{ fontWeight: 600 }}>{sig.category}</TableCell>
                  <TableCell>{sig.count}</TableCell>
                  <TableCell>
                    <Chip
                      label={sig.severity}
                      size="small"
                      sx={{
                        bgcolor: alpha(
                          sig.severity === "Critical" ? "#ef4444" : sig.severity === "High" ? "#f59e0b" : "#3b82f6",
                          0.1
                        ),
                        color: sig.severity === "Critical" ? "#ef4444" : sig.severity === "High" ? "#f59e0b" : "#3b82f6",
                        fontWeight: 600,
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                    {sig.examples.join(", ")}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Smart Detection Features */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, height: "100%", textAlign: "center" }}>
              <Box
                sx={{
                  width: 64,
                  height: 64,
                  borderRadius: "50%",
                  bgcolor: alpha("#ef4444", 0.1),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  mx: "auto",
                  mb: 2,
                }}
              >
                <VisibilityIcon sx={{ fontSize: 32, color: "#ef4444" }} />
              </Box>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                Risk Score (0-100)
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Visual gauge showing overall risk level based on vulnerability count and severity distribution
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, height: "100%", textAlign: "center" }}>
              <Box
                sx={{
                  width: 64,
                  height: 64,
                  borderRadius: "50%",
                  bgcolor: alpha("#f59e0b", 0.1),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  mx: "auto",
                  mb: 2,
                }}
              >
                <BugReportIcon sx={{ fontSize: 32, color: "#f59e0b" }} />
              </Box>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                Auto Classification
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Vulnerabilities grouped by type with severity badges, confidence levels, and matched patterns
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, height: "100%", textAlign: "center" }}>
              <Box
                sx={{
                  width: 64,
                  height: 64,
                  borderRadius: "50%",
                  bgcolor: alpha("#10b981", 0.1),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  mx: "auto",
                  mb: 2,
                }}
              >
                <CheckCircleIcon sx={{ fontSize: 32, color: "#10b981" }} />
              </Box>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                Recommendations
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Actionable remediation guidance for each detected vulnerability category
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* How to Use */}
        <Paper
          sx={{
            p: 3,
            mt: 4,
            borderRadius: 3,
            bgcolor: alpha(theme.palette.success.main, 0.1),
            border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: theme.palette.success.main }} />
            How to Use Smart Detection
          </Typography>
          <List dense>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
              <ListItemText primary="Run your fuzzing campaign normally - Smart Detection works automatically" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
              <ListItemText primary="Click the 'Smart Detection' tab to see analyzed results" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
              <ListItemText primary="Click 'Analyze Responses' to run detection on existing results" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
              <ListItemText primary="Expand vulnerability categories to see individual findings" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
              <ListItemText primary="Review recommendations and export findings for reporting" />
            </ListItem>
          </List>
        </Paper>
      </TabPanel>

      {/* Tab 4: Sessions */}
      <TabPanel value={tabValue} index={4}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📁 Session Management
        </Typography>

        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <StorageIcon sx={{ color: "#10b981" }} />
            Why Sessions Matter
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Sessions allow you to <strong>save</strong>, <strong>restore</strong>, and <strong>manage</strong> your fuzzing 
            campaigns. Perfect for long-running tests, team collaboration, or continuing work later. All sessions are 
            stored in PostgreSQL for persistence.
          </Typography>
        </Paper>

        {/* Session Features */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <FeatureCard
              icon={<SaveIcon sx={{ fontSize: 32 }} />}
              title="Save Sessions"
              description="Capture your current configuration, all results, statistics, and Smart Detection findings with one click."
              color="#10b981"
              tips={["Add name & description", "Tag sessions", "Auto-save target URL"]}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <FeatureCard
              icon={<RestoreIcon sx={{ fontSize: 32 }} />}
              title="Restore Sessions"
              description="Load any saved session to continue testing or review previous results. Full state restoration."
              color="#3b82f6"
              tips={["Full config restore", "Results included", "Resume fuzzing"]}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <FeatureCard
              icon={<DownloadIcon sx={{ fontSize: 32 }} />}
              title="Export Sessions"
              description="Export sessions as JSON for backup, sharing, or integration with other tools."
              color="#8b5cf6"
              tips={["JSON format", "Full data export", "Import anywhere"]}
            />
          </Grid>
        </Grid>

        {/* Session Data */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          What's Saved in a Session
        </Typography>
        <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#10b981", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Data Type</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                ["Configuration", "Target URL, HTTP method, headers, rate limits, timeouts"],
                ["Payload Settings", "Payload mode, custom wordlist, encoding options"],
                ["Results", "All response data, status codes, sizes, timing"],
                ["Statistics", "Request counts, success/error rates, duration"],
                ["Smart Detection", "Detected vulnerabilities, severity, recommendations"],
                ["Metadata", "Session name, description, tags, timestamps"],
              ].map(([type, desc], i) => (
                <TableRow key={i}>
                  <TableCell sx={{ fontWeight: 600 }}>{type}</TableCell>
                  <TableCell>{desc}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Session Actions */}
        <Paper
          sx={{
            p: 3,
            mt: 4,
            borderRadius: 3,
            bgcolor: alpha(theme.palette.warning.main, 0.1),
            border: `1px solid ${alpha(theme.palette.warning.main, 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: theme.palette.warning.main }} />
            Session Management Tips
          </Typography>
          <List dense>
            <ListItem>
              <ListItemText 
                primary="Use descriptive names" 
                secondary="Include target, date, and test type for easy identification"
              />
            </ListItem>
            <ListItem>
              <ListItemText 
                primary="Tag your sessions" 
                secondary="Use tags like 'production', 'staging', 'sqli', 'xss' for filtering"
              />
            </ListItem>
            <ListItem>
              <ListItemText 
                primary="Export before deleting" 
                secondary="Always export important sessions as JSON backup before removal"
              />
            </ListItem>
            <ListItem>
              <ListItemText 
                primary="Review before restore" 
                secondary="Restoring overwrites current results - save first if needed"
              />
            </ListItem>
          </List>
        </Paper>
      </TabPanel>

      {/* Tab 5: Pro Tips */}
      <TabPanel value={tabValue} index={5}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          💡 Pro Tips & Best Practices
        </Typography>

        <Accordion defaultExpanded sx={{ borderRadius: "12px !important", mb: 2, "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              🎯 Choosing the Right Fuzzer
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <List dense>
              <ListItem>
                <ListItemIcon><SecurityIcon sx={{ color: "#f97316" }} /></ListItemIcon>
                <ListItemText 
                  primary="Security Fuzzer" 
                  secondary="Best for: Web APIs, form inputs, URL parameters, authentication testing"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><SmartToyIcon sx={{ color: "#8b5cf6" }} /></ListItemIcon>
                <ListItemText 
                  primary="Agentic Fuzzer" 
                  secondary="Best for: Unknown attack surfaces, reconnaissance, adaptive testing, WAF evasion"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><MemoryIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                <ListItemText 
                  primary="Binary Fuzzer" 
                  secondary="Best for: Native executables, parsers, file format handlers, firmware"
                />
              </ListItem>
            </List>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ borderRadius: "12px !important", mb: 2, "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              🎯 Target Selection
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <List dense>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Start with unauthenticated endpoints" 
                  secondary="Test public-facing functionality first before adding auth headers"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Focus on input parameters" 
                  secondary="search, id, page, filter, sort - these often have weak validation"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Test multiple injection points" 
                  secondary="URL params, POST body, headers, cookies can all be vulnerable"
                />
              </ListItem>
            </List>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ borderRadius: "12px !important", mb: 2, "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              ⚡ Performance Optimization
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <List dense>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Start with lower concurrency" 
                  secondary="Begin with 2-3 concurrent requests, increase if stable"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Use Quick mode first" 
                  secondary="Run targeted SQLi or XSS tests before comprehensive scans"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Monitor Statistics tab" 
                  secondary="Watch for high error rates indicating rate limiting or crashes"
                />
              </ListItem>
            </List>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ borderRadius: "12px !important", mb: 2, "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              🛡️ Responsible Testing
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Paper
              sx={{
                p: 2,
                mb: 2,
                bgcolor: alpha(theme.palette.warning.main, 0.1),
                borderRadius: 2,
              }}
            >
              <Typography variant="body2" sx={{ color: "warning.main", fontWeight: 500 }}>
                ⚠️ Only test applications you have explicit permission to test
              </Typography>
            </Paper>
            <List dense>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Get written authorization" 
                  secondary="Always have explicit permission before testing"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Use rate limiting" 
                  secondary="Don't DoS the target - respect server capacity"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Document everything" 
                  secondary="Save sessions and export findings for proper reporting"
                />
              </ListItem>
            </List>
          </AccordionDetails>
        </Accordion>
      </TabPanel>

      {/* Footer CTA */}
      <Paper
        sx={{
          mt: 4,
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
          border: `1px solid ${alpha("#f97316", 0.2)}`,
        }}
      >
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
          🔥 Ready to Start Fuzzing?
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Choose the right fuzzer for your target and start discovering vulnerabilities!
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap", mb: 2 }}>
          <Chip
            icon={<SecurityIcon />}
            label="Security Fuzzer"
            clickable
            onClick={() => navigate("/network/fuzzer")}
            sx={{ bgcolor: "#f97316", color: "white", fontWeight: 600, "&:hover": { bgcolor: "#ea580c" } }}
          />
          <Chip
            icon={<SmartToyIcon />}
            label="Agentic Fuzzer"
            clickable
            onClick={() => navigate("/network/agentic-fuzzer")}
            sx={{ bgcolor: "#8b5cf6", color: "white", fontWeight: 600, "&:hover": { bgcolor: "#7c3aed" } }}
          />
          <Chip
            icon={<MemoryIcon />}
            label="Binary Fuzzer"
            clickable
            onClick={() => navigate("/network/binary-fuzzer")}
            sx={{ bgcolor: "#10b981", color: "white", fontWeight: 600, "&:hover": { bgcolor: "#059669" } }}
          />
        </Box>
        <Divider sx={{ my: 2 }} />
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Chip
            label="Back to Learning Hub"
            clickable
            onClick={() => navigate("/learn")}
            sx={{ fontWeight: 600 }}
          />
          <Chip
            label="Fuzzing Concepts Guide"
            clickable
            onClick={() => navigate("/learn/fuzzing")}
            sx={{ fontWeight: 600 }}
          />
        </Box>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
