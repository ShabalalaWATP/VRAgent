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
import SmartToyIcon from "@mui/icons-material/SmartToy";
import MemoryIcon from "@mui/icons-material/Memory";
import RadarIcon from "@mui/icons-material/Radar";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import TerminalIcon from "@mui/icons-material/Terminal";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
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
import ExploreIcon from "@mui/icons-material/Explore";
import DescriptionIcon from "@mui/icons-material/Description";

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

// Security Fuzzer feature summary
const tabConfig = [
  { name: "Multi-position injection", icon: <TrackChangesIcon /> },
  { name: "Attack modes (4)", icon: <TuneIcon /> },
  { name: "Built-in wordlists (10)", icon: <LocalOfferIcon /> },
  { name: "Payload generators", icon: <TransformIcon /> },
  { name: "Smart Detection", icon: <AutoAwesomeIcon /> },
  { name: "Sessions & export", icon: <SaveIcon /> },
];

// Smart Detection signatures (signature families in smart_detection_service.py)
const smartDetectionSignatures = [
  { category: "SQL Injection", count: 7, severity: "High", examples: ["SQL syntax", "ORA-", "SQLSTATE"] },
  { category: "XSS", count: 3, severity: "High", examples: ["<script", "onerror=", "javascript:"] },
  { category: "Command Injection", count: 2, severity: "Critical", examples: ["uid=", "root:.*:0:0:", "Windows IP Configuration"] },
  { category: "Path Traversal", count: 2, severity: "High", examples: ["/etc/passwd", "[boot loader]", "localhost 127.0.0.1"] },
  { category: "SSTI", count: 2, severity: "High", examples: ["{{7*7}}", "TemplateSyntaxError", "freemarker"] },
  { category: "XXE", count: 2, severity: "High", examples: ["<!ENTITY", "XMLParseError", "file://"] },
  { category: "LDAP Injection", count: 1, severity: "High", examples: ["Invalid DN syntax", "LdapErr:", "javax.naming"] },
  { category: "Open Redirect", count: 1, severity: "Medium", examples: ["Location:", "Refresh:", "redirect="] },
  { category: "Information Disclosure", count: 5, severity: "Medium", examples: ["stack trace", "DEBUG = True", "Exception in thread"] },
];

export default function FuzzingToolGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `VRAgent Fuzzing Tool Guide covering the Security Fuzzer (multi-position web fuzzing with FUZZ/§n§ markers, four attack modes, built-in wordlists and payload generators, response filtering, WebSocket fuzzing, Smart Detection signatures + anomaly analysis, sessions and report exports), Agentic Fuzzer (SSE streaming, intelligent crawl + reconnaissance + fingerprinting, 88 techniques, 5 presets, depth/iteration control, stealth mode, WAF detection/evasion, attack-chain and blind/OOB testing, auto-saved reports with MD/PDF/DOCX export), and Binary Fuzzer (AFL++ coverage-guided fuzzing, crash bucketing and exploitability analysis, QEMU mode for closed-source binaries, corpus browser, AI seed/coverage/exploit guidance, and report exports).`;

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
                Web application fuzzing with Smart Detection, built-in wordlists, and response analysis
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
                AFL++ coverage-guided fuzzing with crash bucketing and QEMU mode support
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
            { value: "88", label: "Agentic Techniques" },
            { value: "4", label: "Attack Modes" },
            { value: "10", label: "Built-in Wordlists" },
            { value: "5", label: "Agentic Presets" },
            { value: "7", label: "WAF Fingerprints" },
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
            The Security Fuzzer is a web application fuzzing tool that sends payloads to your chosen injection points
            in a request. You mark positions with <code>FUZZ</code> or <code>§0§</code>, select an attack mode, and the
            fuzzer iterates over built-in or custom payload lists while streaming results in real time. Smart Detection
            performs signature + anomaly analysis, and sessions let you save configurations, results, and export reports.
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
          Payload Sources
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "Built-in Wordlists", desc: "10 categories / 325 payloads", color: "#ef4444" },
            { name: "Custom Wordlist", desc: "Upload .txt per position", color: "#f59e0b" },
            { name: "Manual Payloads", desc: "Paste one per line", color: "#8b5cf6" },
            { name: "Payload Generators", desc: "Number/char/date ranges", color: "#10b981" },
            { name: "Encoding Toolkit", desc: "URL/HTML/Unicode/Base64", color: "#06b6d4" },
            { name: "Multi-Position Sets", desc: "Independent lists per §n§", color: "#ec4899" },
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
          Built-in Wordlists (10 Categories)
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "Common Directories", count: "50", label: "Discovery", color: "#3b82f6", samples: ["admin", "api", "backup", "login"] },
            { name: "Common Files", count: "40", label: "Discovery", color: "#3b82f6", samples: [".env", "config.yml", "Dockerfile", "package.json"] },
            { name: "SQL Injection", count: "35", label: "Injection", color: "#ef4444", samples: ["' OR 1=1--", "UNION SELECT", "SLEEP(5)", "SQLSTATE"] },
            { name: "XSS Payloads", count: "40", label: "Client", color: "#f59e0b", samples: ["<script>", "onerror=", "svg onload", "javascript:"] },
            { name: "Path Traversal", count: "30", label: "File", color: "#8b5cf6", samples: ["../", "..\\\\", "/etc/passwd", "C:\\\\Windows\\\\System32"] },
            { name: "Command Injection", count: "25", label: "Injection", color: "#ef4444", samples: ["; id", "| whoami", "`ls -la`", "&& cat /etc/passwd"] },
            { name: "SSTI Payloads", count: "20", label: "Injection", color: "#f97316", samples: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"] },
            { name: "API Parameters", count: "50", label: "API", color: "#10b981", samples: ["id", "user_id", "token", "redirect"] },
            { name: "HTTP Methods", count: "15", label: "Protocol", color: "#06b6d4", samples: ["GET", "POST", "PUT", "DELETE"] },
            { name: "User Agents", count: "20", label: "Header", color: "#ec4899", samples: ["Mozilla/5.0", "curl/7.68.0", "python-requests", "PostmanRuntime"] },
          ].map((cat, i) => (
            <Grid item xs={12} sm={6} md={4} key={i}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(cat.color, 0.3)}`, bgcolor: alpha(cat.color, 0.05) }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{cat.name}</Typography>
                  <Chip label={cat.label} size="small" sx={{ bgcolor: alpha(cat.color, 0.1), color: cat.color, fontWeight: 600, fontSize: "0.7rem" }} />
                </Box>
                <Typography variant="caption" color="text.secondary">{cat.count} payloads</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
                  {cat.samples.map((t, j) => (
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
            { name: "Headers & Auth", options: ["Custom headers", "Authorization token", "Cookies", "User-Agent"], icon: <VpnKeyIcon /> },
            { name: "Rate Control", options: ["Concurrency (threads)", "Delay per request", "Timeouts", "Retries"], icon: <SpeedIcon /> },
            { name: "Proxy & Redirects", options: ["HTTP/SOCKS proxy", "Follow redirects", "Inspect in Burp/ZAP", "Manual repeater"], icon: <LinkIcon /> },
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
                  <ListItemText primary="Signature Findings" secondary="Detects SQLi, XSS, XXE, and other known patterns" /></ListItem>
                <ListItem><ListItemIcon><AutoAwesomeIcon sx={{ color: "#8b5cf6", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Anomaly Detection" secondary="Flags timing, length, and status outliers" /></ListItem>
                <ListItem><ListItemIcon><AutoAwesomeIcon sx={{ color: "#8b5cf6", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Response Categorization" secondary="Groups responses as interesting, blocked, or error" /></ListItem>
                <ListItem><ListItemIcon><AutoAwesomeIcon sx={{ color: "#8b5cf6", fontSize: 20 }} /></ListItemIcon>
                  <ListItemText primary="Risk Summary" secondary="Aggregates findings into a session-level score" /></ListItem>
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
          <Step active><StepLabel><Typography sx={{ fontWeight: 600 }}>Select Payload Source</Typography></StepLabel>
            <StepContent><Typography variant="body2" color="text.secondary">Pick built-in wordlists, a generator (range/charset/date), or a custom list</Typography></StepContent></Step>
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
            Security Fuzzer supports <strong>full session persistence</strong> so you can save and resume long-running
            campaigns, then export findings when you're ready to report.
          </Typography>
          <Grid container spacing={2}>
            {[
              { icon: <SaveIcon />, title: "Save Sessions", desc: "Persist fuzzing configuration, results, and progress" },
              { icon: <RestoreIcon />, title: "Restore Sessions", desc: "Continue interrupted scans from where you left off" },
              { icon: <StorageIcon />, title: "Export Results", desc: "Export findings to JSON, Markdown, PDF, or DOCX" },
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
                label="88 TECHNIQUES"
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
            The Agentic Fuzzer is an <strong style={{ color: "#ff00ff" }}>LLM-driven autonomous security testing tool</strong> that
            streams scan progress via SSE, performs intelligent crawling and reconnaissance, fingerprints the target stack, and selects
            from <strong style={{ color: "#00ffff" }}>88 techniques</strong> using presets or depth-based iteration budgets. It adapts
            payloads based on responses, supports blind/OOB testing and attack-chain correlation, and auto-saves reports for export.
          </Typography>
          <Divider sx={{ my: 2, borderColor: "rgba(0, 255, 255, 0.2)" }} />
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Circuit Breakers", "Rate Limiter", "Watchdog", "Intelligent Crawl", "Attack Chains", "Stealth Mode"].map((feat, i) => (
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

        {/* Depth & Iteration Budgets - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <SyncIcon sx={{ color: "#ff00ff" }} />
          DEPTH & ITERATION BUDGETS
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { mode: "MINIMAL", desc: "25 iterations • fast sanity check", color: "#6b7280", glowColor: "rgba(107, 114, 128, 0.5)", icon: <TimerIcon /> },
            { mode: "QUICK", desc: "50 iterations • light recon", color: "#00ffff", glowColor: "rgba(0, 255, 255, 0.3)", icon: <SpeedIcon /> },
            { mode: "NORMAL", desc: "150 iterations • balanced", color: "#f59e0b", glowColor: "rgba(245, 158, 11, 0.3)", icon: <TuneIcon /> },
            { mode: "THOROUGH", desc: "500 iterations • deep coverage", color: "#8b5cf6", glowColor: "rgba(139, 92, 246, 0.3)", icon: <RocketLaunchIcon /> },
            { mode: "AGGRESSIVE", desc: "1500 iterations • maximum depth", color: "#ff00ff", glowColor: "rgba(255, 0, 255, 0.3)", icon: <WarningIcon /> },
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

        {/* Presets - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <ShieldIcon sx={{ color: "#ff00ff" }} />
          PRESETS (5 BUILT-IN)
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
                <TableCell sx={{ fontWeight: 700, color: "#00ffff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>DEPTH</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#00ffff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>ITERATIONS</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#00ffff", fontFamily: "'Orbitron', monospace", borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>FOCUS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                ["Web App Quick Scan", "quick", "20", "SQLi, XSS, path traversal"],
                ["Web App Thorough", "thorough", "100", "All techniques (adaptive selection)"],
                ["API Security Test", "normal", "50", "IDOR/auth bypass/api abuse"],
                ["Injection Focus", "thorough", "75", "SQLi, CMDi, SSTI, XXE, headers"],
                ["Malware Analysis", "normal", "50", "C2 detection, evasion, sandbox analysis"],
              ].map(([name, depth, iterations, desc], i) => (
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
                      label={depth}
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
                      label={iterations}
                      size="small"
                      sx={{
                        fontSize: "0.65rem",
                        bgcolor: "rgba(255, 0, 255, 0.1)",
                        color: "#ff00ff",
                        border: "1px solid rgba(255, 0, 255, 0.3)",
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
          TECHNIQUE CATEGORIES (88 TOTAL)
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { cat: "Injection", techs: ["SQLi", "NoSQLi", "Command", "LDAP", "XPath", "SSTI"], color: "#ff00ff" },
            { cat: "Client-Side", techs: ["XSS", "DOM Clobbering", "Prototype Pollution", "CSS Injection", "PostMessage"], color: "#00ffff" },
            { cat: "Auth & Access", techs: ["Auth Bypass", "IDOR", "BOLA", "Session Fixation", "MFA Bypass"], color: "#ff00ff" },
            { cat: "Protocol & API", techs: ["GraphQL", "WebSocket", "gRPC", "OpenAPI", "API Abuse"], color: "#00ffff" },
            { cat: "Blind/OOB", techs: ["Blind SSRF", "Blind SQLi", "Blind XXE", "Blind RCE", "OOB Exfil"], color: "#ff00ff" },
            { cat: "Request Layer", techs: ["HTTP Smuggling", "Request Splitting", "HTTP/2", "Race Condition"], color: "#00ffff" },
            { cat: "Deserialization", techs: ["Java", "PHP", "Python Pickle", ".NET"], color: "#ff00ff" },
            { cat: "File & Upload", techs: ["File Upload", "File Inclusion", "Zip Slip", "SVG XSS", "PDF Injection"], color: "#00ffff" },
            { cat: "Cache/CDN", techs: ["Cache Poisoning", "Cache Deception", "CDN Bypass"], color: "#ff00ff" },
            { cat: "Crypto/Cloud/CMS", techs: ["Padding Oracle", "Timing", "Cloud Metadata", "WP/Drupal/Joomla"], color: "#00ffff" },
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

        {/* Payload Generation - CYBERPUNK STYLED */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
          <LocalOfferIcon sx={{ color: "#ff00ff" }} />
          PAYLOAD GENERATION & EVIDENCE
        </Typography>
        <Grid container spacing={1} sx={{ mb: 4 }}>
          {[
            { name: "Context-Aware Payloads", desc: "Parameter-type + tech hints" },
            { name: "Technique Wordlists", desc: "SQLi/XSS/SSRF/XXE" },
            { name: "Blind/OOB Payloads", desc: "Timing + callback tests" },
            { name: "WAF Mutations", desc: "Encoding/case/obfuscation" },
            { name: "Header Injection", desc: "Host/Forwarded/User-Agent" },
            { name: "JWT Attacks", desc: "Algo/claim abuse payloads" },
            { name: "Attack Chains", desc: "Multi-step exploit paths" },
            { name: "Response Fingerprints", desc: "Baseline diffs" },
            { name: "Parameter Discovery", desc: "URL/body/header params" },
            { name: "Protocol Targets", desc: "GraphQL/WebSocket/gRPC" },
            { name: "File Vectors", desc: "Upload/inclusion/zip slip" },
            { name: "CMS Targets", desc: "WP/Drupal/Joomla" },
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
            {["Cloudflare", "AWS WAF", "Akamai", "ModSecurity", "Imperva", "F5 BIG-IP", "Sucuri", "Unknown"].map((waf, i) => (
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
            ⚡ When a WAF is detected, the fuzzer generates mutation and encoding variants tailored to the detected signature.
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
              features: ["Server detection", "WAF detection", "Framework ID", "Version detection"],
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
              title: "ATTACK CHAINS & BLIND TESTS",
              description: "Correlates multi-step exploit paths and runs timing/callback checks for blind SSRF/SQLi/XXE.",
              color: "#00ffff",
              features: ["Attack chains", "Blind timing", "OOB callbacks", "Risk prioritization"],
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
              "JWT Attack Service", "HTTP Smuggling Tests", "Race Condition Testing",
              "CORS Bypass Checks", "Intelligent Crawler", "Response Fingerprinting",
              "Payload Mutation Engine", "Vulnerability Correlator", "Attack Surface Mapper",
              "ETA Estimation Service", "Technology Fingerprinter", "WAF Evasion Engine",
              "Session Checkpointing", "Circuit Breaker System", "Dead Letter Queue",
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
                ["Fingerprinting", "Detect server, framework, language, and WAF signals", "Tech stack identification"],
                ["Intelligent Crawl", "Discover endpoints, params, and methods", "Auto-discovery & sitemap parsing"],
                ["Reconnaissance", "Profile auth, tech, and attack surface", "Context-aware target mapping"],
                ["Technique Selection", "Pick techniques based on findings and scope", "Adaptive strategy planning"],
                ["Payload Execution", "Run technique payloads with response analysis", "Mutation & evidence capture"],
                ["Chain Exploitation", "Correlate multi-step attack paths", "Attack-chain reasoning"],
                ["Reporting", "Summarize findings with remediation guidance", "Executive report synthesis"],
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
            Use headers in the UI or configure auth via the API to test protected endpoints:
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Basic Auth", "Bearer Token", "API Key", "JWT", "OAuth2", "Session Login", "Cookie-Based", "Custom Headers"].map((auth, i) => (
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

        {/* Overview */}
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
            What is the Binary Fuzzer?
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8, mb: 2 }}>
            The <strong>Agentic Binary Fuzzer</strong> is an AI-powered autonomous fuzzing system that combines
            <strong> AFL++</strong> (American Fuzzy Lop Plus Plus) with intelligent decision-making to find vulnerabilities in
            native executables, libraries, and firmware. Unlike traditional fuzzers that run with fixed configurations,
            the Agentic Binary Fuzzer continuously monitors campaign progress and makes strategic adjustments to maximize
            vulnerability discovery.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            The AI acts as an <strong>automated fuzzing campaign manager</strong> - it doesn't replace AFL++, but rather
            monitors metrics (coverage, crash rates, execution speed) every 5 minutes and decides whether to switch strategies,
            enable advanced features like CMPLOG, generate new seeds, or adjust mutation weights. This automation eliminates
            the need for constant human monitoring during long-running campaigns.
          </Typography>
        </Paper>

        {/* Architecture Diagram */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          System Architecture
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, bgcolor: alpha("#1e1e2e", 0.5), fontFamily: "monospace" }}>
          <Typography component="pre" sx={{ fontSize: "0.75rem", lineHeight: 1.6, color: "#e2e8f0", overflow: "auto" }}>
{`┌─────────────────────────────────────────────────────────────────────────┐
│                        AGENTIC BINARY FUZZER                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────┐              ┌─────────────────────────────┐  │
│   │   AFL++ ENGINE(S)   │   feedback   │   AGENTIC REASONING ENGINE  │  │
│   │                     │ ───────────► │                             │  │
│   │  • Execute binary   │              │  • MEMORY: Past decisions   │  │
│   │  • Track coverage   │              │  • REASONING: Multi-step    │  │
│   │  • Find crashes     │ ◄─────────── │  • LEARNING: What works     │  │
│   │  • Mutate inputs    │   commands   │  • EXPLORATION: Try new     │  │
│   │                     │              │                             │  │
│   └─────────────────────┘              └─────────────────────────────┘  │
│                                                                         │
│   Every 5 minutes: AI reviews metrics and makes strategic decisions     │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                      CAMPAIGN LIFECYCLE                          │   │
│   │  Upload → Quick Analysis → Configure → Run → Monitor → Report   │   │
│   └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘`}
          </Typography>
        </Paper>

        {/* How the AI Works */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          How the AI Decision-Making Works
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#8b5cf6", 0.3)}`, bgcolor: alpha("#8b5cf6", 0.05) }}>
          <Typography variant="body2" sx={{ mb: 2 }}>
            The AI is <strong>NOT running AFL++</strong> directly. AFL++ does the actual fuzzing (executing the binary millions of times).
            The AI acts as a <strong>strategic advisor</strong> that monitors progress and makes tactical decisions at regular intervals.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>
                What the AI Receives (Every 5 min):
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Coverage percentage (how much code explored)" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Unique crashes found / exploitable count" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Executions per second" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Corpus size and trend direction" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Coverage trend (increasing/stable/declining)" /></ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>
                Decisions the AI Can Make:
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="SWITCH_STRATEGY → Change power schedule" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="ENABLE_CMPLOG → Magic byte solving" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="GENERATE_SEEDS → Create new test inputs" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="ADJUST_MUTATIONS → Change mutation weights" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="TRIAGE_CRASH → Analyze for exploitability" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="SCALE_UP/DOWN → Add/remove instances" /></ListItem>
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* AI Components */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          AI Intelligence Components
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#10b981", 0.3)}`, bgcolor: alpha("#10b981", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon /> Memory System
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Remembers past decisions and their outcomes across the campaign.
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Tracks success/failure rates by strategy" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Bayesian learning from outcomes" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Avoids repeating failed approaches" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Binary-type pattern matching" /></ListItem>
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#f59e0b", 0.3)}`, bgcolor: alpha("#f59e0b", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <PsychologyIcon /> Reasoning Chain
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Multi-step thinking with explicit reasoning trace.
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Analyzes coverage trends over time" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Considers binary characteristics" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Evaluates strategy effectiveness" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Logs reasoning for transparency" /></ListItem>
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#8b5cf6", 0.3)}`, bgcolor: alpha("#8b5cf6", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <ExploreIcon /> Exploration Balance
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Balances trying new strategies vs using what works.
              </Typography>
              <List dense>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Multi-armed bandit approach" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Adaptive exploration rate" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Confidence-based decisions" /></ListItem>
                <ListItem sx={{ py: 0 }}><ListItemText primary="Diminishing exploration over time" /></ListItem>
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Campaign Configuration */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Campaign Configuration & Duration Presets
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Choose a duration preset based on your use case. The AI makes decisions every 5 minutes, so longer campaigns allow for more strategic adjustments.
          </Typography>
          <Grid container spacing={2}>
            {[
              { name: "Quick", duration: "30 min", aiCalls: "~6", useCase: "Smoke testing, CI/CD integration", color: "#10b981" },
              { name: "Standard", duration: "2 hours", aiCalls: "~24", useCase: "Most security assessments", color: "#3b82f6" },
              { name: "Thorough", duration: "8 hours", aiCalls: "~96", useCase: "Deep security review, pre-release", color: "#f59e0b" },
              { name: "Deep", duration: "24 hours", aiCalls: "~288", useCase: "Critical targets, comprehensive audit", color: "#ef4444" },
            ].map((preset, i) => (
              <Grid item xs={12} sm={6} md={3} key={i}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `2px solid ${alpha(preset.color, 0.3)}`, bgcolor: alpha(preset.color, 0.05), height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: preset.color, mb: 0.5 }}>{preset.name}</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, mb: 1 }}>{preset.duration}</Typography>
                  <Chip label={`${preset.aiCalls} AI decisions`} size="small" sx={{ mb: 1, fontSize: "0.7rem" }} />
                  <Typography variant="caption" color="text.secondary" display="block">{preset.useCase}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* AFL++ Integration */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          AFL++ Fuzzing Engine
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#ef4444", 0.3)}`, bgcolor: alpha("#ef4444", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>AFL++ (Required)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Coverage-guided fuzzing with AFL++ for high-throughput test case generation. The AI dynamically
                configures AFL++ features based on campaign progress.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>AI-Controlled Features:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["Power schedule (fast/explore/exploit)", "CMPLOG magic bytes", "MOpt mutations", "Dictionary usage", "Deterministic stage", "Crash exploration"].map(t => <Chip key={t} label={t} size="small" sx={{ fontSize: "0.65rem" }} />)}
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#8b5cf6", 0.3)}`, bgcolor: alpha("#8b5cf6", 0.05), height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Execution Modes</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Support for instrumented and uninstrumented binaries with automatic mode detection.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Supported Modes:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["Source instrumented (fastest)", "QEMU mode (closed-source)", "FRIDA mode (dynamic)", "Unicorn emulation", "Nyx snapshot fuzzing"].map(t => <Chip key={t} label={t} size="small" sx={{ fontSize: "0.65rem" }} />)}
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Vulnerability Types */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Detectable Vulnerability Types
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "Stack Buffer Overflow", desc: "Stack corruption leading to RIP control", color: "#ef4444", severity: "Critical" },
            { name: "Heap Corruption", desc: "Heap metadata manipulation", color: "#f59e0b", severity: "Critical" },
            { name: "Use-After-Free", desc: "Dangling pointer exploitation", color: "#10b981", severity: "Critical" },
            { name: "Double Free", desc: "Heap state corruption", color: "#ec4899", severity: "Critical" },
            { name: "Integer Overflow", desc: "Arithmetic-induced memory issues", color: "#8b5cf6", severity: "High" },
            { name: "Format String", desc: "Printf-style vulnerabilities", color: "#06b6d4", severity: "High" },
            { name: "Null Pointer Deref", desc: "Null dereference crashes", color: "#3b82f6", severity: "Medium" },
            { name: "Out-of-Bounds Read", desc: "Information disclosure", color: "#a855f7", severity: "Medium" },
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

        {/* Crash Triage & Exploitability */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Crash Triage & Exploitability Assessment
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Every crash is automatically triaged and classified for exploitability using multiple analysis techniques:
          </Typography>
          <Grid container spacing={2}>
            {[
              { level: "Exploitable", color: "#ef4444", desc: "Direct control flow hijack, arbitrary write primitives" },
              { level: "Probably Exploitable", color: "#f59e0b", desc: "Likely exploitable with additional work, partial control" },
              { level: "Probably Not Exploitable", color: "#3b82f6", desc: "Denial of service, limited exploitation potential" },
              { level: "Not Exploitable", color: "#10b981", desc: "Non-security crash, null deref in safe context" },
            ].map((item, i) => (
              <Grid item xs={12} sm={6} md={3} key={i}>
                <Box sx={{ p: 2, borderRadius: 2, border: `2px solid ${alpha(item.color, 0.3)}`, bgcolor: alpha(item.color, 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.level}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Auto-Generated Reports */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          AI-Generated Campaign Reports
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#10b981", 0.3)}`, bgcolor: alpha("#10b981", 0.05) }}>
          <Typography variant="body2" sx={{ mb: 2 }}>
            When a campaign completes (or is stopped), an <strong>AI-generated comprehensive report</strong> is automatically created and saved.
            Reports include:
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem><ListItemIcon><DescriptionIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Executive Summary" secondary="Risk rating, key metrics, overall assessment" /></ListItem>
                <ListItem><ListItemIcon><BugReportIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Crash Analysis" secondary="Each crash with exploitability, impact, and recommendations" /></ListItem>
                <ListItem><ListItemIcon><TimelineIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="AI Decision History" secondary="What strategies were tried and why" /></ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem><ListItemIcon><AssessmentIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Strategy Effectiveness" secondary="Which approaches worked best" /></ListItem>
                <ListItem><ListItemIcon><SecurityIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Security Recommendations" secondary="Actionable remediation guidance" /></ListItem>
                <ListItem><ListItemIcon><DownloadIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                  <ListItemText primary="Export Options" secondary="Markdown, PDF, and Word formats" /></ListItem>
              </List>
            </Grid>
          </Grid>
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Export Formats:</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Markdown (.md)" sx={{ bgcolor: alpha("#10b981", 0.1) }} />
            <Chip label="PDF Document (.pdf)" sx={{ bgcolor: alpha("#ef4444", 0.1) }} />
            <Chip label="Microsoft Word (.docx)" sx={{ bgcolor: alpha("#3b82f6", 0.1) }} />
          </Box>
        </Paper>

        {/* Combined Analysis Integration */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Combined Analysis Integration
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
          <Typography variant="body2" sx={{ mb: 2 }}>
            All fuzzing campaign reports are available for <strong>Combined Analysis</strong>, allowing correlation with other security scan types:
          </Typography>
          <Grid container spacing={2}>
            {[
              { name: "Static Analysis", desc: "Correlate crashes with code-level vulnerabilities" },
              { name: "Reverse Engineering", desc: "Map crashes to decompiled functions" },
              { name: "Network Scans", desc: "Connect binary issues to network exposure" },
              { name: "Dynamic Scans", desc: "Cross-reference with runtime behavior" },
            ].map((item, i) => (
              <Grid item xs={12} sm={6} md={3} key={i}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>{item.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* When to Use */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          When to Use the Agentic Binary Fuzzer
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#10b981", 0.3)}`, bgcolor: alpha("#10b981", 0.05) }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Best For:</Typography>
              <List dense>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Long-running unattended fuzzing campaigns" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="When you lack fuzzing expertise" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Security audits requiring documentation" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="CI/CD pipeline integration" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Comprehensive vulnerability assessment" /></ListItem>
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, border: `2px solid ${alpha("#f59e0b", 0.3)}`, bgcolor: alpha("#f59e0b", 0.05) }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Limitations:</Typography>
              <List dense>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Won't make AFL++ execute faster" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Can't guarantee finding all bugs" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Requires AFL++ to be installed" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="AI decisions add ~5% overhead" /></ListItem>
                <ListItem sx={{ py: 0.5 }}><ListItemText primary="Not a replacement for expert analysis" /></ListItem>
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Access */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#10b981", 0.1), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <LinkIcon sx={{ color: "#10b981" }} /> Access Path
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>Dynamic Analysis Hub → Agentic Binary Fuzzer or <code>/dynamic/agentic-binary-fuzzer</code></Typography>
          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Button variant="contained" size="small" sx={{ bgcolor: "#10b981" }} onClick={() => navigate("/dynamic/agentic-binary-fuzzer")}>
              Open Agentic Binary Fuzzer
            </Button>
            <Button variant="outlined" size="small" onClick={() => navigate("/pentest/binary-fuzzer")}>
              Open Basic Binary Fuzzer
            </Button>
          </Box>
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
            Smart Detection analyzes fuzzing responses using <strong>25 signature families</strong> plus anomaly and
            differential analysis. It classifies findings by severity and confidence, summarizes risk at the session
            level, and provides remediation recommendations.
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
            Sessions allow you to <strong>save</strong>, <strong>restore</strong>, and <strong>manage</strong> Security Fuzzer
            campaigns. They capture configuration, results, and Smart Detection analysis for long-running tests or later
            comparison. Agentic Fuzzer reports are auto-saved separately when scans complete.
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
              title="Duplicate & Delete"
              description="Clone a session to branch new tests or delete completed runs cleanly."
              color="#8b5cf6"
              tips={["Duplicate configs", "Clean up old runs", "Keep history tidy"]}
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
                ["Payload Settings", "Payload lists per position, generators, and encoded variants"],
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
                  primary="Start with focused wordlists" 
                  secondary="Run targeted SQLi or XSS payloads before broader testing"
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
