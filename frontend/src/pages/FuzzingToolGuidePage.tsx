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
} from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
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
  { name: "Configuration", icon: <SettingsIcon /> },
  { name: "Payloads", icon: <CodeIcon /> },
  { name: "Results", icon: <BarChartIcon /> },
  { name: "Raw Responses", icon: <HttpIcon /> },
  { name: "Statistics", icon: <TimelineIcon /> },
  { name: "Errors", icon: <WarningIcon /> },
  { name: "Smart Detection", icon: <PsychologyIcon /> },
  { name: "Sessions", icon: <HistoryIcon /> },
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

  const pageContext = `This page is the VRAgent Fuzzing Tool Guide covering fuzzing capabilities, smart detection signatures for SQL injection/XSS/command injection/path traversal, session management, request configuration, response analysis, payload wordlists, and advanced fuzzing techniques.`;

  return (
    <LearnPageLayout pageTitle="Fuzzing Tool Guide" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
          <ArrowBackIcon />
        </IconButton>

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
              VRAgent Fuzzing Tool Guide
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Master the web application fuzzer with Smart Detection & Session Management
            </Typography>
          </Box>
        </Box>

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
            { value: "8", label: "Tabs" },
            { value: "50+", label: "Detection Signatures" },
            { value: "6", label: "Payload Modes" },
            { value: "∞", label: "Sessions Saved" },
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
          <Tab label="🚀 Getting Started" />
          <Tab label="⚙️ Configuration" />
          <Tab label="💣 Payload Modes" />
          <Tab label="🧠 Smart Detection" />
          <Tab label="📁 Sessions" />
          <Tab label="📊 Results & Stats" />
          <Tab label="💡 Pro Tips" />
        </Tabs>
      </Paper>

      {/* Tab 0: Getting Started */}
      <TabPanel value={tabValue} index={0}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          🚀 Getting Started with VRAgent Fuzzer
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
            What is VRAgent Fuzzer?
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            VRAgent's Fuzzing Tool is a powerful web application security testing tool that automatically sends malicious payloads 
            to your target endpoints to discover vulnerabilities. It features <strong>Smart Detection</strong> for automatic 
            vulnerability classification and <strong>Session Management</strong> to save and restore your testing sessions.
          </Typography>
        </Paper>

        {/* Interface Overview */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Interface Overview
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

        {/* Quick Start Guide */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Quick Start Guide
        </Typography>
        <Stepper orientation="vertical" sx={{ mb: 4 }}>
          <Step active>
            <StepLabel>
              <Typography sx={{ fontWeight: 600 }}>Configure Your Target</Typography>
            </StepLabel>
            <StepContent>
              <Typography variant="body2" color="text.secondary">
                Enter the target URL with the <code>FUZZ</code> placeholder where you want payloads injected. 
                Example: <code>https://target.com/search?q=FUZZ</code>
              </Typography>
            </StepContent>
          </Step>
          <Step active>
            <StepLabel>
              <Typography sx={{ fontWeight: 600 }}>Choose Payload Mode</Typography>
            </StepLabel>
            <StepContent>
              <Typography variant="body2" color="text.secondary">
                Select from Quick (SQLi, XSS), Comprehensive, Custom wordlist, or AI-Generated payloads.
              </Typography>
            </StepContent>
          </Step>
          <Step active>
            <StepLabel>
              <Typography sx={{ fontWeight: 600 }}>Set Request Options</Typography>
            </StepLabel>
            <StepContent>
              <Typography variant="body2" color="text.secondary">
                Configure HTTP method, headers, authentication, rate limiting, and timeouts.
              </Typography>
            </StepContent>
          </Step>
          <Step active>
            <StepLabel>
              <Typography sx={{ fontWeight: 600 }}>Start Fuzzing</Typography>
            </StepLabel>
            <StepContent>
              <Typography variant="body2" color="text.secondary">
                Click "Start Fuzzing" and monitor results in real-time across the Results, Statistics, and Smart Detection tabs.
              </Typography>
            </StepContent>
          </Step>
          <Step active>
            <StepLabel>
              <Typography sx={{ fontWeight: 600 }}>Analyze with Smart Detection</Typography>
            </StepLabel>
            <StepContent>
              <Typography variant="body2" color="text.secondary">
                Review automatically detected vulnerabilities, severity levels, and remediation recommendations.
              </Typography>
            </StepContent>
          </Step>
          <Step active>
            <StepLabel>
              <Typography sx={{ fontWeight: 600 }}>Save Session</Typography>
            </StepLabel>
            <StepContent>
              <Typography variant="body2" color="text.secondary">
                Save your session for later analysis or to continue testing. Sessions include all results and configuration.
              </Typography>
            </StepContent>
          </Step>
        </Stepper>

        {/* Access Path */}
        <Paper
          sx={{
            p: 3,
            borderRadius: 3,
            bgcolor: alpha(theme.palette.info.main, 0.1),
            border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <LinkIcon sx={{ color: theme.palette.info.main }} />
            How to Access
          </Typography>
          <Typography variant="body2">
            Navigate to <strong>Network Analysis Hub → API Fuzzer</strong> or go directly to{" "}
            <code style={{ background: alpha(theme.palette.info.main, 0.1), padding: "2px 8px", borderRadius: 4 }}>
              /network/fuzzer
            </code>
          </Typography>
        </Paper>
      </TabPanel>

      {/* Tab 1: Configuration */}
      <TabPanel value={tabValue} index={1}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          ⚙️ Configuration Options
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <FeatureCard
              icon={<HttpIcon sx={{ fontSize: 32 }} />}
              title="Target URL"
              description="The URL to fuzz. Use FUZZ as a placeholder where payloads will be inserted. Supports URL parameters, path segments, and request bodies."
              color="#3b82f6"
              tips={["Use FUZZ placeholder", "Multiple positions supported", "URL encode special chars"]}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <FeatureCard
              icon={<CodeIcon sx={{ fontSize: 32 }} />}
              title="HTTP Method"
              description="Choose the HTTP method: GET, POST, PUT, DELETE, PATCH. POST requests can include a body with FUZZ placeholder."
              color="#8b5cf6"
              tips={["GET for URL params", "POST for body fuzzing", "DELETE for destructive tests"]}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <FeatureCard
              icon={<LocalOfferIcon sx={{ fontSize: 32 }} />}
              title="Custom Headers"
              description="Add authentication tokens, cookies, or custom headers. Essential for testing authenticated endpoints."
              color="#10b981"
              tips={["Authorization: Bearer", "Cookie: session=", "X-Custom-Header"]}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <FeatureCard
              icon={<SpeedIcon sx={{ fontSize: 32 }} />}
              title="Rate Limiting"
              description="Control request rate to avoid overwhelming the target or triggering rate limits. Set concurrent requests and delays."
              color="#f59e0b"
              tips={["Concurrent: 1-10", "Delay: 0-1000ms", "Timeout: 5-60s"]}
            />
          </Grid>
        </Grid>

        {/* Advanced Options */}
        <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
          Advanced Options
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3 }}>
          <List>
            <ListItem>
              <ListItemIcon><FilterAltIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText
                primary="Response Filtering"
                secondary="Filter results by status code, response size, or content patterns to reduce noise"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><SecurityIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText
                primary="SSL/TLS Options"
                secondary="Verify SSL certificates or ignore for self-signed certs during testing"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><TimelineIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText
                primary="Follow Redirects"
                secondary="Choose whether to follow HTTP redirects (301, 302, etc.)"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><StorageIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText
                primary="Request Body"
                secondary="For POST/PUT requests, define the body with FUZZ placeholder for injection points"
              />
            </ListItem>
          </List>
        </Paper>
      </TabPanel>

      {/* Tab 2: Payload Modes */}
      <TabPanel value={tabValue} index={2}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          💣 Payload Modes
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                borderRadius: 3,
                border: `2px solid ${alpha("#ef4444", 0.3)}`,
                bgcolor: alpha("#ef4444", 0.05),
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
                🔥 Quick - SQL Injection
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                100+ SQL injection payloads covering error-based, UNION-based, blind, and time-based techniques.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["' OR '1'='1", "'; DROP TABLE--", "1 UNION SELECT", "SLEEP(5)"].map((p) => (
                  <Chip key={p} label={p} size="small" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }} />
                ))}
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                borderRadius: 3,
                border: `2px solid ${alpha("#f59e0b", 0.3)}`,
                bgcolor: alpha("#f59e0b", 0.05),
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>
                ⚡ Quick - XSS
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                100+ XSS payloads including reflected, stored, DOM-based, and filter bypass techniques.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["<script>alert(1)</script>", "<img onerror=alert(1)>", "javascript:alert(1)", "<svg onload=alert(1)>"].map((p) => (
                  <Chip key={p} label={p} size="small" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }} />
                ))}
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                borderRadius: 3,
                border: `2px solid ${alpha("#8b5cf6", 0.3)}`,
                bgcolor: alpha("#8b5cf6", 0.05),
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>
                🎯 Comprehensive
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                500+ payloads covering SQLi, XSS, Command Injection, Path Traversal, SSTI, XXE, and more.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["All attack types", "Encoding variations", "Filter bypasses", "Edge cases"].map((p) => (
                  <Chip key={p} label={p} size="small" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }} />
                ))}
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                borderRadius: 3,
                border: `2px solid ${alpha("#10b981", 0.3)}`,
                bgcolor: alpha("#10b981", 0.05),
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                📝 Custom Wordlist
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Upload your own wordlist or paste payloads directly. Perfect for specific attack scenarios.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["One payload per line", "File upload", "Paste directly", "Any format"].map((p) => (
                  <Chip key={p} label={p} size="small" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }} />
                ))}
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                borderRadius: 3,
                border: `2px solid ${alpha("#06b6d4", 0.3)}`,
                bgcolor: alpha("#06b6d4", 0.05),
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>
                🤖 AI-Generated
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Let AI generate context-aware payloads based on your target. Intelligent mutation and bypass techniques.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["Context-aware", "Adaptive mutations", "Bypass generation", "Smart encoding"].map((p) => (
                  <Chip key={p} label={p} size="small" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }} />
                ))}
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                borderRadius: 3,
                border: `2px solid ${alpha("#ec4899", 0.3)}`,
                bgcolor: alpha("#ec4899", 0.05),
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>
                🔢 Number Range
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Generate numeric sequences for IDOR testing, ID enumeration, and boundary testing.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {["Start: 1", "End: 1000", "Step: 1", "IDOR testing"].map((p) => (
                  <Chip key={p} label={p} size="small" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }} />
                ))}
              </Box>
            </Paper>
          </Grid>
        </Grid>
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

      {/* Tab 5: Results & Stats */}
      <TabPanel value={tabValue} index={5}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📊 Understanding Results & Statistics
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <BarChartIcon sx={{ color: "#3b82f6" }} />
                Results Tab
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText primary="Payload Sent" secondary="The exact payload that was sent to the target" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Status Code" secondary="HTTP response code (200, 404, 500, etc.)" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Response Size" secondary="Size of the response body in bytes" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Response Time" secondary="Time taken for the server to respond" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Anomaly Indicator" secondary="Visual highlight for interesting responses" />
                </ListItem>
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TimelineIcon sx={{ color: "#8b5cf6" }} />
                Statistics Tab
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText primary="Total Requests" secondary="Number of payloads sent" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Success Rate" secondary="Percentage of 2xx/3xx responses" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Error Rate" secondary="Percentage of 4xx/5xx responses" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Avg Response Time" secondary="Mean response time across all requests" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Status Distribution" secondary="Chart showing response code breakdown" />
                </ListItem>
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Interpreting Results */}
        <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
          Interpreting Results
        </Typography>
        <Grid container spacing={2}>
          {[
            { code: "200", meaning: "Success - Check response for data leakage or injection evidence", color: "#10b981" },
            { code: "302", meaning: "Redirect - Could indicate auth bypass or open redirect", color: "#3b82f6" },
            { code: "403", meaning: "Forbidden - Potential for bypass testing", color: "#f59e0b" },
            { code: "500", meaning: "Server Error - Often indicates successful injection or crash", color: "#ef4444" },
            { code: "Different Size", meaning: "Response size varies - Compare payloads for behavior changes", color: "#8b5cf6" },
            { code: "Slow Response", meaning: "Time-based detection - Could indicate blind injection", color: "#ec4899" },
          ].map((item, i) => (
            <Grid item xs={12} sm={6} md={4} key={i}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha(item.color, 0.3)}`,
                  bgcolor: alpha(item.color, 0.05),
                }}
              >
                <Chip
                  label={item.code}
                  size="small"
                  sx={{ bgcolor: item.color, color: "white", fontWeight: 700, mb: 1 }}
                />
                <Typography variant="body2" sx={{ lineHeight: 1.5 }}>
                  {item.meaning}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Tab 6: Pro Tips */}
      <TabPanel value={tabValue} index={6}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          💡 Pro Tips & Best Practices
        </Typography>

        <Accordion defaultExpanded sx={{ borderRadius: "12px !important", mb: 2, "&:before": { display: "none" } }}>
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
              🔍 Analysis Techniques
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <List dense>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Look for response size anomalies" 
                  secondary="Significantly larger or smaller responses often indicate issues"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Check timing differences" 
                  secondary="Slow responses may indicate time-based blind injection"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Read Raw Responses carefully" 
                  secondary="Error messages often reveal database type, stack traces, or paths"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main" }} /></ListItemIcon>
                <ListItemText 
                  primary="Trust Smart Detection, verify manually" 
                  secondary="Use Smart Detection for triage, confirm findings in Raw Responses"
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
                  primary="Test in staging first" 
                  secondary="Avoid production systems when possible"
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

        {/* Workflow Diagram */}
        <Paper
          sx={{
            p: 3,
            mt: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
            border: `1px solid ${alpha("#f97316", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            Recommended Workflow
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, justifyContent: "center" }}>
            {[
              "Configure Target",
              "Quick SQLi Test",
              "Quick XSS Test",
              "Check Smart Detection",
              "Review Anomalies",
              "Comprehensive Scan",
              "Analyze Results",
              "Save Session",
            ].map((step, i) => (
              <Chip
                key={step}
                label={`${i + 1}. ${step}`}
                sx={{
                  bgcolor: alpha("#f97316", 0.1 + i * 0.05),
                  color: "#f97316",
                  fontWeight: 600,
                  border: `1px solid ${alpha("#f97316", 0.3)}`,
                }}
              />
            ))}
          </Box>
        </Paper>
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
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Open the Fuzzing Tool and put your knowledge into practice!
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Chip
            label="Back to Learning Hub"
            clickable
            onClick={() => navigate("/learn")}
            sx={{ fontWeight: 600 }}
          />
          <Chip
            label="Open Fuzzing Tool →"
            clickable
            onClick={() => navigate("/network/fuzzer")}
            sx={{ bgcolor: "#f97316", color: "white", fontWeight: 600, "&:hover": { bgcolor: "#ea580c" } }}
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
