import React, { useState } from "react";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  Card,
  CardContent,
  alpha,
  Divider,
  Alert,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import AndroidIcon from "@mui/icons-material/Android";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import LockIcon from "@mui/icons-material/Lock";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import VisibilityIcon from "@mui/icons-material/Visibility";
import LinkIcon from "@mui/icons-material/Link";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import SearchIcon from "@mui/icons-material/Search";
import SchoolIcon from "@mui/icons-material/School";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import ChatIcon from "@mui/icons-material/Chat";
import MapIcon from "@mui/icons-material/Map";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import DownloadIcon from "@mui/icons-material/Download";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

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

const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({
  code,
  language = "bash",
  title,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        bgcolor: "#0d1117",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(34, 197, 94, 0.2)",
        overflow: "hidden",
      }}
    >
      {title && (
        <Box sx={{ px: 2, py: 1, bgcolor: "rgba(34, 197, 94, 0.1)", borderBottom: "1px solid rgba(34, 197, 94, 0.2)" }}>
          <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 600 }}>{title}</Typography>
        </Box>
      )}
      <Box sx={{ position: "absolute", top: title ? 40 : 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e", fontSize: "0.7rem" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: copied ? "#22c55e" : "#888" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          pt: 3,
          overflow: "auto",
          fontFamily: "'Fira Code', 'Consolas', monospace",
          fontSize: "0.8rem",
          color: "#e6edf3",
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const ApkAnalysisGuidePage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const dangerousPermissions = [
    { permission: "android.permission.READ_SMS", risk: "Critical", description: "Read SMS messages - can intercept 2FA codes" },
    { permission: "android.permission.SEND_SMS", risk: "Critical", description: "Send SMS - premium SMS fraud, data exfiltration" },
    { permission: "android.permission.READ_CONTACTS", risk: "High", description: "Access contacts - social engineering, spam" },
    { permission: "android.permission.READ_CALL_LOG", risk: "High", description: "Call history - behavioral profiling" },
    { permission: "android.permission.CAMERA", risk: "High", description: "Camera access - surveillance, spying" },
    { permission: "android.permission.RECORD_AUDIO", risk: "High", description: "Microphone - eavesdropping" },
    { permission: "android.permission.ACCESS_FINE_LOCATION", risk: "High", description: "GPS location - tracking, stalking" },
    { permission: "android.permission.READ_EXTERNAL_STORAGE", risk: "Medium", description: "Storage access - data theft" },
    { permission: "android.permission.INTERNET", risk: "Low", description: "Network access - required for most apps" },
  ];

  const attackVectors = [
    { vector: "Exported Activities", description: "Launch internal screens directly, bypass auth", adb: "adb shell am start -n com.app/.SecretActivity" },
    { vector: "Content Providers", description: "Query app databases, read sensitive data", adb: "adb shell content query --uri content://com.app/users" },
    { vector: "Broadcast Receivers", description: "Trigger app actions, inject malicious intents", adb: "adb shell am broadcast -a com.app.ACTION" },
    { vector: "Deep Links", description: "Open via URL, potential for XSS/injection", adb: "adb shell am start -d 'myapp://path?param=value'" },
  ];

  const obfuscationTools = [
    { tool: "ProGuard/R8", indicators: "Single-letter class names (a.b.c)", level: "Light" },
    { tool: "DexGuard", indicators: "String encryption, class encryption, anti-tampering", level: "Heavy" },
    { tool: "Allatori", indicators: "Control flow obfuscation, watermarking", level: "Medium" },
    { tool: "Arxan/DexProtector", indicators: "Native protection, VM-based obfuscation", level: "Extreme" },
  ];

  const vrAgentFeatures = [
    { feature: "Unified APK Scan", description: "One-click comprehensive analysis with real-time progress tracking", icon: <PlayArrowIcon />, color: "#22c55e" },
    { feature: "JADX Decompilation", description: "Full Java source code decompilation with syntax highlighting", icon: <CodeIcon />, color: "#3b82f6" },
    { feature: "AI Chat", description: "Ask questions about the APK and get intelligent answers", icon: <ChatIcon />, color: "#8b5cf6" },
    { feature: "AI Code Explain", description: "Get AI explanations of any decompiled method or class", icon: <AutoAwesomeIcon />, color: "#a855f7" },
    { feature: "AI Vulnerability Scan", description: "Deep AI-powered security analysis of decompiled code", icon: <BugReportIcon />, color: "#ef4444" },
    { feature: "Threat Modeling", description: "Automated STRIDE-based threat model generation", icon: <SecurityIcon />, color: "#f59e0b" },
    { feature: "Exploit Suggestions", description: "AI-generated exploitation paths and PoC code", icon: <BugReportIcon />, color: "#dc2626" },
    { feature: "Analysis Walkthrough", description: "Step-by-step guided analysis with AI explanations", icon: <SchoolIcon />, color: "#06b6d4" },
  ];

  const codeAnalysisFeatures = [
    { feature: "Data Flow Analysis", description: "Track how sensitive data flows through the app", icon: <AccountTreeIcon />, color: "#3b82f6" },
    { feature: "Call Graph", description: "Visualize method call relationships", icon: <AccountTreeIcon />, color: "#8b5cf6" },
    { feature: "Cross-References", description: "Find all usages of methods, fields, and classes", icon: <LinkIcon />, color: "#06b6d4" },
    { feature: "Smart Search", description: "AI-powered natural language code search", icon: <SearchIcon />, color: "#22c55e" },
    { feature: "Symbol Lookup", description: "Quick lookup of classes, methods, and fields", icon: <SearchIcon />, color: "#f59e0b" },
    { feature: "Smali View", description: "View raw Dalvik bytecode for advanced analysis", icon: <CodeIcon />, color: "#ef4444" },
  ];

  const securityFeatures = [
    { feature: "Library CVE Scan", description: "Detect vulnerable libraries with CVE database lookup", icon: <BugReportIcon />, color: "#ef4444" },
    { feature: "Enhanced Security Scan", description: "Comprehensive security assessment with 50+ checks", icon: <SecurityIcon />, color: "#f59e0b" },
    { feature: "Crypto Audit", description: "Analyze cryptographic implementations for weaknesses", icon: <VpnKeyIcon />, color: "#8b5cf6" },
    { feature: "Permission Analysis", description: "Deep dive into requested permissions and their risks", icon: <LockIcon />, color: "#3b82f6" },
    { feature: "Network Endpoints", description: "Extract and analyze all network URLs and APIs", icon: <NetworkCheckIcon />, color: "#06b6d4" },
    { feature: "Attack Surface Map", description: "Visual map of all exploitable entry points", icon: <MapIcon />, color: "#22c55e" },
  ];

  const visualizationFeatures = [
    { feature: "Manifest Visualization", description: "Interactive tree view of AndroidManifest.xml", icon: <MapIcon />, color: "#22c55e" },
    { feature: "Component Map", description: "Visual diagram of Activities, Services, and Receivers", icon: <AccountTreeIcon />, color: "#3b82f6" },
    { feature: "Dependency Graph", description: "Library and package dependency visualization", icon: <AccountTreeIcon />, color: "#8b5cf6" },
    { feature: "AI Diagrams", description: "Auto-generated architecture and flow diagrams", icon: <AutoAwesomeIcon />, color: "#f59e0b" },
  ];

  const quickStartSteps = [
    { label: "Upload Your APK", description: "Navigate to Reverse Engineering Hub and select 'APK Analysis'. Upload any .apk file." },
    { label: "Run Unified Scan", description: "Click 'Start Unified Scan' for comprehensive analysis with real-time progress tracking." },
    { label: "Explore 5-Tab Results", description: "Review results in five tabs: What Does This APK Do?, Security Findings, Architecture Diagram, Attack Surface Map, and Decompiled Classes." },
    { label: "Browse Decompiled Code", description: "Navigate the package tree in the Decompiled Classes tab, search for suspicious patterns, and click any class to view its source." },
    { label: "Use AI Analysis", description: "Use 'Explain with AI' for code explanations or run 'Full Security Scan' for comprehensive AI-powered vulnerability detection." },
    { label: "Export Reports", description: "Generate Markdown, PDF, or DOCX reports with all findings for documentation." },
  ];

  const pageContext = `This page is the VRAgent APK Analysis Guide covering Android security assessment, APK file structure, dangerous permissions analysis, exported components attack vectors, deep link security, obfuscation detection, JADX decompilation, AI-powered vulnerability scanning, and Android reverse engineering tools.`;

  return (
    <LearnPageLayout pageTitle="APK Analysis Guide" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
      <Container maxWidth="lg">
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ mb: 2, color: "#22c55e" }}
          >
            Back to Learning Hub
          </Button>
          
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1) }}>
              <AndroidIcon sx={{ fontSize: 48, color: "#22c55e" }} />
            </Box>
            <Box>
              <Typography variant="h3" sx={{ fontWeight: 800, color: "white" }}>
                APK Analysis Guide
              </Typography>
              <Typography variant="h6" sx={{ color: "grey.400" }}>
                Android Security Assessment & Reverse Engineering
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
            <Alert severity="info" sx={{ bgcolor: alpha("#22c55e", 0.1), flex: 1 }}>
              <Typography variant="body2">
                <strong>VRAgent's APK Analyzer</strong> provides 40+ analysis capabilities including JADX decompilation,
                AI-powered vulnerability detection, threat modeling, and comprehensive security auditing.
              </Typography>
            </Alert>
            <Button
              variant="contained"
              size="large"
              startIcon={<AndroidIcon />}
              onClick={() => navigate("/reverse")}
              sx={{ bgcolor: "#22c55e", "&:hover": { bgcolor: "#16a34a" }, alignSelf: "center", whiteSpace: "nowrap" }}
            >
              Launch APK Analyzer
            </Button>
          </Box>
        </Box>

        {/* Tabs */}
        <Paper sx={{ bgcolor: "#111118", borderRadius: 3, mb: 3 }}>
          <Tabs
            value={tabValue}
            onChange={handleTabChange}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: 1,
              borderColor: "divider",
              "& .MuiTab-root": { color: "grey.400", fontWeight: 600 },
              "& .Mui-selected": { color: "#22c55e" },
              "& .MuiTabs-indicator": { bgcolor: "#22c55e" },
            }}
          >
            <Tab icon={<SchoolIcon />} label="Getting Started" />
            <Tab icon={<AndroidIcon />} label="APK Structure" />
            <Tab icon={<LockIcon />} label="Permissions" />
            <Tab icon={<BugReportIcon />} label="Attack Surface" />
            <Tab icon={<CodeIcon />} label="Obfuscation" />
            <Tab icon={<BuildIcon />} label="VRAgent Tools" />
            <Tab icon={<TipsAndUpdatesIcon />} label="Tips & Tricks" />
          </Tabs>
        </Paper>

        {/* Tab 0: Getting Started */}
        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🎯 What is APK Analysis?
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  APK analysis is the process of examining Android application packages to understand their behavior,
                  find security vulnerabilities, and identify malicious functionality. APKs contain compiled Dalvik
                  bytecode that can be decompiled back to Java source code for analysis.
                </Typography>
                <Grid container spacing={2} sx={{ mt: 2 }}>
                  {[
                    { title: "Security Auditing", desc: "Find vulnerabilities before deployment", icon: "🔍" },
                    { title: "Malware Analysis", desc: "Understand what suspicious apps do", icon: "🦠" },
                    { title: "Penetration Testing", desc: "Test Android app security", icon: "🛡️" },
                    { title: "Privacy Research", desc: "Discover what data apps collect", icon: "👁️" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={3} key={item.title}>
                      <Card sx={{ bgcolor: alpha("#22c55e", 0.05), border: "1px solid rgba(34, 197, 94, 0.2)", height: "100%" }}>
                        <CardContent sx={{ textAlign: "center" }}>
                          <Typography sx={{ fontSize: 32, mb: 1 }}>{item.icon}</Typography>
                          <Typography sx={{ color: "white", fontWeight: 600, mb: 0.5 }}>{item.title}</Typography>
                          <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 3, fontWeight: 700 }}>
                  🚀 Quick Start with VRAgent
                </Typography>
                <Stepper orientation="vertical" sx={{ 
                  "& .MuiStepLabel-label": { color: "grey.300" },
                  "& .MuiStepLabel-label.Mui-active": { color: "#22c55e" },
                  "& .MuiStepIcon-root": { color: "grey.700" },
                  "& .MuiStepIcon-root.Mui-active": { color: "#22c55e" },
                  "& .MuiStepIcon-root.Mui-completed": { color: "#22c55e" },
                }}>
                  {quickStartSteps.map((step) => (
                    <Step key={step.label} active expanded>
                      <StepLabel>
                        <Typography sx={{ color: "white", fontWeight: 600 }}>{step.label}</Typography>
                      </StepLabel>
                      <StepContent>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>{step.description}</Typography>
                      </StepContent>
                    </Step>
                  ))}
                </Stepper>

                <Box sx={{ mt: 3, textAlign: "center" }}>
                  <Button
                    variant="contained"
                    size="large"
                    startIcon={<PlayArrowIcon />}
                    onClick={() => navigate("/reverse")}
                    sx={{ bgcolor: "#22c55e", "&:hover": { bgcolor: "#16a34a" }, px: 4, py: 1.5 }}
                  >
                    Launch APK Analyzer Now
                  </Button>
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 1: APK Structure */}
        <TabPanel value={tabValue} index={1}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  📦 APK File Structure
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  An APK is a ZIP archive containing:
                </Typography>
                <List dense>
                  {[
                    { file: "AndroidManifest.xml", desc: "App metadata, permissions, components" },
                    { file: "classes.dex", desc: "Compiled Dalvik bytecode (Java → DEX)" },
                    { file: "classes2.dex...", desc: "Additional DEX files (multidex apps)" },
                    { file: "resources.arsc", desc: "Compiled resources table" },
                    { file: "res/", desc: "Layouts, strings, drawables, images" },
                    { file: "lib/", desc: "Native libraries (.so) per architecture" },
                    { file: "META-INF/", desc: "Signing certificates, manifest" },
                    { file: "assets/", desc: "Raw files (configs, databases, HTML)" },
                    { file: "kotlin/", desc: "Kotlin metadata (if Kotlin app)" },
                  ].map((item) => (
                    <ListItem key={item.file} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        <StorageIcon sx={{ color: "#22c55e", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Typography sx={{ color: "#22c55e", fontFamily: "monospace", fontSize: "0.85rem" }}>{item.file}</Typography>}
                        secondary={<Typography sx={{ color: "grey.500", fontSize: "0.75rem" }}>{item.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🔐 APK Signing
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Android uses multiple signature schemes:
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Scheme</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Android</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Security</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {[
                        { scheme: "v1 (JAR)", android: "All", security: "Weak - ZIP comment bypass" },
                        { scheme: "v2", android: "7.0+", security: "Strong - whole-file signing" },
                        { scheme: "v3", android: "9.0+", security: "Key rotation support" },
                        { scheme: "v4", android: "11.0+", security: "Streaming install" },
                      ].map((row) => (
                        <TableRow key={row.scheme}>
                          <TableCell sx={{ color: "white" }}>{row.scheme}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.android}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.security}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <CodeBlock
                title="Manual APK Analysis Commands"
                language="bash"
                code={`# Unzip APK contents
unzip app.apk -d extracted/

# Decode with apktool (preserves binary XML)
apktool d app.apk -o decoded/

# Decompile to Java with jadx
jadx app.apk -d jadx_output/

# View certificate info
keytool -printcert -jarfile app.apk

# List permissions
aapt dump permissions app.apk

# Extract strings
strings classes.dex | grep -E "http|api|key|password"`}
              />
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 2: Permissions */}
        <TabPanel value={tabValue} index={2}>
          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 3 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              ⚠️ Dangerous Permissions Reference
            </Typography>
            <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha("#f59e0b", 0.1) }}>
              These permissions require user approval and can access sensitive data. Excessive permissions may indicate malicious intent or poor security practices.
            </Alert>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Permission</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Risk</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Security Impact</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dangerousPermissions.map((perm) => (
                    <TableRow key={perm.permission}>
                      <TableCell sx={{ color: "white", fontFamily: "monospace", fontSize: "0.75rem" }}>{perm.permission}</TableCell>
                      <TableCell>
                        <Chip
                          label={perm.risk}
                          size="small"
                          sx={{
                            bgcolor: perm.risk === "Critical" ? alpha("#ef4444", 0.2) : perm.risk === "High" ? alpha("#f59e0b", 0.2) : perm.risk === "Medium" ? alpha("#eab308", 0.2) : alpha("#22c55e", 0.2),
                            color: perm.risk === "Critical" ? "#ef4444" : perm.risk === "High" ? "#f59e0b" : perm.risk === "Medium" ? "#eab308" : "#22c55e",
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ color: "grey.400", fontSize: "0.8rem" }}>{perm.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🔍 Permission Analysis Tips
            </Typography>
            <Grid container spacing={2}>
              {[
                { title: "Over-Permission", desc: "App requests more permissions than needed for its stated purpose", icon: <WarningIcon sx={{ color: "#f59e0b" }} /> },
                { title: "Signature Permissions", desc: "Custom permissions shared between apps from same developer", icon: <LockIcon sx={{ color: "#22c55e" }} /> },
                { title: "Runtime vs Install", desc: "Dangerous permissions must be granted at runtime (Android 6+)", icon: <SecurityIcon sx={{ color: "#3b82f6" }} /> },
                { title: "Protection Level", desc: "Check if permissions are 'normal', 'dangerous', or 'signature'", icon: <VpnKeyIcon sx={{ color: "#8b5cf6" }} /> },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.title}>
                  <Card sx={{ bgcolor: "#1a1a24", height: "100%" }}>
                    <CardContent>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        {item.icon}
                        <Typography sx={{ color: "white", fontWeight: 600 }}>{item.title}</Typography>
                      </Box>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </TabPanel>

        {/* Tab 3: Attack Surface */}
        <TabPanel value={tabValue} index={3}>
          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 3 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🎯 Exported Component Attack Vectors
            </Typography>
            <Alert severity="error" sx={{ mb: 2, bgcolor: alpha("#ef4444", 0.1) }}>
              Exported components with <code>android:exported="true"</code> or intent filters can be invoked by any app!
            </Alert>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Vector</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Risk</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>ADB Test Command</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {attackVectors.map((av) => (
                    <TableRow key={av.vector}>
                      <TableCell sx={{ color: "white", fontWeight: 600 }}>{av.vector}</TableCell>
                      <TableCell sx={{ color: "grey.400", fontSize: "0.8rem" }}>{av.description}</TableCell>
                      <TableCell sx={{ color: "#22c55e", fontFamily: "monospace", fontSize: "0.7rem" }}>{av.adb}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 3 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🔗 Deep Link Security
            </Typography>
            <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
              Deep links (custom URL schemes and App Links) can be exploited for:
            </Typography>
            <List dense>
              {[
                "Authentication bypass - redirect OAuth tokens to attacker-controlled app",
                "XSS injection - if WebView renders URL parameters without sanitization",
                "Intent injection - manipulate internal app state via crafted URIs",
                "Data exfiltration - leak sensitive parameters through URL referrer",
                "Link hijacking - claim another app's deep links (App Link verification bypass)",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon><BugReportIcon sx={{ color: "#ef4444", fontSize: 18 }} /></ListItemIcon>
                  <ListItemText primary={<Typography sx={{ color: "grey.300", fontSize: "0.85rem" }}>{item}</Typography>} />
                </ListItem>
              ))}
            </List>
            <CodeBlock
              title="Test Deep Links"
              language="bash"
              code={`# Find deep links in manifest
grep -E "scheme|host|pathPrefix|pathPattern" AndroidManifest.xml

# Test deep link with ADB
adb shell am start -a android.intent.action.VIEW \\
  -d "myapp://login?redirect=http://evil.com"

# Test with malicious payload
adb shell am start -a android.intent.action.VIEW \\
  -d "myapp://webview?url=javascript:alert(document.cookie)"`}
            />
          </Paper>

          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🔥 Common Android Vulnerabilities
            </Typography>
            <Grid container spacing={2}>
              {[
                { vuln: "Insecure Data Storage", desc: "Sensitive data in SharedPreferences, SQLite, or external storage without encryption", severity: "High" },
                { vuln: "Insecure Communication", desc: "Missing SSL pinning, cleartext traffic, trusting all certificates", severity: "Critical" },
                { vuln: "Improper Platform Usage", desc: "Misconfigured permissions, exported components, insecure IPC", severity: "High" },
                { vuln: "Insecure Authentication", desc: "Weak biometric implementation, credential storage, session management", severity: "Critical" },
                { vuln: "Insufficient Cryptography", desc: "Weak algorithms (MD5, SHA1), hardcoded keys, ECB mode", severity: "High" },
                { vuln: "Client Code Quality", desc: "Buffer overflows in native code, format string bugs", severity: "Medium" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.vuln}>
                  <Card sx={{ bgcolor: "#1a1a24" }}>
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                        <Typography sx={{ color: "white", fontWeight: 600 }}>{item.vuln}</Typography>
                        <Chip
                          label={item.severity}
                          size="small"
                          sx={{
                            bgcolor: item.severity === "Critical" ? alpha("#ef4444", 0.2) : item.severity === "High" ? alpha("#f59e0b", 0.2) : alpha("#eab308", 0.2),
                            color: item.severity === "Critical" ? "#ef4444" : item.severity === "High" ? "#f59e0b" : "#eab308",
                          }}
                        />
                      </Box>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </TabPanel>

        {/* Tab 4: Obfuscation */}
        <TabPanel value={tabValue} index={4}>
          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 3 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🛡️ Obfuscation Detection
            </Typography>
            <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
              Obfuscation makes reverse engineering harder but doesn't stop determined analysts.
              VRAgent automatically detects obfuscation and suggests deobfuscation strategies.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Tool</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Indicators</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Difficulty</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {obfuscationTools.map((tool) => (
                    <TableRow key={tool.tool}>
                      <TableCell sx={{ color: "white", fontWeight: 600 }}>{tool.tool}</TableCell>
                      <TableCell sx={{ color: "grey.400", fontSize: "0.8rem" }}>{tool.indicators}</TableCell>
                      <TableCell>
                        <Chip
                          label={tool.level}
                          size="small"
                          sx={{
                            bgcolor: tool.level === "Extreme" ? alpha("#ef4444", 0.2) : tool.level === "Heavy" ? alpha("#f59e0b", 0.2) : tool.level === "Medium" ? alpha("#eab308", 0.2) : alpha("#22c55e", 0.2),
                            color: tool.level === "Extreme" ? "#ef4444" : tool.level === "Heavy" ? "#f59e0b" : tool.level === "Medium" ? "#eab308" : "#22c55e",
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🧪 Deobfuscation Strategies
            </Typography>
            <Grid container spacing={2}>
              {[
                { title: "Static Analysis", desc: "Use jadx --deobf flag for automatic renaming based on usage patterns", icon: "📝" },
                { title: "Dynamic Analysis", desc: "Hook methods with Frida to observe runtime behavior", icon: "🔬" },
                { title: "String Decryption", desc: "Find decryption method and call it with encrypted strings", icon: "🔓" },
                { title: "Mapping Files", desc: "If you have mapping.txt, use proguard-retrace to restore names", icon: "🗺️" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Card sx={{ bgcolor: "#1a1a24" }}>
                    <CardContent>
                      <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>{item.icon} {item.title}</Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
            <CodeBlock
              title="Frida String Decryption Hook"
              language="javascript"
              code={`// Hook string constructor to catch decrypted strings
Java.perform(function() {
  var StringClass = Java.use('java.lang.String');
  
  // Hook byte[] constructor
  StringClass.$init.overload('[B').implementation = function(bytes) {
    var result = this.$init(bytes);
    console.log('[Decrypted String] ' + result);
    return result;
  };
  
  // Hook the app's decrypt method directly
  var Crypto = Java.use('com.app.utils.CryptoHelper');
  Crypto.decrypt.implementation = function(encrypted) {
    var decrypted = this.decrypt(encrypted);
    console.log('[Decrypt] ' + encrypted + ' -> ' + decrypted);
    return decrypted;
  };
});`}
            />
          </Paper>
        </TabPanel>

        {/* Tab 5: VRAgent Tools */}
        <TabPanel value={tabValue} index={5}>
          <Alert severity="info" sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.1) }}>
            VRAgent provides <strong>40+ APK analysis capabilities</strong> powered by JADX decompilation and AI.
            All tools are accessible from the Reverse Engineering Hub.
          </Alert>
          
          {/* 5-Tab Unified Results Interface */}
          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 4 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              📊 Unified Results Interface (5 Tabs)
            </Typography>
            <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
              After running a Unified Scan, results are presented in an intuitive 5-tab interface:
            </Typography>
            <Grid container spacing={2}>
              {[
                { tab: "1. What Does This APK Do?", desc: "AI-generated summary of the app's purpose, features, and behavior", color: "#22c55e", icon: "📱" },
                { tab: "2. Security Findings", desc: "All detected vulnerabilities with severity ratings and remediation guidance", color: "#ef4444", icon: "🔒" },
                { tab: "3. Architecture Diagram", desc: "Auto-generated Mermaid diagram showing app components and relationships", color: "#3b82f6", icon: "🏗️" },
                { tab: "4. Attack Surface Map", desc: "Visual attack tree showing exported components and entry points", color: "#8b5cf6", icon: "🎯" },
                { tab: "5. Decompiled Classes", desc: "Browse JADX-decompiled Java source code with package tree navigation", color: "#f59e0b", icon: "📂" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.tab}>
                  <Box sx={{ p: 2, bgcolor: alpha(item.color, 0.1), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.3)}`, height: "100%" }}>
                    <Typography sx={{ color: item.color, fontWeight: 700, mb: 0.5 }}>{item.icon} {item.tab}</Typography>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
          
          {/* Core AI Features */}
          <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
            🤖 AI-Powered Analysis
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {vrAgentFeatures.map((feature) => (
              <Grid item xs={12} sm={6} md={3} key={feature.feature}>
                <Card sx={{ bgcolor: "#111118", height: "100%", border: `1px solid ${alpha(feature.color, 0.3)}`, "&:hover": { borderColor: feature.color } }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                      <Typography sx={{ color: "white", fontWeight: 700, fontSize: "0.9rem" }}>{feature.feature}</Typography>
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{feature.description}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Code Analysis Features */}
          <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
            🔍 Code Analysis Tools
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {codeAnalysisFeatures.map((feature) => (
              <Grid item xs={12} sm={6} md={4} key={feature.feature}>
                <Card sx={{ bgcolor: "#111118", height: "100%", border: `1px solid ${alpha(feature.color, 0.3)}`, "&:hover": { borderColor: feature.color } }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                      <Typography sx={{ color: "white", fontWeight: 700, fontSize: "0.9rem" }}>{feature.feature}</Typography>
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{feature.description}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Security Features */}
          <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
            🛡️ Security Analysis
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {securityFeatures.map((feature) => (
              <Grid item xs={12} sm={6} md={4} key={feature.feature}>
                <Card sx={{ bgcolor: "#111118", height: "100%", border: `1px solid ${alpha(feature.color, 0.3)}`, "&:hover": { borderColor: feature.color } }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                      <Typography sx={{ color: "white", fontWeight: 700, fontSize: "0.9rem" }}>{feature.feature}</Typography>
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{feature.description}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Visualization Features */}
          <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
            📊 Visualization & Export
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {visualizationFeatures.map((feature) => (
              <Grid item xs={12} sm={6} md={3} key={feature.feature}>
                <Card sx={{ bgcolor: "#111118", height: "100%", border: `1px solid ${alpha(feature.color, 0.3)}`, "&:hover": { borderColor: feature.color } }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                      <Typography sx={{ color: "white", fontWeight: 700, fontSize: "0.9rem" }}>{feature.feature}</Typography>
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{feature.description}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ bgcolor: "#111118", height: "100%", border: "1px solid rgba(6, 182, 212, 0.3)", "&:hover": { borderColor: "#06b6d4" } }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Box sx={{ color: "#06b6d4" }}><DownloadIcon /></Box>
                    <Typography sx={{ color: "white", fontWeight: 700, fontSize: "0.9rem" }}>Export Reports</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>Export to Markdown, PDF, or DOCX with all findings</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ bgcolor: "#111118", height: "100%", border: "1px solid rgba(168, 85, 247, 0.3)", "&:hover": { borderColor: "#a855f7" } }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Box sx={{ color: "#a855f7" }}><DownloadIcon /></Box>
                    <Typography sx={{ color: "white", fontWeight: 700, fontSize: "0.9rem" }}>Download ZIP</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>Download full decompiled source as ZIP archive</Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Divider sx={{ my: 4, borderColor: "grey.800" }} />

          <Box sx={{ textAlign: "center" }}>
            <Button
              variant="contained"
              size="large"
              startIcon={<AndroidIcon />}
              onClick={() => navigate("/reverse")}
              sx={{ bgcolor: "#22c55e", "&:hover": { bgcolor: "#16a34a" }, px: 4, py: 1.5 }}
            >
              Launch APK Analyzer
            </Button>
          </Box>
        </TabPanel>

        {/* Tab 6: Tips & Tricks */}
        <TabPanel value={tabValue} index={6}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  ✅ Best Practices
                </Typography>
                <List>
                  {[
                    "Always analyze APKs in an isolated environment (VM/emulator)",
                    "Start with manifest analysis to understand app structure",
                    "Use the Unified Scan for quick comprehensive overview",
                    "Check for hardcoded secrets in strings and resources",
                    "Analyze network security config for MITM vulnerabilities",
                    "Look at exported components first - easiest attack surface",
                    "Use AI Chat to ask questions about specific findings",
                    "Export reports to document all findings for clients",
                  ].map((tip, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{tip}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                  ⚠️ Common Mistakes to Avoid
                </Typography>
                <List>
                  {[
                    "Installing unknown APKs on your personal device",
                    "Ignoring native libraries (.so files) - they can contain vulns too",
                    "Assuming obfuscated code is secure",
                    "Missing multi-dex analysis (check classes2.dex, classes3.dex...)",
                    "Not checking assets folder for sensitive files",
                    "Skipping Kotlin-specific analysis for Kotlin apps",
                    "Ignoring Firebase/Google Services configs",
                    "Not testing actual network requests (use MITM proxy)",
                  ].map((mistake, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <WarningIcon sx={{ color: "#ef4444", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{mistake}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  💡 Pro Tips for VRAgent
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { tip: "Use AI Chat", desc: "Ask questions like 'What authentication methods does this app use?' or 'Find all API endpoints'" },
                    { tip: "Smart Search", desc: "Use natural language: 'find login functionality' or 'show crypto operations'" },
                    { tip: "Data Flow Analysis", desc: "Track sensitive data from user input to storage/network" },
                    { tip: "Threat Model First", desc: "Generate a threat model to prioritize your analysis" },
                    { tip: "Cross-References", desc: "When you find a suspicious method, trace all its callers" },
                    { tip: "Export Everything", desc: "Generate reports throughout your analysis, not just at the end" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={4} key={item.tip}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, border: "1px solid rgba(34, 197, 94, 0.2)" }}>
                        <Typography sx={{ color: "#22c55e", fontWeight: 700, mb: 0.5 }}>{item.tip}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                  📚 Additional Learning Resources
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "OWASP MASTG", url: "https://mas.owasp.org/MASTG/", desc: "Mobile Application Security Testing Guide" },
                    { name: "Android Security", url: "https://source.android.com/security", desc: "Official Android security documentation" },
                    { name: "Frida Handbook", url: "https://learnfrida.info/", desc: "Dynamic instrumentation tutorials" },
                    { name: "APKLab", url: "https://github.com/APKLab/APKLab", desc: "VS Code extension for APK analysis" },
                  ].map((resource) => (
                    <Grid item xs={12} sm={6} md={3} key={resource.name}>
                      <Button
                        fullWidth
                        variant="outlined"
                        href={resource.url}
                        target="_blank"
                        sx={{ 
                          borderColor: "rgba(59, 130, 246, 0.5)", 
                          color: "#3b82f6",
                          textAlign: "left",
                          display: "block",
                          py: 1.5,
                          "&:hover": { borderColor: "#3b82f6", bgcolor: alpha("#3b82f6", 0.1) }
                        }}
                      >
                        <Typography sx={{ fontWeight: 600 }}>{resource.name}</Typography>
                        <Typography variant="caption" sx={{ color: "grey.400" }}>{resource.desc}</Typography>
                      </Button>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default ApkAnalysisGuidePage;
