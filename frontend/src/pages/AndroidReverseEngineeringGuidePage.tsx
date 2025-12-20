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
import MemoryIcon from "@mui/icons-material/Memory";
import SchoolIcon from "@mui/icons-material/School";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import TerminalIcon from "@mui/icons-material/Terminal";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
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

const AndroidReverseEngineeringGuidePage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  // Essential tools for Android RE
  const essentialTools = [
    { tool: "JADX", description: "DEX to Java decompiler with GUI - the go-to tool for reading Android app source code", category: "Static Analysis", url: "https://github.com/skylot/jadx" },
    { tool: "apktool", description: "APK disassembly/reassembly - essential for modifying and repackaging apps", category: "Static Analysis", url: "https://ibotpeaches.github.io/Apktool/" },
    { tool: "Frida", description: "Dynamic instrumentation toolkit - hook any function at runtime", category: "Dynamic Analysis", url: "https://frida.re/" },
    { tool: "objection", description: "Frida-powered runtime exploration with pre-built scripts", category: "Dynamic Analysis", url: "https://github.com/sensepost/objection" },
    { tool: "Ghidra", description: "NSA's reverse engineering suite - essential for native library analysis", category: "Native Code", url: "https://ghidra-sre.org/" },
    { tool: "Android Studio", description: "Official IDE with profiler, debugger, and layout inspector", category: "Development", url: "https://developer.android.com/studio" },
    { tool: "Burp Suite", description: "HTTP/HTTPS proxy for intercepting app traffic", category: "Network", url: "https://portswigger.net/burp" },
    { tool: "MobSF", description: "Mobile Security Framework - automated static/dynamic analysis", category: "Automation", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF" },
    { tool: "Drozer", description: "Android security assessment framework for IPC testing", category: "Dynamic Analysis", url: "https://github.com/WithSecureLabs/drozer" },
  ];

  // Additional tools by category
  const additionalTools = {
    "Static Analysis": [
      { name: "Bytecode Viewer", desc: "Java/Android decompiler with multiple backends" },
      { name: "APKiD", desc: "Identify packers, protectors, and obfuscators" },
      { name: "ClassyShark", desc: "Android executable browser" },
      { name: "dex2jar", desc: "Convert DEX to JAR for analysis" },
    ],
    "Dynamic Analysis": [
      { name: "Xposed Framework", desc: "System-wide hooks without app modification" },
      { name: "LSPosed", desc: "Modern Xposed implementation for newer Android" },
      { name: "RMS", desc: "Runtime Mobile Security - Frida web UI" },
      { name: "House", desc: "Runtime mobile analysis toolkit" },
    ],
    "Network Analysis": [
      { name: "mitmproxy", desc: "Interactive HTTPS proxy" },
      { name: "Charles Proxy", desc: "HTTP debugging proxy with SSL support" },
      { name: "PCAPdroid", desc: "No-root network capture on device" },
      { name: "HTTP Toolkit", desc: "Beautiful HTTP debugging tool" },
    ],
  };

  // Android architecture layers
  const androidLayers = [
    { layer: "Applications", description: "User apps, system apps (Java/Kotlin)", examples: "Gmail, Settings, Your APK" },
    { layer: "Framework", description: "Android APIs, Activity Manager, Content Providers", examples: "android.*, javax.*" },
    { layer: "Native Libraries", description: "C/C++ libraries, JNI", examples: "libc, libssl, libcrypto" },
    { layer: "Android Runtime (ART)", description: "DEX bytecode execution, JIT/AOT compilation", examples: "dalvikvm, dex2oat" },
    { layer: "HAL", description: "Hardware Abstraction Layer", examples: "Camera, Sensors, Audio" },
    { layer: "Linux Kernel", description: "Process management, memory, drivers", examples: "Binder IPC, SELinux" },
  ];

  // Android components
  const androidComponents = [
    { component: "Activity", description: "Single screen with UI, entry point for user interaction", security: "Can be exported and launched by other apps" },
    { component: "Service", description: "Background operations without UI", security: "Bound services can leak data, started services can be hijacked" },
    { component: "Broadcast Receiver", description: "Responds to system-wide broadcasts", security: "Can intercept sensitive broadcasts or be triggered maliciously" },
    { component: "Content Provider", description: "Manages shared app data", security: "SQL injection, path traversal, data leakage" },
  ];

  // Important Android directories
  const androidDirectories = [
    { path: "/data/data/<package>/", desc: "App private data directory", content: "SharedPrefs, databases, files" },
    { path: "/data/data/<package>/shared_prefs/", desc: "SharedPreferences XML files", content: "Often contains tokens, settings" },
    { path: "/data/data/<package>/databases/", desc: "SQLite databases", content: "User data, cached content" },
    { path: "/data/data/<package>/files/", desc: "Internal storage files", content: "App-created files" },
    { path: "/sdcard/Android/data/<package>/", desc: "External storage (less secure)", content: "Downloaded files, caches" },
    { path: "/data/app/<package>/", desc: "Installed APK location", content: "APK, native libs, ODEX" },
  ];

  // Common vulnerability categories
  const vulnCategories = [
    { category: "Insecure Data Storage", description: "Sensitive data in SharedPrefs, SQLite, files, logs", severity: "High", examples: "Plaintext passwords, tokens in SharedPreferences" },
    { category: "Insecure Communication", description: "Missing SSL pinning, cleartext traffic, weak TLS", severity: "High", examples: "HTTP traffic, accepting all certificates" },
    { category: "Insufficient Cryptography", description: "Weak algorithms, hardcoded keys, improper IV usage", severity: "Critical", examples: "DES, ECB mode, static keys in code" },
    { category: "Client-Side Injection", description: "WebView JavaScript injection, SQL injection, path traversal", severity: "High", examples: "addJavascriptInterface, raw SQL queries" },
    { category: "Improper Platform Usage", description: "Exported components, intent vulnerabilities, broadcast issues", severity: "Medium", examples: "Exported activities without permissions" },
    { category: "Code Tampering", description: "Lack of integrity checks, no root detection, debuggable", severity: "Medium", examples: "android:debuggable=true, no signature verification" },
    { category: "Reverse Engineering", description: "No obfuscation, debug builds, readable strings", severity: "Low", examples: "ProGuard disabled, hardcoded API keys" },
    { category: "Extraneous Functionality", description: "Hidden backdoors, debug endpoints, test code in production", severity: "High", examples: "Debug menus, bypass flags" },
  ];

  // Specific vulnerability patterns to search for
  const vulnPatterns = [
    { pattern: "MODE_WORLD_READABLE", desc: "Files readable by all apps", severity: "High" },
    { pattern: "setJavaScriptEnabled(true)", desc: "WebView with JS enabled - check for XSS", severity: "Medium" },
    { pattern: "addJavascriptInterface", desc: "Exposes Java objects to JavaScript", severity: "High" },
    { pattern: "android:exported=\"true\"", desc: "Component accessible to other apps", severity: "Medium" },
    { pattern: "android:debuggable=\"true\"", desc: "App can be debugged", severity: "Medium" },
    { pattern: "android:allowBackup=\"true\"", desc: "App data can be backed up via ADB", severity: "Low" },
    { pattern: "checkServerTrusted", desc: "Custom SSL - look for empty implementations", severity: "Critical" },
    { pattern: "ALLOW_ALL_HOSTNAME_VERIFIER", desc: "Accepts any hostname in SSL", severity: "Critical" },
    { pattern: "Log.d|Log.v|Log.i", desc: "Debug logging - may leak sensitive data", severity: "Low" },
    { pattern: "getExternalStorage", desc: "External storage usage - world-readable", severity: "Medium" },
  ];

  const pageContext = `This page covers Android Reverse Engineering fundamentals including Android OS architecture, APK structure, Dalvik/ART runtime, smali code, static analysis with JADX and APKTool, dynamic analysis with Frida, common vulnerability patterns, root detection bypass, certificate pinning bypass, and VRAgent AI-assisted analysis tools.`;

  return (
    <LearnPageLayout pageTitle="Android Reverse Engineering" pageContext={pageContext}>
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
                Android Reverse Engineering
              </Typography>
              <Typography variant="h6" sx={{ color: "grey.400" }}>
                Fundamentals, Tools & Techniques for Android Security Research
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
            <Alert severity="info" sx={{ bgcolor: alpha("#22c55e", 0.1), flex: 1 }}>
              <Typography variant="body2">
                <strong>Learn Android reverse engineering</strong> from the ground up. This guide covers architecture,
                tools, static/dynamic analysis, and common vulnerabilities.
              </Typography>
            </Alert>
            <Button
              variant="contained"
              size="large"
              startIcon={<AndroidIcon />}
              onClick={() => navigate("/reverse")}
              sx={{ bgcolor: "#22c55e", "&:hover": { bgcolor: "#16a34a" }, alignSelf: "center", whiteSpace: "nowrap" }}
            >
              Try APK Analyzer
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
            <Tab icon={<SchoolIcon />} label="Fundamentals" />
            <Tab icon={<PhoneAndroidIcon />} label="Android Architecture" />
            <Tab icon={<BuildIcon />} label="Tools & Setup" />
            <Tab icon={<CodeIcon />} label="Static Analysis" />
            <Tab icon={<TerminalIcon />} label="Dynamic Analysis" />
            <Tab icon={<BugReportIcon />} label="Vulnerabilities" />
            <Tab icon={<TipsAndUpdatesIcon />} label="Resources" />
          </Tabs>
        </Paper>

        {/* Tab 0: Fundamentals */}
        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  What is Android Reverse Engineering?
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Android reverse engineering is the process of analyzing Android applications to understand how they work,
                  find security vulnerabilities, or extract information without access to the original source code. Unlike
                  compiled native binaries, Android apps are relatively easier to reverse engineer because they compile to
                  Dalvik bytecode (DEX) which can be decompiled back to readable Java/Kotlin code.
                </Typography>
                <Grid container spacing={2} sx={{ mt: 2 }}>
                  {[
                    { title: "Security Research", desc: "Find vulnerabilities before attackers do - authentication bypasses, data leaks, injection flaws", icon: <SecurityIcon /> },
                    { title: "Malware Analysis", desc: "Understand malicious app behavior - C2 servers, exfiltration methods, persistence mechanisms", icon: <BugReportIcon /> },
                    { title: "Penetration Testing", desc: "Test mobile apps for clients - API security, local storage, network traffic analysis", icon: <TerminalIcon /> },
                    { title: "Bug Bounty", desc: "Find vulnerabilities in popular apps for rewards - many companies have mobile programs", icon: <StorageIcon /> },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={3} key={item.title}>
                      <Card sx={{ bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                        <CardContent>
                          <Box sx={{ color: "#22c55e", mb: 1 }}>{item.icon}</Box>
                          <Typography sx={{ color: "white", fontWeight: 600 }}>{item.title}</Typography>
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
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  APK File Structure
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  An APK (Android Package) is essentially a ZIP file containing everything needed to run an Android app.
                  You can unzip any APK to explore its contents:
                </Typography>
                <CodeBlock
                  title="Extract APK Contents"
                  language="bash"
                  code={`# Simply unzip the APK
unzip app.apk -d extracted/

# Or use apktool for decoded resources
apktool d app.apk -o decoded/`}
                />
                <Grid container spacing={2}>
                  {[
                    { file: "AndroidManifest.xml", desc: "App metadata, permissions, components - START HERE! Binary XML that needs decoding" },
                    { file: "classes.dex", desc: "Compiled Dalvik bytecode - your Java/Kotlin code lives here. May have classes2.dex, classes3.dex for multidex" },
                    { file: "resources.arsc", desc: "Compiled resources table - maps resource IDs to values (strings, colors, dimensions)" },
                    { file: "res/", desc: "Resource files - layouts (XML), images (PNG/WebP), raw assets. Partially compiled" },
                    { file: "lib/", desc: "Native libraries (.so) - ARM, ARM64, x86 subdirectories. Analyze with Ghidra/IDA" },
                    { file: "assets/", desc: "Raw bundled files - configs, databases, HTML, JavaScript. Often contains secrets!" },
                    { file: "META-INF/", desc: "Signature and certificate - CERT.RSA, CERT.SF, MANIFEST.MF. Verifies app integrity" },
                    { file: "kotlin/", desc: "Kotlin metadata files - present in Kotlin apps, can reveal original structure" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} key={item.file}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                        <Typography sx={{ color: "#22c55e", fontFamily: "monospace", fontWeight: 600 }}>{item.file}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  DEX vs Native Code
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                      <Typography sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>DEX (Dalvik Executable)</Typography>
                      <List dense>
                        {[
                          "Java/Kotlin source → DEX bytecode",
                          "Easily decompiled with JADX",
                          "Runs on ART (Android Runtime)",
                          "Most app logic lives here",
                          "Obfuscation makes it harder but not impossible",
                        ].map((item, i) => (
                          <ListItem key={i} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#3b82f6", fontSize: 16 }} /></ListItemIcon>
                            <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, border: "1px solid rgba(245, 158, 11, 0.3)" }}>
                      <Typography sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>Native Code (.so files)</Typography>
                      <List dense>
                        {[
                          "C/C++ source → ARM/x86 assembly",
                          "Requires disassemblers (Ghidra, IDA)",
                          "Used for performance, security, games",
                          "JNI bridge connects Java ↔ Native",
                          "Harder to reverse but not impossible",
                        ].map((item, i) => (
                          <ListItem key={i} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#f59e0b", fontSize: 16 }} /></ListItemIcon>
                            <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 1: Android Architecture */}
        <TabPanel value={tabValue} index={1}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 3, fontWeight: 700 }}>
                  Android System Architecture
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Layer</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Description</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Examples</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {androidLayers.map((row) => (
                        <TableRow key={row.layer}>
                          <TableCell sx={{ color: "white", fontWeight: 600 }}>{row.layer}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{row.description}</TableCell>
                          <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.85rem" }}>{row.examples}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Android App Components
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Android apps are built from four main component types. Each can be an entry point for attacks:
                </Typography>
                <Grid container spacing={2}>
                  {androidComponents.map((comp) => (
                    <Grid item xs={12} sm={6} key={comp.component}>
                      <Card sx={{ bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                        <CardContent>
                          <Typography sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>{comp.component}</Typography>
                          <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>{comp.description}</Typography>
                          <Alert severity="warning" sx={{ py: 0.5, bgcolor: "transparent", color: "#f59e0b" }}>
                            <Typography variant="caption">{comp.security}</Typography>
                          </Alert>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Important File System Locations
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Path</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Description</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>What to Look For</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {androidDirectories.map((dir) => (
                        <TableRow key={dir.path}>
                          <TableCell sx={{ color: "#3b82f6", fontFamily: "monospace", fontSize: "0.8rem" }}>{dir.path}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{dir.desc}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{dir.content}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                <CodeBlock
                  title="Explore App Data (requires root or ADB backup)"
                  language="bash"
                  code={`# With root access
adb shell
su
cd /data/data/com.example.app/
ls -la
cat shared_prefs/preferences.xml

# Without root - use run-as (only for debuggable apps)
adb shell run-as com.example.app ls -la

# Backup method (if allowBackup=true)
adb backup -f backup.ab com.example.app
java -jar abe.jar unpack backup.ab backup.tar`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Intent System
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Intents are the messaging system that allows components to communicate. They're a prime attack surface:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { type: "Explicit Intent", desc: "Targets a specific component by name", example: "new Intent(this, TargetActivity.class)", risk: "Low - internal communication" },
                    { type: "Implicit Intent", desc: "Declares an action, system finds handler", example: "new Intent(Intent.ACTION_VIEW, uri)", risk: "Medium - can be intercepted" },
                    { type: "Broadcast Intent", desc: "Sent to all registered receivers", example: "sendBroadcast(intent)", risk: "High - can leak data" },
                    { type: "Pending Intent", desc: "Token given to external apps", example: "PendingIntent.getActivity(...)", risk: "Critical - if mutable, can be hijacked" },
                  ].map((intent) => (
                    <Grid item xs={12} sm={6} key={intent.type}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                        <Typography sx={{ color: "#22c55e", fontWeight: 600 }}>{intent.type}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>{intent.desc}</Typography>
                        <Typography variant="caption" sx={{ color: "#3b82f6", fontFamily: "monospace", display: "block", mt: 1 }}>{intent.example}</Typography>
                        <Chip label={intent.risk} size="small" sx={{ mt: 1, bgcolor: alpha(intent.risk.includes("Critical") ? "#ef4444" : intent.risk.includes("High") ? "#f59e0b" : "#22c55e", 0.2), color: intent.risk.includes("Critical") ? "#ef4444" : intent.risk.includes("High") ? "#f59e0b" : "#22c55e" }} />
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 2: Tools & Setup */}
        <TabPanel value={tabValue} index={2}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 3, fontWeight: 700 }}>
                  Essential Tools
                </Typography>
                <Grid container spacing={2}>
                  {essentialTools.map((tool) => (
                    <Grid item xs={12} sm={6} md={4} key={tool.tool}>
                      <Card sx={{ bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                        <CardContent>
                          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "start", mb: 1 }}>
                            <Typography sx={{ color: "white", fontWeight: 700 }}>{tool.tool}</Typography>
                            <Chip label={tool.category} size="small" sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e" }} />
                          </Box>
                          <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>{tool.description}</Typography>
                          <Button size="small" href={tool.url} target="_blank" sx={{ color: "#22c55e" }}>
                            Learn More →
                          </Button>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Additional Tools by Category
                </Typography>
                <Grid container spacing={2}>
                  {Object.entries(additionalTools).map(([category, tools]) => (
                    <Grid item xs={12} md={4} key={category}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                        <Typography sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>{category}</Typography>
                        <List dense>
                          {tools.map((tool) => (
                            <ListItem key={tool.name} sx={{ px: 0, py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 16 }} /></ListItemIcon>
                              <ListItemText 
                                primary={<Typography variant="body2" sx={{ color: "white" }}>{tool.name}</Typography>}
                                secondary={<Typography variant="caption" sx={{ color: "grey.500" }}>{tool.desc}</Typography>}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Quick Setup Commands
                </Typography>
                <CodeBlock
                  title="Install Essential Tools (Ubuntu/Debian)"
                  language="bash"
                  code={`# Install Java (required for most tools)
sudo apt install openjdk-17-jdk

# Install apktool
sudo apt install apktool
# Or latest version:
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
sudo mv apktool_2.9.3.jar /usr/local/bin/apktool.jar

# Install JADX
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d ~/tools/jadx
echo 'export PATH=$PATH:~/tools/jadx/bin' >> ~/.bashrc

# Install Frida
pip install frida-tools
# For device: push frida-server (match your arch)
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Install ADB (Android Debug Bridge)
sudo apt install adb

# Install objection
pip install objection`}
                />

                <CodeBlock
                  title="Device Setup"
                  language="bash"
                  code={`# Enable USB debugging on device:
# Settings > Developer Options > USB Debugging

# Verify device connection
adb devices

# Get device shell
adb shell

# Install APK
adb install app.apk

# Pull APK from device
adb shell pm path com.example.app
adb pull /data/app/com.example.app-1/base.apk

# Logcat (view app logs)
adb logcat | grep -i "com.example.app"

# Port forwarding for Burp
adb reverse tcp:8080 tcp:8080`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, border: "1px solid rgba(245, 158, 11, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2, fontWeight: 700 }}>
                  ⚠️ Emulator vs Physical Device
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Emulator (Genymotion/AVD)</Typography>
                    <List dense>
                      {[
                        "Easy to root and configure",
                        "Can install Xposed/Frida easily",
                        "Some apps detect emulators",
                        "Performance can be slow",
                        "Missing some hardware features",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>• {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Physical Device</Typography>
                    <List dense>
                      {[
                        "Real-world behavior",
                        "Better for network testing",
                        "Root may void warranty",
                        "Some devices hard to root",
                        "Recommended: Pixel or OnePlus",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>• {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 3: Static Analysis */}
        <TabPanel value={tabValue} index={3}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Static Analysis Techniques
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  Static analysis examines the app without executing it. This includes decompiling, disassembling, 
                  and reviewing code. It's safer than dynamic analysis and reveals the complete codebase.
                </Typography>
                
                <Alert severity="info" sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.1) }}>
                  <Typography variant="body2">
                    <strong>Analysis Flow:</strong> Start with AndroidManifest.xml → identify entry points (Activities, 
                    Services, Receivers, Providers) → trace data flow → look for hardcoded secrets → analyze network calls
                  </Typography>
                </Alert>

                <CodeBlock
                  title="Decompile APK with JADX"
                  language="bash"
                  code={`# GUI mode - best for exploration
jadx-gui app.apk

# Command line - output to directory
jadx -d output_dir app.apk

# Export as Gradle project (can import to Android Studio)
jadx -e -d output_dir app.apk

# Decompile with all options
jadx -d output --deobf --show-bad-code --escape-unicode app.apk`}
                />

                <CodeBlock
                  title="Disassemble with apktool (for Smali)"
                  language="bash"
                  code={`# Decode APK to Smali and resources
apktool d app.apk -o output_dir

# Decode without resources (faster)
apktool d -r app.apk -o output_dir

# Rebuild after modifications
apktool b output_dir -o modified.apk

# Sign the modified APK (required to install)
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks debug.keystore --ks-key-alias debug modified.apk
# Or with jarsigner:
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore debug.keystore modified.apk debug`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  What to Look For
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <CodeBlock
                      title="Search for Secrets (grep)"
                      language="bash"
                      code={`# API Keys
grep -rn "api_key\\|apikey\\|api-key" output_dir/
grep -rn "AIza[0-9A-Za-z_-]{35}" output_dir/  # Google API

# Passwords and tokens
grep -rn "password\\|passwd\\|secret\\|token" output_dir/

# URLs and endpoints
grep -rn "https://\\|http://" output_dir/
grep -rn "api\\." output_dir/

# Firebase
grep -rn "firebase\\|firebaseio.com" output_dir/

# AWS
grep -rn "AKIA[0-9A-Z]{16}" output_dir/  # AWS Access Key`}
                    />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <CodeBlock
                      title="Search for Vulnerabilities"
                      language="bash"
                      code={`# Insecure WebView
grep -rn "setJavaScriptEnabled\\|addJavascriptInterface" output_dir/

# SQL Injection
grep -rn "rawQuery\\|execSQL" output_dir/

# Logging sensitive data
grep -rn "Log\\.d\\|Log\\.v\\|Log\\.i" output_dir/

# Insecure storage
grep -rn "MODE_WORLD_READABLE\\|MODE_WORLD_WRITEABLE" output_dir/

# Weak crypto
grep -rn "DES\\|MD5\\|SHA1" output_dir/

# Certificate pinning bypass opportunities
grep -rn "checkServerTrusted\\|X509TrustManager" output_dir/`}
                    />
                  </Grid>
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Manifest Analysis
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  The AndroidManifest.xml is your roadmap. Always start here:
                </Typography>
                <CodeBlock
                  title="Key Manifest Elements"
                  language="xml"
                  code={`<!-- Dangerous: App can be debugged -->
<application android:debuggable="true" ...>

<!-- Dangerous: Backup enabled (data extraction) -->
<application android:allowBackup="true" ...>

<!-- Check: What permissions does it request? -->
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.CAMERA" />

<!-- Attack Surface: Exported components -->
<activity android:name=".AdminActivity" android:exported="true" />
<service android:name=".BackgroundService" android:exported="true" />
<receiver android:name=".BootReceiver" android:exported="true" />
<provider android:name=".DataProvider" 
          android:exported="true" 
          android:authorities="com.app.provider" />

<!-- Deep Links: URL entry points -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <data android:scheme="myapp" android:host="*" />
</intent-filter>

<!-- Network Security Config -->
<application android:networkSecurityConfig="@xml/network_security_config" ...>`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Native Library Analysis
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  If the app uses native code (.so files), you'll need Ghidra or IDA Pro:
                </Typography>
                <CodeBlock
                  title="Analyze Native Libraries"
                  language="bash"
                  code={`# List native libraries
ls -la lib/arm64-v8a/  # or armeabi-v7a, x86, x86_64

# Check library info
file lib/arm64-v8a/libnative.so
readelf -d lib/arm64-v8a/libnative.so

# Find JNI functions (entry points from Java)
nm -D lib/arm64-v8a/libnative.so | grep Java_

# Open in Ghidra
ghidraRun  # Then File > Import > select .so file

# Strings in native code
strings lib/arm64-v8a/libnative.so | grep -i "password\\|key\\|secret\\|http"`}
                />
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 4: Dynamic Analysis */}
        <TabPanel value={tabValue} index={4}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Dynamic Analysis & Runtime Instrumentation
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  Dynamic analysis runs the app and observes its behavior in real-time. Use Frida to hook functions, 
                  bypass security checks, and extract runtime data. Objection provides a user-friendly wrapper around Frida.
                </Typography>
                
                <Alert severity="warning" sx={{ mb: 3, bgcolor: alpha("#f59e0b", 0.1) }}>
                  <Typography variant="body2">
                    <strong>Prerequisites:</strong> Device must be rooted or use a rooted emulator. Install frida-server 
                    on device matching your Frida version.
                  </Typography>
                </Alert>

                <CodeBlock
                  title="Frida Setup & Basic Commands"
                  language="bash"
                  code={`# List running apps
frida-ps -U

# Spawn app and attach
frida -U -f com.target.app --no-pause

# Attach to running app
frida -U com.target.app

# Load script from file
frida -U -f com.target.app -l script.js --no-pause

# Trace all methods in a class
frida-trace -U -j "com.target.app.*!*" com.target.app`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Root Detection Bypass
                </Typography>
                <CodeBlock
                  title="Frida Root Bypass Script"
                  language="javascript"
                  code={`Java.perform(function() {
  // Hook common root check
  var RootCheck = Java.use("com.app.security.RootChecker");
  RootCheck.isRooted.implementation = function() {
    console.log("[*] Root check bypassed");
    return false;
  };
  
  // Block su binary checks
  var File = Java.use("java.io.File");
  File.exists.implementation = function() {
    var path = this.getAbsolutePath();
    if (path.indexOf("/su") !== -1) {
      return false;
    }
    return this.exists();
  };
});`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  SSL Pinning Bypass
                </Typography>
                <CodeBlock
                  title="Universal SSL Bypass"
                  language="javascript"
                  code={`Java.perform(function() {
  // OkHttp3 CertificatePinner
  try {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List")
      .implementation = function(hostname, certs) {
      console.log("[*] Bypassed: " + hostname);
      return;
    };
  } catch(e) {}

  // TrustManagerImpl
  try {
    var TrustManager = Java.use(
      "com.android.org.conscrypt.TrustManagerImpl");
    TrustManager.verifyChain.implementation = function() {
      return arguments[0];
    };
  } catch(e) {}
});`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Intercept Crypto Operations
                </Typography>
                <CodeBlock
                  title="Hook Encryption"
                  language="javascript"
                  code={`Java.perform(function() {
  var Cipher = Java.use("javax.crypto.Cipher");
  
  Cipher.doFinal.overload("[B").implementation = 
    function(input) {
    var result = this.doFinal(input);
    console.log("[*] Cipher.doFinal()");
    console.log("    Input:  " + bytesToHex(input));
    console.log("    Output: " + bytesToHex(result));
    return result;
  };
  
  // Capture encryption keys
  var SecretKeySpec = Java.use(
    "javax.crypto.spec.SecretKeySpec");
  SecretKeySpec.$init.overload("[B", "java.lang.String")
    .implementation = function(key, alg) {
    console.log("[*] Key: " + bytesToHex(key));
    return this.$init(key, alg);
  };
});`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Objection Quick Reference
                </Typography>
                <CodeBlock
                  title="Objection Commands"
                  language="bash"
                  code={`# Start objection
objection -g com.target.app explore

# Common commands:
android sslpinning disable
android root disable
android hooking list classes
android hooking watch class ClassName

# File system
ls /data/data/com.target.app/
file download prefs.xml

# Memory
memory search "password"
memory dump all dump.bin

# Keystore
android keystore list
android keystore dump`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Network Traffic Interception
                </Typography>
                <CodeBlock
                  title="Setup Traffic Interception"
                  language="bash"
                  code={`# 1. Configure proxy on device (Settings > Wi-Fi > Proxy)
#    Host: your-pc-ip, Port: 8080

# 2. Install Burp CA certificate as system cert
openssl x509 -inform DER -in burp.der -out burp.pem
hash=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
adb root && adb remount
adb push $hash.0 /system/etc/security/cacerts/

# 3. Run app with SSL bypass script
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# 4. Traffic now visible in Burp Suite!`}
                />
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 5: Vulnerabilities */}
        <TabPanel value={tabValue} index={5}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 3, fontWeight: 700 }}>
                  Common Android Vulnerabilities (OWASP Mobile Top 10)
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Category</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Description</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Example</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Severity</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {vulnCategories.map((row) => (
                        <TableRow key={row.category}>
                          <TableCell sx={{ color: "white", fontWeight: 600 }}>{row.category}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{row.description}</TableCell>
                          <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.75rem" }}>{row.examples}</TableCell>
                          <TableCell>
                            <Chip 
                              label={row.severity} 
                              size="small" 
                              sx={{ 
                                bgcolor: alpha(
                                  row.severity === "Critical" ? "#ef4444" : 
                                  row.severity === "High" ? "#f59e0b" : 
                                  row.severity === "Medium" ? "#3b82f6" : "#22c55e", 
                                  0.2
                                ),
                                color: row.severity === "Critical" ? "#ef4444" : 
                                       row.severity === "High" ? "#f59e0b" : 
                                       row.severity === "Medium" ? "#3b82f6" : "#22c55e",
                              }} 
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🔍 Code Patterns to Search For
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Use grep or JADX search to find these vulnerability indicators:
                </Typography>
                <Grid container spacing={2}>
                  {vulnPatterns.map((pattern, index) => (
                    <Grid item xs={12} md={6} key={index}>
                      <Box sx={{ 
                        p: 2, 
                        bgcolor: alpha("#ef4444", 0.05), 
                        borderRadius: 1, 
                        border: "1px solid rgba(239, 68, 68, 0.2)" 
                      }}>
                        <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 0.5 }}>
                          {pattern.desc}
                        </Typography>
                        <Typography 
                          variant="body2" 
                          sx={{ 
                            color: "grey.300", 
                            fontFamily: "monospace", 
                            fontSize: "0.75rem",
                            wordBreak: "break-all"
                          }}
                        >
                          {pattern.pattern}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                  💡 Testing Checklist
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Data Storage</Typography>
                    <List dense>
                      {[
                        "Check SharedPreferences encryption",
                        "Review SQLite for sensitive data",
                        "Check for data in logs (adb logcat)",
                        "Examine backup files",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>☐ {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Network Security</Typography>
                    <List dense>
                      {[
                        "Test SSL pinning",
                        "Check for cleartext traffic",
                        "Inspect API endpoints",
                        "Review certificate validation",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>☐ {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Authentication</Typography>
                    <List dense>
                      {[
                        "Review biometric implementation",
                        "Check session management",
                        "Test for weak passwords",
                        "Verify token storage",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>☐ {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 6: Resources */}
        <TabPanel value={tabValue} index={6}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  📚 Essential Documentation
                </Typography>
                <List>
                  {[
                    { name: "OWASP MASTG", url: "https://mas.owasp.org/MASTG/", desc: "Mobile Application Security Testing Guide - the bible of mobile security" },
                    { name: "OWASP MASVS", url: "https://mas.owasp.org/MASVS/", desc: "Mobile Application Security Verification Standard" },
                    { name: "Android Security Docs", url: "https://source.android.com/security", desc: "Official Android security architecture documentation" },
                    { name: "Frida Documentation", url: "https://frida.re/docs/home/", desc: "Complete Frida reference and JavaScript API" },
                    { name: "JADX GitHub", url: "https://github.com/skylot/jadx", desc: "DEX to Java decompiler - documentation and releases" },
                  ].map((resource) => (
                    <ListItem key={resource.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: "#22c55e" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={resource.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{resource.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{resource.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🎯 Vulnerable Practice Apps
                </Typography>
                <List>
                  {[
                    { name: "DIVA (Damn Insecure Vulnerable App)", url: "https://github.com/payatu/diva-android", desc: "13 challenges covering common vulnerabilities" },
                    { name: "InsecureBankv2", url: "https://github.com/dineshshetty/Android-InsecureBankv2", desc: "Vulnerable banking app with comprehensive backend" },
                    { name: "OWASP UnCrackable Apps", url: "https://mas.owasp.org/crackmes/", desc: "Official OWASP mobile crackmes - L1 to L4 difficulty" },
                    { name: "AndroGoat", url: "https://github.com/AnirudhHack/AndroGoat", desc: "Open source vulnerable app with CTF challenges" },
                    { name: "MSTG Apps", url: "https://github.com/OWASP/owasp-mastg/tree/master/Crackmes", desc: "Test cases for OWASP MASTG methodology" },
                  ].map((target) => (
                    <ListItem key={target.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <BugReportIcon sx={{ color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={target.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{target.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{target.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🛠️ Tool Repositories
                </Typography>
                <List>
                  {[
                    { name: "Frida CodeShare", url: "https://codeshare.frida.re/", desc: "Community scripts for Frida - ready to use hooks" },
                    { name: "awesome-mobile-security", url: "https://github.com/vaib25vicky/awesome-mobile-security", desc: "Curated list of mobile security resources" },
                    { name: "Android Security Awesome", url: "https://github.com/ashishb/android-security-awesome", desc: "Collection of Android security tools" },
                    { name: "MobSF", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF", desc: "Automated mobile security framework" },
                  ].map((tool) => (
                    <ListItem key={tool.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <BuildIcon sx={{ color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={tool.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{tool.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{tool.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🎓 Learning Platforms & Courses
                </Typography>
                <List>
                  {[
                    { name: "HackTricks - Android", url: "https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting", desc: "Comprehensive Android pentesting methodology" },
                    { name: "TCM Security - Mobile", url: "https://tcm-sec.com/", desc: "Practical mobile app hacking courses" },
                    { name: "Corellium", url: "https://www.corellium.com/", desc: "Virtual iOS/Android devices for security research" },
                    { name: "NowSecure Academy", url: "https://www.nowsecure.com/", desc: "Mobile app security training and certification" },
                  ].map((course) => (
                    <ListItem key={course.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <SchoolIcon sx={{ color: "#a855f7" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={course.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{course.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{course.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, border: "1px solid rgba(34, 197, 94, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  📖 Recommended Books
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { title: "Android Hacker's Handbook", author: "Joshua Drake et al.", desc: "Deep dive into Android internals and exploitation" },
                    { title: "Learning Frida", author: "Debasish Mandal", desc: "Practical guide to dynamic instrumentation" },
                    { title: "The Mobile Application Hacker's Handbook", author: "Dominic Chell et al.", desc: "Comprehensive mobile security testing" },
                    { title: "Android Security Internals", author: "Nikolay Elenkov", desc: "In-depth look at Android security architecture" },
                  ].map((book, index) => (
                    <Grid item xs={12} sm={6} md={3} key={index}>
                      <Box sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                        <Typography variant="subtitle2" sx={{ color: "white", fontWeight: 600 }}>{book.title}</Typography>
                        <Typography variant="caption" sx={{ color: "#22c55e" }}>{book.author}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mt: 1, fontSize: "0.75rem" }}>{book.desc}</Typography>
                      </Box>
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

export default AndroidReverseEngineeringGuidePage;
