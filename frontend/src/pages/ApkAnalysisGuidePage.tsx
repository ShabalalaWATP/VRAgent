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
import VisibilityIcon from "@mui/icons-material/Visibility";
import LinkIcon from "@mui/icons-material/Link";
import { useNavigate } from "react-router-dom";

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

  return (
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
            <Tab icon={<AndroidIcon />} label="APK Structure" />
            <Tab icon={<LockIcon />} label="Permissions" />
            <Tab icon={<BugReportIcon />} label="Attack Surface" />
            <Tab icon={<CodeIcon />} label="Obfuscation" />
            <Tab icon={<BuildIcon />} label="VRAgent Tools" />
          </Tabs>
        </Paper>

        {/* Tab 0: APK Structure */}
        <TabPanel value={tabValue} index={0}>
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
                    { file: "classes.dex", desc: "Compiled Dalvik bytecode" },
                    { file: "resources.arsc", desc: "Compiled resources" },
                    { file: "res/", desc: "Layouts, strings, images" },
                    { file: "lib/", desc: "Native libraries (.so files)" },
                    { file: "META-INF/", desc: "Signing certificates" },
                    { file: "assets/", desc: "Raw files (configs, databases)" },
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
                title="Manual APK Extraction"
                language="bash"
                code={`# Unzip APK
unzip app.apk -d extracted/

# Decode with apktool (preserves XML)
apktool d app.apk -o decoded/

# Decompile to Java with jadx
jadx app.apk -d jadx_output/

# View certificate info
keytool -printcert -jarfile app.apk`}
              />
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 1: Permissions */}
        <TabPanel value={tabValue} index={1}>
          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 3 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              ⚠️ Dangerous Permissions Reference
            </Typography>
            <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha("#f59e0b", 0.1) }}>
              These permissions require user approval and can access sensitive data. Excessive permissions may indicate malicious intent.
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
                            bgcolor: perm.risk === "Critical" ? alpha("#ef4444", 0.2) : perm.risk === "High" ? alpha("#f59e0b", 0.2) : alpha("#22c55e", 0.2),
                            color: perm.risk === "Critical" ? "#ef4444" : perm.risk === "High" ? "#f59e0b" : "#22c55e",
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
              ].map((item) => (
                <Grid item xs={12} md={4} key={item.title}>
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

        {/* Tab 2: Attack Surface */}
        <TabPanel value={tabValue} index={2}>
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
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>ADB Command</TableCell>
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

          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🔗 Deep Link Security
            </Typography>
            <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
              Deep links (custom URL schemes) can be exploited for:
            </Typography>
            <List dense>
              {[
                "Authentication bypass - redirect OAuth tokens to attacker",
                "XSS injection - if WebView renders URL parameters",
                "Intent injection - manipulate internal app state",
                "Data exfiltration - leak sensitive parameters in URL",
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
grep -E "scheme|host|pathPrefix" AndroidManifest.xml

# Test deep link
adb shell am start -a android.intent.action.VIEW \\
  -d "myapp://login?redirect=http://evil.com"`}
            />
          </Paper>
        </TabPanel>

        {/* Tab 3: Obfuscation */}
        <TabPanel value={tabValue} index={3}>
          <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, mb: 3 }}>
            <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
              🛡️ Obfuscation Detection
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Tool</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Indicators</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Level</TableCell>
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
                            bgcolor: tool.level === "Extreme" ? alpha("#ef4444", 0.2) : tool.level === "Heavy" ? alpha("#f59e0b", 0.2) : alpha("#22c55e", 0.2),
                            color: tool.level === "Extreme" ? "#ef4444" : tool.level === "Heavy" ? "#f59e0b" : "#22c55e",
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
              code={`Java.perform(function() {
  var StringClass = Java.use('java.lang.String');
  StringClass.$init.overload('[B').implementation = function(bytes) {
    var result = this.$init(bytes);
    console.log('[Decrypted] ' + result);
    return result;
  };
});`}
            />
          </Paper>
        </TabPanel>

        {/* Tab 4: VRAgent Tools */}
        <TabPanel value={tabValue} index={4}>
          <Alert severity="info" sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.1) }}>
            VRAgent's Reverse Engineering Hub provides automated APK analysis with AI-powered insights.
          </Alert>
          
          <Grid container spacing={3}>
            {[
              { title: "Quick AI Summary", desc: "One-click analysis: what the app does + security findings", icon: <VisibilityIcon />, color: "#22c55e" },
              { title: "Attack Surface Map", desc: "Automatically identifies exported components, deep links, and attack vectors with ADB commands", icon: <BugReportIcon />, color: "#ef4444" },
              { title: "Obfuscation Analysis", desc: "Detects ProGuard/DexGuard, generates Frida hooks, suggests deobfuscation tools", icon: <CodeIcon />, color: "#f59e0b" },
              { title: "Permission Analysis", desc: "Risk-rated permissions with over-permission detection", icon: <LockIcon />, color: "#3b82f6" },
              { title: "Certificate Validation", desc: "Signature scheme detection, certificate chain analysis", icon: <SecurityIcon />, color: "#8b5cf6" },
              { title: "Export Reports", desc: "Generate Markdown, PDF, or DOCX reports with all findings", icon: <StorageIcon />, color: "#06b6d4" },
            ].map((feature) => (
              <Grid item xs={12} md={4} key={feature.title}>
                <Card sx={{ bgcolor: "#111118", height: "100%", border: `1px solid ${alpha(feature.color, 0.3)}` }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                      <Typography sx={{ color: "white", fontWeight: 700 }}>{feature.title}</Typography>
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{feature.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
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
              Launch Reverse Engineering Hub
            </Button>
          </Box>
        </TabPanel>
      </Container>
    </Box>
  );
};

export default ApkAnalysisGuidePage;
