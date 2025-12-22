import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  alpha,
  useTheme,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CodeIcon from "@mui/icons-material/Code";
import WarningIcon from "@mui/icons-material/Warning";
import WebIcon from "@mui/icons-material/Web";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import SearchIcon from "@mui/icons-material/Search";
import ShieldIcon from "@mui/icons-material/Shield";
import { useNavigate } from "react-router-dom";

interface XSSType {
  title: string;
  description: string;
  persistence: string;
  color: string;
}

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "javascript",
}) => {
  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: "#0f1422",
        borderRadius: 2,
        border: "1px solid rgba(245, 158, 11, 0.2)",
      }}
    >
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: alpha("#f59e0b", 0.2), color: "#f59e0b" }} />
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "grey.200",
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const xssTypes: XSSType[] = [
  { title: "Reflected XSS", description: "Payload in URL/request, reflected back in response", persistence: "Non-persistent", color: "#f59e0b" },
  { title: "Stored XSS", description: "Payload saved in database, executes for all users", persistence: "Persistent", color: "#ef4444" },
  { title: "DOM-Based XSS", description: "Payload manipulates DOM directly via client-side JS", persistence: "Client-side", color: "#8b5cf6" },
];

const xssFlow = [
  "Untrusted input enters the app (URL, form, API, or stored data).",
  "The app inserts that input into the page without proper encoding.",
  "The browser interprets the input as HTML or JavaScript.",
  "The injected code runs with the site's permissions.",
  "The attacker can read data or perform actions as the user.",
];

const entryPoints = [
  "Search, filter, and sort parameters in URLs",
  "Comment fields, profile bios, and support tickets",
  "Markdown or rich text editors",
  "File names and metadata rendered in the UI",
  "JSON values rendered into templates",
  "Single-page app routes using URL fragments",
];

const highRiskFeatures = [
  "User-generated content feeds",
  "Admin dashboards with custom queries or notes",
  "Preview pages or content moderation queues",
  "Notifications and email template previews",
  "Analytics dashboards with custom filters",
];

const domSources = [
  "location.search, location.hash, location.pathname",
  "document.cookie (if not HttpOnly)",
  "localStorage and sessionStorage",
  "postMessage event data",
  "document.referrer",
  "window.name or injected JSON blobs",
];

const safeDomPractices = [
  "Prefer textContent or innerText over innerHTML",
  "Use createElement + appendChild for DOM building",
  "Sanitize HTML with DOMPurify before insertion",
  "Validate URL schemes before setting href or src",
  "Avoid eval or new Function for dynamic code",
];

const commonPayloads = [
  { payload: "<script>alert(1)</script>", context: "Basic test" },
  { payload: "<img src=x onerror=alert(1)>", context: "Event handler" },
  { payload: "<svg onload=alert(1)>", context: "SVG element" },
  { payload: "javascript:alert(1)", context: "URL scheme" },
  { payload: "'-alert(1)-'", context: "Attribute breakout" },
  { payload: "</script><script>alert(1)</script>", context: "Tag escape" },
  { payload: "\"><img src=x onerror=alert(1)>", context: "Quote escape" },
  { payload: "<a href=javascript:alert(1)>link</a>", context: "Link injection" },
];

const impactScenarios = [
  "Session hijacking (steal cookies)",
  "Keylogging user input",
  "Phishing via page modification",
  "Cryptocurrency mining",
  "Malware distribution",
  "Credential theft via fake login forms",
];

const preventionMethods = [
  "Context-aware output encoding (HTML, JS, URL, CSS)",
  "Content Security Policy (CSP) headers",
  "HttpOnly and Secure cookie flags",
  "Input validation (whitelist allowed chars)",
  "Use frameworks with auto-escaping (React, Angular)",
  "Sanitize HTML with DOMPurify or similar",
];

const dangerousSinks = [
  "innerHTML, outerHTML",
  "insertAdjacentHTML",
  "document.write()",
  "eval(), setTimeout(), setInterval()",
  "new Function()",
  "location.href, location.assign()",
  "setAttribute with untrusted href or src",
  "jQuery .html(), .append()",
];

const encodingContexts = [
  { context: "HTML body", risk: "Injected tags become real elements", safe: "Use HTML encoding or textContent" },
  { context: "HTML attribute", risk: "Quote breaking or event handler injection", safe: "Attribute encoding + allowlists" },
  { context: "URL", risk: "javascript: or data: schemes", safe: "Validate scheme with URL API" },
  { context: "JavaScript string", risk: "Break out of quotes", safe: "Avoid inline JS, use data attributes" },
  { context: "CSS", risk: "url() or expression injection", safe: "Avoid dynamic CSS or allowlist values" },
  { context: "JSON in HTML", risk: "Script breakouts in templates", safe: "Use JSON.stringify and escape safely" },
];

const detectionSignals = [
  "Unexpected HTML tags rendered in user content",
  "CSP reports blocking inline scripts",
  "WAF alerts for script or event handler patterns",
  "DOM changes after input is rendered",
  "User reports of popups or page tampering",
];

const testingChecklist = [
  "Map all input fields and where they render",
  "Identify the output context (HTML, attribute, URL, JS, CSS)",
  "Verify if output is encoded or sanitized",
  "Inspect the DOM in dev tools, not only the response",
  "Review client-side code for unsafe sinks",
  "Confirm CSP behavior in Report-Only mode",
];

const cspGuidelines = [
  "Start with default-src 'self' and add sources slowly",
  "Use nonces or hashes for scripts instead of unsafe-inline",
  "Avoid unsafe-eval unless absolutely required",
  "Set object-src 'none' and base-uri 'none'",
  "Enable Report-Only before enforcing blocking",
];

const responseSteps = [
  "Fix output encoding in the vulnerable context",
  "Remove or refactor unsafe DOM sinks",
  "Add a CSP policy and validate coverage",
  "Rotate sessions if exposure is suspected",
  "Add regression tests for the vulnerable view",
];

const frameworkNotes = [
  "React escapes by default; avoid dangerouslySetInnerHTML without sanitization.",
  "Angular sanitizes templates; avoid bypassSecurityTrust unless required.",
  "Vue escapes by default; v-html requires sanitization.",
  "Template engines with auto-escape can be bypassed with unsafe flags.",
];

const codeSamples = [
  {
    title: "Unsafe DOM injection",
    language: "javascript",
    code: `// Bad: user input becomes HTML
const input = location.hash.slice(1);
element.innerHTML = input;`,
  },
  {
    title: "Safe text rendering",
    language: "javascript",
    code: `// Good: user input becomes plain text
const input = location.hash.slice(1);
element.textContent = input;`,
  },
  {
    title: "Safe URL handling",
    language: "javascript",
    code: `const url = new URL(input, window.location.origin);
const allowed = ["http:", "https:"];
link.href = allowed.includes(url.protocol) ? url.href : "#";`,
  },
  {
    title: "React safe rendering",
    language: "jsx",
    code: `// Safe: React escapes by default
return <div>{comment}</div>;

// Risky: only use with sanitizer
return <div dangerouslySetInnerHTML={{ __html: comment }} />;`,
  },
  {
    title: "Sanitize rich HTML",
    language: "javascript",
    code: `import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(html);`,
  },
];

export default function XSSGuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Cross-Site Scripting (XSS) Guide - Covers reflected, stored, and DOM-based XSS types, attack flow, entry points, sources and sinks, context-aware encoding, detection signals, safe testing checklist, CSP guidance, and secure coding examples.`;

  return (
    <LearnPageLayout pageTitle="Cross-Site Scripting (XSS)" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
            Back to Learning Hub
          </Button>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box
              sx={{
                width: 64,
                height: 64,
                borderRadius: 2,
                bgcolor: alpha("#f59e0b", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <CodeIcon sx={{ fontSize: 36, color: "#f59e0b" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Cross-Site Scripting (XSS)
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Client-Side Code Injection
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Web Security" color="warning" size="small" />
            <Chip label="OWASP A03" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="Client-Side" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
          </Box>
        </Box>

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WebIcon color="warning" /> What is XSS?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other 
            users. The victim's browser executes the script in the context of the vulnerable site, enabling session 
            hijacking, data theft, and account takeover.
          </Typography>
        </Paper>

        {/* How XSS Happens */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#f59e0b" }} /> How XSS Works (Step-by-Step)
              </Typography>
              <List dense>
                {xssFlow.map((step) => (
                  <ListItem key={step} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={step} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#8b5cf6" }} /> Common Entry Points
              </Typography>
              <List dense>
                {entryPoints.map((item) => (
                  <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.04) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            High-Risk Features to Review
          </Typography>
          <Grid container spacing={1}>
            {highRiskFeatures.map((item) => (
              <Grid item xs={12} sm={6} key={item}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                  <Typography variant="body2">{item}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Sources and Sinks */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#3b82f6" }} /> Untrusted Sources
              </Typography>
              <List dense>
                {domSources.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#8b5cf6" }} /> Safer DOM Practices
              </Typography>
              <List dense>
                {safeDomPractices.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* XSS Types */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 XSS Types</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {xssTypes.map((type) => (
            <Grid item xs={12} md={4} key={type.title}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(type.color, 0.2)}`,
                  "&:hover": { borderColor: type.color },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: type.color }}>
                    {type.title}
                  </Typography>
                  <Chip label={type.persistence} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {type.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Context-Aware Encoding */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            Context-Aware Encoding Cheat Sheet
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            The safe fix depends on where the data is placed. Always encode for the correct context.
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Context</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Risk</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Safer Handling</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {encodingContexts.map((row) => (
                  <TableRow key={row.context}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.context}</TableCell>
                    <TableCell>{row.risk}</TableCell>
                    <TableCell>{row.safe}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* Common Payloads */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.05)}, ${alpha("#ef4444", 0.05)})`,
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BugReportIcon sx={{ color: "#f59e0b" }} /> Common Payloads
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Use these only in authorized environments. They help identify the context (HTML, attribute, URL) and confirm
            whether encoding or sanitization is working as expected.
          </Typography>
          <Grid container spacing={1}>
            {commonPayloads.map((p, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ p: 0.5, px: 1, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem", flexShrink: 0 }}>
                    {p.payload}
                  </Box>
                  <Typography variant="caption" color="text.secondary">{p.context}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Dangerous Sinks & Impact */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#8b5cf6" }} /> Dangerous Sinks (DOM XSS)
              </Typography>
              <List dense>
                {dangerousSinks.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} /> Impact Scenarios
              </Typography>
              <List dense>
                {impactScenarios.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Detection and Testing */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#3b82f6" }} /> Detection Signals
              </Typography>
              <List dense>
                {detectionSignals.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TipsAndUpdatesIcon sx={{ color: "#10b981" }} /> Safe Testing Checklist
              </Typography>
              <List dense>
                {testingChecklist.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Prevention */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#10b981" }} /> Prevention Methods
          </Typography>
          <Grid container spacing={1}>
            {preventionMethods.map((m, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                  <Typography variant="body2">{m}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon sx={{ color: "#f59e0b" }} /> CSP Essentials
              </Typography>
              <List dense>
                {cspGuidelines.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon sx={{ color: "#8b5cf6" }} /> Framework Notes
              </Typography>
              <List dense>
                {frameworkNotes.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#f59e0b" }} /> Secure Coding Examples
          </Typography>
          <Grid container spacing={2}>
            {codeSamples.map((sample) => (
              <Grid item xs={12} md={6} key={sample.title}>
                <Box sx={{ mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    {sample.title}
                  </Typography>
                </Box>
                <CodeBlock code={sample.code} language={sample.language} />
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.05) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#3b82f6" }} /> Response Steps
          </Typography>
          <Grid container spacing={1}>
            {responseSteps.map((m, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                  <Typography variant="body2">{m}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Tip */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 2,
            bgcolor: alpha("#3b82f6", 0.05),
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <TipsAndUpdatesIcon sx={{ color: "#3b82f6" }} />
          <Typography variant="body2">
            <strong>CSP Tip:</strong> Start with <code>Content-Security-Policy: default-src 'self'</code> and gradually add trusted sources.
          </Typography>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Command Injection →" clickable onClick={() => navigate("/learn/command-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="SQL Injection →" clickable onClick={() => navigate("/learn/sql-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="OWASP Top 10 →" clickable onClick={() => navigate("/learn/owasp")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
