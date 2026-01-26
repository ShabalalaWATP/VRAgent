import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  Card,
  CardContent,
  Breadcrumbs,
  Link as MuiLink,
  Divider,
  Button,
  Tabs,
  Tab,
} from "@mui/material";
import React from "react";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import DnsIcon from "@mui/icons-material/Dns";
import SecurityIcon from "@mui/icons-material/Security";
import SearchIcon from "@mui/icons-material/Search";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import InfoIcon from "@mui/icons-material/Info";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import CodeIcon from "@mui/icons-material/Code";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import EmailIcon from "@mui/icons-material/Email";
import LockIcon from "@mui/icons-material/Lock";
import PublicIcon from "@mui/icons-material/Public";
import SubdirectoryArrowRightIcon from "@mui/icons-material/SubdirectoryArrowRight";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import TimelineIcon from "@mui/icons-material/Timeline";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import CloudIcon from "@mui/icons-material/Cloud";
import LinkOffIcon from "@mui/icons-material/LinkOff";
import VerifiedIcon from "@mui/icons-material/Verified";
import HubIcon from "@mui/icons-material/Hub";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import TuneIcon from "@mui/icons-material/Tune";
import MapIcon from "@mui/icons-material/Map";
import BadgeIcon from "@mui/icons-material/Badge";

// Tab panel component
interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

// DNS Record Types reference
const DNS_RECORD_TYPES = [
  { type: "A", description: "Maps domain to IPv4 address", example: "example.com → 93.184.216.34", security: "Reveals server IP, enables further reconnaissance" },
  { type: "AAAA", description: "Maps domain to IPv6 address", example: "example.com → 2606:2800:220:1:248:1893:25c8:1946", security: "IPv6 may have different firewall rules" },
  { type: "MX", description: "Mail exchange servers", example: "example.com → mail.example.com (priority 10)", security: "Identifies email infrastructure for phishing analysis" },
  { type: "NS", description: "Authoritative nameservers", example: "example.com → ns1.example.com", security: "Zone transfer targets, DNS infrastructure attacks" },
  { type: "TXT", description: "Text records (SPF, DKIM, etc.)", example: "v=spf1 include:_spf.google.com ~all", security: "Reveals email providers, verification tokens" },
  { type: "CNAME", description: "Canonical name (alias)", example: "www.example.com → example.com", security: "May reveal CDNs, third-party services" },
  { type: "SOA", description: "Start of Authority", example: "Primary NS, admin email, serial", security: "DNS admin contact, zone serial for change detection" },
  { type: "SRV", description: "Service location records", example: "_sip._tcp.example.com → sipserver.example.com:5060", security: "Reveals internal services (SIP, LDAP, Kerberos)" },
  { type: "PTR", description: "Reverse DNS lookup", example: "34.216.184.93.in-addr.arpa → example.com", security: "Validates IP ownership, finds hidden domains" },
  { type: "CAA", description: "Certificate Authority Authorization", example: "0 issue \"letsencrypt.org\"", security: "Shows which CAs can issue certificates" },
];

// Common subdomains
const COMMON_SUBDOMAINS = [
  { category: "Web", subdomains: ["www", "www1", "www2", "web", "portal", "secure", "app", "apps"] },
  { category: "Development", subdomains: ["dev", "staging", "stage", "test", "qa", "uat", "demo", "beta", "sandbox"] },
  { category: "API", subdomains: ["api", "api1", "api2", "api-dev", "api-staging", "rest", "graphql", "ws"] },
  { category: "Email", subdomains: ["mail", "mail1", "smtp", "pop", "imap", "webmail", "mx", "exchange", "autodiscover"] },
  { category: "Infrastructure", subdomains: ["ns1", "ns2", "dns", "vpn", "remote", "gateway", "proxy", "lb", "cdn"] },
  { category: "Admin", subdomains: ["admin", "administrator", "cpanel", "webmin", "phpmyadmin", "manage", "dashboard"] },
  { category: "Database", subdomains: ["db", "database", "mysql", "postgres", "mongo", "redis", "sql"] },
  { category: "CI/CD", subdomains: ["jenkins", "gitlab", "github", "ci", "cd", "build", "deploy", "artifactory"] },
];

// Email security records
const EMAIL_SECURITY = [
  {
    name: "SPF (Sender Policy Framework)",
    purpose: "Specifies which mail servers can send email for your domain",
    record: "TXT",
    example: 'v=spf1 include:_spf.google.com -all',
    issues: [
      "+all allows any server to send (very insecure)",
      "~all softfail may not block spoofing",
      "Too many DNS lookups (>10) can break SPF",
      "Missing SPF = anyone can spoof your domain",
    ],
  },
  {
    name: "DMARC (Domain-based Message Authentication)",
    purpose: "Tells receivers how to handle SPF/DKIM failures",
    record: "TXT at _dmarc.domain.com",
    example: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
    issues: [
      "p=none provides no protection",
      "No rua/ruf = no visibility into failures",
      "pct<100 leaves gaps in coverage",
      "Missing DMARC = no enforcement",
    ],
  },
  {
    name: "DKIM (DomainKeys Identified Mail)",
    purpose: "Cryptographically signs emails to prove authenticity",
    record: "TXT at selector._domainkey.domain.com",
    example: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3...',
    issues: [
      "Weak key length (<2048 bits)",
      "Key not rotated regularly",
      "Missing DKIM = emails can be modified",
      "Multiple selectors may have different security",
    ],
  },
];

// Zone transfer vulnerability
const ZONE_TRANSFER_INFO = {
  description: "DNS zone transfer (AXFR) allows secondary DNS servers to copy the entire zone file from the primary server. If misconfigured, attackers can retrieve all DNS records at once.",
  risks: [
    "Reveals entire DNS infrastructure",
    "Exposes internal hostnames and IPs",
    "Shows all subdomains instantly",
    "May reveal network topology",
    "Provides reconnaissance goldmine",
  ],
  prevention: [
    "Restrict AXFR to known secondary servers by IP",
    "Use TSIG (Transaction Signature) for authentication",
    "Monitor for unauthorized transfer attempts",
    "Regularly audit DNS server configurations",
  ],
  testCommand: "dig @ns1.example.com example.com AXFR",
};

// VRAgent DNS Scan Types
const DNS_SCAN_TYPES = [
  {
    id: "quick",
    name: "Quick Scan",
    description: "Basic DNS records only (A, AAAA, MX, NS, TXT)",
    time: "5-15 sec",
    features: ["Basic record types", "No subdomain enumeration"],
    color: "#10b981",
  },
  {
    id: "standard",
    name: "Standard Scan",
    description: "All record types + top 50 subdomains + security check",
    time: "30-90 sec",
    features: ["All DNS record types", "Top 50 subdomains", "Email security check", "Zone transfer test"],
    color: "#3b82f6",
  },
  {
    id: "thorough",
    name: "Thorough Scan",
    description: "All records + 150 subdomains + full security analysis",
    time: "2-5 min",
    features: ["All DNS records", "150+ subdomains", "Full security analysis", "Takeover detection", "Cloud provider detection"],
    color: "#8b5cf6",
  },
  {
    id: "subdomain_focus",
    name: "Subdomain Enumeration",
    description: "Focused on finding subdomains (300+ checked)",
    time: "3-10 min",
    features: ["300+ subdomain checks", "Wildcard detection", "CT log search", "Dangling CNAME detection"],
    color: "#f59e0b",
  },
  {
    id: "security_focus",
    name: "Security Analysis",
    description: "Focus on email security (SPF, DMARC, DKIM, MTA-STS, BIMI) and DNSSEC",
    time: "30-60 sec",
    features: ["SPF analysis", "DMARC policy check", "DKIM validation", "MTA-STS detection", "BIMI record check", "DNSSEC status"],
    color: "#ef4444",
  },
];

// Subdomain Takeover Providers
const TAKEOVER_PROVIDERS = [
  { category: "Cloud Platforms", providers: ["AWS S3", "AWS CloudFront", "AWS Elastic Beanstalk", "Azure Web Apps", "Azure Blob Storage", "Azure CDN", "Google Cloud Storage", "Google App Engine", "Firebase"] },
  { category: "CDN & Hosting", providers: ["Fastly", "Heroku", "Netlify", "Vercel", "Surge.sh", "Pantheon", "WP Engine"] },
  { category: "Git Platforms", providers: ["GitHub Pages", "GitLab Pages", "Bitbucket"] },
  { category: "SaaS Services", providers: ["Shopify", "Zendesk", "ReadMe.io", "Freshdesk", "Statuspage", "UserVoice", "HelpJuice", "Ghost"] },
];

// Cloud Provider Detection Patterns
const CLOUD_PROVIDERS = [
  { provider: "AWS", patterns: ["amazonaws.com", "cloudfront.net", "elasticbeanstalk", "elb.amazonaws.com", "s3.amazonaws.com", "execute-api", "apigateway"], color: "#ff9900" },
  { provider: "Azure", patterns: ["azure", "microsoft.com", "windows.net", "azurewebsites.net", "azureedge.net", "cloudapp.azure.com"], color: "#0078d4" },
  { provider: "GCP", patterns: ["google", "googleapis.com", "appspot.com", "cloudfunctions.net", "run.app", "firebaseapp.com"], color: "#4285f4" },
  { provider: "Cloudflare", patterns: ["cloudflare"], color: "#f38020" },
  { provider: "Akamai", patterns: ["akamai", "akamaiedge", "akamaitechnologies"], color: "#0096d6" },
  { provider: "Fastly", patterns: ["fastly"], color: "#ff282d" },
  { provider: "Vercel", patterns: ["vercel", "now.sh"], color: "#000000" },
  { provider: "Netlify", patterns: ["netlify"], color: "#00c7b7" },
];

// Advanced Email Security (MTA-STS, BIMI)
const ADVANCED_EMAIL_SECURITY = [
  {
    name: "MTA-STS (Mail Transfer Agent Strict Transport Security)",
    record: "TXT at _mta-sts.domain.com",
    purpose: "Enforces TLS encryption for email delivery, preventing downgrade attacks",
    example: 'v=STSv1; id=20240101000000Z',
    requirements: ["Requires HTTPS-hosted policy file at .well-known/mta-sts.txt", "Policy specifies MX hosts and TLS requirements"],
  },
  {
    name: "BIMI (Brand Indicators for Message Identification)",
    record: "TXT at default._bimi.domain.com",
    purpose: "Displays brand logo next to authenticated emails, requires valid DMARC p=quarantine/reject",
    example: 'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem',
    requirements: ["DMARC policy must be quarantine or reject", "Logo must be SVG Tiny PS format", "Optional VMC (Verified Mark Certificate)"],
  },
];

export default function DNSGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  // State for advanced features tab
  const [advancedTab, setAdvancedTab] = React.useState(0);

  const pageContext = `This page covers DNS reconnaissance and security including:
- DNS record types: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, PTR, CAA
- Common subdomains for web, dev, API, email, infrastructure, admin, database, CI/CD
- Email security records: SPF, DMARC, DKIM configuration and issues
- Zone transfer vulnerabilities and prevention
- Subdomain enumeration techniques
- DNS security best practices and hardening
- Tools for DNS reconnaissance and analysis
- Advanced: Subdomain takeover detection, Cloud provider identification, CT logs, MTA-STS, BIMI`;

  return (
    <LearnPageLayout pageTitle="DNS Reconnaissance" pageContext={pageContext}>
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
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Breadcrumbs separator={<NavigateNextIcon fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink component={Link} to="/learn" color="inherit" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <MenuBookIcon fontSize="small" />
            Learn
          </MuiLink>
          <Typography color="text.primary" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <DnsIcon fontSize="small" />
            DNS Reconnaissance
          </Typography>
        </Breadcrumbs>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 3,
              background: `linear-gradient(135deg, #f59e0b 0%, #d97706 100%)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <DnsIcon sx={{ fontSize: 36, color: "white" }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              DNS Reconnaissance Guide
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Understanding DNS enumeration, subdomain discovery, and email security analysis
            </Typography>
          </Box>
        </Box>

        <Chip
          component={Link}
          to="/dynamic/dns"
          label="Open DNS Analyzer Tool →"
          clickable
          sx={{
            background: `linear-gradient(135deg, #f59e0b 0%, #d97706 100%)`,
            color: "white",
            fontWeight: 600,
            "&:hover": { opacity: 0.9 },
          }}
        />
      </Box>

      {/* Introduction */}
      <Paper sx={{ p: 3, mb: 4, background: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
          <InfoIcon color="warning" />
          What is DNS Reconnaissance?
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          DNS reconnaissance is the process of gathering information about a target's domain infrastructure through DNS queries.
          It's a critical first step in security assessments, revealing:
        </Typography>
        <Grid container spacing={2}>
          {[
            { icon: <StorageIcon />, text: "Server IP addresses and hosting providers" },
            { icon: <SubdirectoryArrowRightIcon />, text: "Subdomains and hidden services" },
            { icon: <EmailIcon />, text: "Email infrastructure and security configuration" },
            { icon: <PublicIcon />, text: "Third-party services and CDNs in use" },
            { icon: <SwapHorizIcon />, text: "Zone transfer vulnerabilities" },
            { icon: <LockIcon />, text: "Certificate authorities and DNSSEC status" },
          ].map((item, i) => (
            <Grid item xs={12} sm={6} md={4} key={i}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Box sx={{ color: "#f59e0b" }}>{item.icon}</Box>
                <Typography variant="body2">{item.text}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* VRAgent DNS Analyzer Features */}
      <Paper sx={{ p: 3, mb: 4, background: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
          <DnsIcon sx={{ color: "#06b6d4" }} />
          VRAgent DNS Analyzer Features
        </Typography>
        <Typography variant="body1" sx={{ mb: 3 }}>
          VRAgent's DNS Analyzer provides an integrated solution for DNS reconnaissance with powerful visualization and analysis features:
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <AccountTreeIcon sx={{ color: "#8b5cf6" }} />
                  <Typography variant="subtitle2" fontWeight={600}>Network Graph</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Interactive force-directed graph showing domain relationships - subdomains, IPs, mail servers, and nameservers with zoom/pan controls.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <SearchIcon sx={{ color: "#f59e0b" }} />
                  <Typography variant="subtitle2" fontWeight={600}>WHOIS Lookup</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Domain and IP WHOIS queries with parsed registrar info, dates, nameservers, ASN, organization, and abuse contacts.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <ContentCopyIcon sx={{ color: "#10b981" }} />
                  <Typography variant="subtitle2" fontWeight={600}>Copy to Clipboard</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  One-click copy buttons for individual records, IPs, subdomains, plus "Copy All" for bulk export to other tools.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <SmartToyIcon sx={{ color: "#3b82f6" }} />
                  <Typography variant="subtitle2" fontWeight={600}>AI Analysis & Chat</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Gemini AI provides security assessment, key findings, and recommendations. Chat interface for follow-up questions.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {/* VRAgent Advanced DNS Features */}
      <Paper
        sx={{
          p: 3,
          mb: 4,
          background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#ef4444", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
          <GppMaybeIcon sx={{ color: "#ef4444", fontSize: 32 }} />
          <Box>
            <Typography variant="h6" fontWeight={700}>
              VRAgent Advanced DNS Features
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Offensive security capabilities for thorough DNS reconnaissance
            </Typography>
          </Box>
        </Box>

        <Tabs
          value={advancedTab}
          onChange={(_, v) => setAdvancedTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            mt: 2,
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none" },
          }}
        >
          <Tab icon={<TuneIcon />} iconPosition="start" label="Scan Types" />
          <Tab icon={<LinkOffIcon />} iconPosition="start" label="Subdomain Takeover" />
          <Tab icon={<CloudIcon />} iconPosition="start" label="Cloud Detection" />
          <Tab icon={<VerifiedIcon />} iconPosition="start" label="CT Logs & ASN" />
          <Tab icon={<BadgeIcon />} iconPosition="start" label="MTA-STS & BIMI" />
        </Tabs>

        {/* Scan Types Tab */}
        <TabPanel value={advancedTab} index={0}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            VRAgent offers <strong>5 specialized scan profiles</strong> to match your reconnaissance needs:
          </Typography>
          <Grid container spacing={2}>
            {DNS_SCAN_TYPES.map((scanType) => (
              <Grid item xs={12} sm={6} key={scanType.id}>
                <Paper
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    border: `1px solid ${alpha(scanType.color, 0.3)}`,
                    bgcolor: alpha(scanType.color, 0.02),
                    height: "100%",
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{scanType.name}</Typography>
                    <Chip label={scanType.time} size="small" sx={{ bgcolor: alpha(scanType.color, 0.1), color: scanType.color }} />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {scanType.description}
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {scanType.features.map((feature) => (
                      <Chip
                        key={feature}
                        label={feature}
                        size="small"
                        variant="outlined"
                        sx={{ fontSize: "0.65rem", height: 22 }}
                      />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        {/* Subdomain Takeover Tab */}
        <TabPanel value={advancedTab} index={1}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            VRAgent detects <strong>50+ subdomain takeover signatures</strong> across cloud platforms, CDNs, and SaaS services.
            A takeover occurs when a CNAME points to an external service that no longer exists, allowing attackers to claim it.
          </Typography>

          <Paper
            sx={{
              p: 2,
              mb: 3,
              bgcolor: alpha("#ef4444", 0.05),
              border: `1px solid ${alpha("#ef4444", 0.2)}`,
            }}
          >
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: "#ef4444" }}>
              ⚠️ How Subdomain Takeover Works
            </Typography>
            <List dense disablePadding>
              <ListItem disableGutters>
                <ListItemIcon sx={{ minWidth: 28 }}><Typography variant="body2">1.</Typography></ListItemIcon>
                <ListItemText primary="subdomain.example.com has CNAME → myapp.herokuapp.com" primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
              <ListItem disableGutters>
                <ListItemIcon sx={{ minWidth: 28 }}><Typography variant="body2">2.</Typography></ListItemIcon>
                <ListItemText primary="Organization deletes the Heroku app but forgets to remove DNS record" primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
              <ListItem disableGutters>
                <ListItemIcon sx={{ minWidth: 28 }}><Typography variant="body2">3.</Typography></ListItemIcon>
                <ListItemText primary="Attacker creates 'myapp' on Heroku and now controls subdomain.example.com" primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            </List>
          </Paper>

          <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 2 }}>Monitored Providers:</Typography>
          <Grid container spacing={2}>
            {TAKEOVER_PROVIDERS.map((cat) => (
              <Grid item xs={12} sm={6} md={3} key={cat.category}>
                <Paper sx={{ p: 2, height: "100%" }}>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: "#8b5cf6" }}>{cat.category}</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
                    {cat.providers.map((p) => (
                      <Chip key={p} label={p} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 20 }} />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        {/* Cloud Detection Tab */}
        <TabPanel value={advancedTab} index={2}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            VRAgent automatically identifies <strong>cloud infrastructure</strong> from DNS records and CNAMEs,
            revealing hosting providers, CDNs, and specific services in use.
          </Typography>

          <Grid container spacing={2}>
            {CLOUD_PROVIDERS.map((provider) => (
              <Grid item xs={12} sm={6} md={3} key={provider.provider}>
                <Paper
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    border: `2px solid ${provider.color}`,
                    bgcolor: alpha(provider.color, 0.02),
                    height: "100%",
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: provider.color }}>
                    {provider.provider}
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {provider.patterns.slice(0, 4).map((pattern) => (
                      <Chip
                        key={pattern}
                        label={pattern}
                        size="small"
                        sx={{ fontSize: "0.65rem", height: 20, bgcolor: alpha(provider.color, 0.1) }}
                      />
                    ))}
                    {provider.patterns.length > 4 && (
                      <Chip label={`+${provider.patterns.length - 4}`} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                    )}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
            <Typography variant="body2">
              <strong>💡 Why It Matters:</strong> Cloud provider detection helps identify potential security boundaries,
              shared responsibility models, and enables targeted testing (e.g., S3 bucket misconfiguration checks for AWS,
              Blob storage public access for Azure).
            </Typography>
          </Paper>
        </TabPanel>

        {/* CT Logs & ASN Tab */}
        <TabPanel value={advancedTab} index={3}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
                  bgcolor: alpha("#8b5cf6", 0.02),
                  height: "100%",
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <VerifiedIcon sx={{ color: "#8b5cf6" }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    Certificate Transparency Logs
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  CT logs are public records of SSL certificates issued for domains. VRAgent searches these logs to discover
                  subdomains that may not be found through DNS brute-forcing.
                </Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Advantages:</Typography>
                <List dense disablePadding>
                  {[
                    "Discovers subdomains that may not resolve in DNS",
                    "Finds internal/staging subdomains that got certificates",
                    "Passive reconnaissance - no direct queries to target",
                    "Historical data shows previously used subdomains",
                  ].map((item, idx) => (
                    <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#10b981", 0.3)}`,
                  bgcolor: alpha("#10b981", 0.02),
                  height: "100%",
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <HubIcon sx={{ color: "#10b981" }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    ASN/BGP Information
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  For each discovered IP, VRAgent retrieves Autonomous System Number (ASN) and BGP routing information,
                  helping identify the organization and network that owns the IP space.
                </Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Retrieved Data:</Typography>
                <List dense disablePadding>
                  {[
                    "ASN number and name",
                    "Organization that owns the IP block",
                    "Network CIDR range",
                    "Country/region information",
                    "Geographic distribution of infrastructure",
                  ].map((item, idx) => (
                    <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          {/* Additional Features */}
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1.5 }}>Additional Detection Features</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 2, textAlign: "center" }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>Wildcard DNS</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Detects if domain uses wildcard A records (*.example.com)
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 2, textAlign: "center" }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>Dangling CNAMEs</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Identifies CNAMEs pointing to non-resolving targets
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 2, textAlign: "center" }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>Geo Distribution</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Maps IP addresses to countries for infrastructure overview
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* MTA-STS & BIMI Tab */}
        <TabPanel value={advancedTab} index={4}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Beyond SPF, DMARC, and DKIM, VRAgent checks for modern email security standards that provide 
            additional protection and brand verification.
          </Typography>

          <Grid container spacing={3}>
            {ADVANCED_EMAIL_SECURITY.map((item) => (
              <Grid item xs={12} md={6} key={item.name}>
                <Paper
                  sx={{
                    p: 3,
                    borderRadius: 2,
                    border: `1px solid ${alpha("#f59e0b", 0.3)}`,
                    height: "100%",
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                    {item.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {item.purpose}
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Record Location:</Typography>
                    <Chip label={item.record} size="small" sx={{ ml: 1 }} />
                  </Box>
                  <Box
                    component="pre"
                    sx={{
                      p: 1.5,
                      bgcolor: alpha("#f59e0b", 0.1),
                      borderRadius: 1,
                      fontFamily: "monospace",
                      fontSize: "0.75rem",
                      overflow: "auto",
                      mb: 2,
                    }}
                  >
                    {item.example}
                  </Box>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Requirements:</Typography>
                  <List dense disablePadding>
                    {item.requirements.map((req, idx) => (
                      <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 20 }}>
                          <CheckCircleIcon sx={{ fontSize: 12, color: "#f59e0b" }} />
                        </ListItemIcon>
                        <ListItemText primary={req} primaryTypographyProps={{ variant: "caption" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
            <Typography variant="body2">
              <strong>✅ Email Security Score Update:</strong> VRAgent now includes MTA-STS and BIMI in its email security 
              scoring. Having all 5 records (SPF, DMARC, DKIM, MTA-STS, BIMI) properly configured represents maximum email 
              authentication maturity.
            </Typography>
          </Paper>
        </TabPanel>
      </Paper>

      {/* DNS Record Types */}
      <Accordion defaultExpanded sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <StorageIcon />
            DNS Record Types Reference
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Security Relevance</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {DNS_RECORD_TYPES.map((record) => (
                  <TableRow key={record.type} hover>
                    <TableCell>
                      <Chip
                        label={record.type}
                        size="small"
                        sx={{
                          fontFamily: "monospace",
                          fontWeight: 700,
                          bgcolor: alpha("#f59e0b", 0.15),
                          color: "#d97706",
                        }}
                      />
                    </TableCell>
                    <TableCell>{record.description}</TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                        {record.example}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {record.security}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Subdomain Enumeration */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SubdirectoryArrowRightIcon />
            Subdomain Enumeration
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Subdomain enumeration discovers hidden services by testing common subdomain names against a target domain.
            Many organizations expose development, staging, or administrative interfaces through subdomains.
          </Typography>

          <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
            Common Subdomain Categories
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {COMMON_SUBDOMAINS.map((cat) => (
              <Grid item xs={12} sm={6} md={3} key={cat.category}>
                <Card variant="outlined">
                  <CardContent sx={{ p: 2 }}>
                    <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                      {cat.category}
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {cat.subdomains.map((sub) => (
                        <Chip
                          key={sub}
                          label={sub}
                          size="small"
                          variant="outlined"
                          sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}
                        />
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
            <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon fontSize="small" color="error" />
              Security Implications
            </Typography>
            <List dense>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="Development/staging servers often have weaker security" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="Admin panels may be exposed without proper authentication" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="API endpoints might lack rate limiting or authentication" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="Internal services exposed to the internet" />
              </ListItem>
            </List>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* Zone Transfer */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SwapHorizIcon />
            Zone Transfer Vulnerability (AXFR)
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#dc2626", 0.1), border: `1px solid ${alpha("#dc2626", 0.3)}` }}>
            <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 1, color: "#dc2626" }}>
              ⚠️ Critical Misconfiguration
            </Typography>
            <Typography variant="body2">
              {ZONE_TRANSFER_INFO.description}
            </Typography>
          </Paper>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                Risks of Exposed Zone Transfers
              </Typography>
              <List dense>
                {ZONE_TRANSFER_INFO.risks.map((risk, i) => (
                  <ListItem key={i}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <WarningIcon fontSize="small" color="error" />
                    </ListItemIcon>
                    <ListItemText primary={risk} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                Prevention Measures
              </Typography>
              <List dense>
                {ZONE_TRANSFER_INFO.prevention.map((item, i) => (
                  <ListItem key={i}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon fontSize="small" color="success" />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
            <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon fontSize="small" />
              Manual Testing Command
            </Typography>
            <Box
              component="pre"
              sx={{
                p: 2,
                bgcolor: "#1e1e1e",
                color: "#d4d4d4",
                borderRadius: 1,
                overflow: "auto",
                fontFamily: "monospace",
                fontSize: "0.85rem",
              }}
            >
              {ZONE_TRANSFER_INFO.testCommand}
            </Box>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* Email Security */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <EmailIcon />
            Email Security Analysis (SPF, DMARC, DKIM)
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Email security relies on DNS records to authenticate senders and prevent spoofing.
            Proper configuration of SPF, DMARC, and DKIM is essential for protecting against phishing attacks.
          </Typography>

          {EMAIL_SECURITY.map((item, index) => (
            <Paper key={item.name} sx={{ p: 2, mb: 2, border: `1px solid ${alpha(theme.palette.divider, 0.2)}` }}>
              <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 1 }}>
                {item.name}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                {item.purpose}
              </Typography>

              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary">
                  Record Type: <Chip label={item.record} size="small" sx={{ ml: 1 }} />
                </Typography>
              </Box>

              <Box
                component="pre"
                sx={{
                  p: 1.5,
                  bgcolor: alpha("#10b981", 0.1),
                  borderRadius: 1,
                  fontFamily: "monospace",
                  fontSize: "0.8rem",
                  mb: 2,
                  overflow: "auto",
                }}
              >
                {item.example}
              </Box>

              <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                Common Issues to Check:
              </Typography>
              <List dense>
                {item.issues.map((issue, i) => (
                  <ListItem key={i} sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon fontSize="small" color="warning" />
                    </ListItemIcon>
                    <ListItemText primary={issue} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          ))}

          {/* Email Security Score */}
          <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
            <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
              Email Security Score Calculation
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Component</TableCell>
                    <TableCell align="center">Max Points</TableCell>
                    <TableCell>Requirements</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell>SPF Record</TableCell>
                    <TableCell align="center">40</TableCell>
                    <TableCell>Present (30) + No issues (10)</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>DMARC Record</TableCell>
                    <TableCell align="center">40</TableCell>
                    <TableCell>Present (30) + p=reject (10) or p=quarantine (5)</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>DKIM Record</TableCell>
                    <TableCell align="center">20</TableCell>
                    <TableCell>At least one selector found</TableCell>
                  </TableRow>
                  <TableRow sx={{ bgcolor: alpha("#10b981", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Total</TableCell>
                    <TableCell align="center" sx={{ fontWeight: 700 }}>100</TableCell>
                    <TableCell>70+ = Good, 40-69 = Fair, &lt;40 = Poor</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* WHOIS Lookup */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SearchIcon />
            WHOIS Lookup
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body1" sx={{ mb: 2 }}>
            WHOIS is a protocol for querying databases that store registered domain and IP address information.
            It reveals ownership details, registration dates, and contact information - crucial for security investigations.
          </Typography>

          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, color: "#3b82f6" }}>
                  Domain WHOIS Information
                </Typography>
                <List dense>
                  <ListItem><ListItemText primary="Registrar & registration dates" /></ListItem>
                  <ListItem><ListItemText primary="Name servers (authoritative DNS)" /></ListItem>
                  <ListItem><ListItemText primary="Domain status codes (clientTransferProhibited, etc.)" /></ListItem>
                  <ListItem><ListItemText primary="Registrant organization & country (when not privacy-protected)" /></ListItem>
                  <ListItem><ListItemText primary="Expiration date (useful for expired domain attacks)" /></ListItem>
                  <ListItem><ListItemText primary="DNSSEC signing status" /></ListItem>
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, color: "#8b5cf6" }}>
                  IP WHOIS Information
                </Typography>
                <List dense>
                  <ListItem><ListItemText primary="Network name and CIDR range" /></ListItem>
                  <ListItem><ListItemText primary="ASN (Autonomous System Number)" /></ListItem>
                  <ListItem><ListItemText primary="Organization that owns the IP block" /></ListItem>
                  <ListItem><ListItemText primary="Regional Internet Registry (ARIN, RIPE, APNIC)" /></ListItem>
                  <ListItem><ListItemText primary="Abuse contact email for reporting" /></ListItem>
                  <ListItem><ListItemText primary="Country and allocation dates" /></ListItem>
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), border: `1px solid ${alpha("#dc2626", 0.2)}`, mb: 2 }}>
            <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1, color: "#dc2626" }}>
              <WarningIcon fontSize="small" />
              Security Implications of WHOIS
            </Typography>
            <List dense>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="Expired domain takeover - Monitor expiration dates for critical domains" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="Social engineering - Registrant contact info can be used for targeted phishing" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="Infrastructure mapping - ASN and network info reveals hosting providers" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 32 }}><BugReportIcon fontSize="small" color="error" /></ListItemIcon>
                <ListItemText primary="Brand protection - Monitor for typosquatting and lookalike domains" />
              </ListItem>
            </List>
          </Paper>

          <Paper sx={{ p: 2, bgcolor: "#1e1e1e" }}>
            <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, color: "#4ec9b0" }}>
              Command Line WHOIS
            </Typography>
            <Box component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", m: 0 }}>
{`# Domain WHOIS lookup
whois example.com

# IP WHOIS lookup
whois 8.8.8.8

# Query specific WHOIS server
whois -h whois.verisign-grs.com example.com`}
            </Box>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* DNSSEC */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LockIcon />
            DNSSEC (DNS Security Extensions)
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body1" sx={{ mb: 2 }}>
            DNSSEC adds cryptographic signatures to DNS records, ensuring that responses haven't been tampered with.
            Without DNSSEC, attackers can perform DNS cache poisoning to redirect users to malicious sites.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, color: "#10b981" }}>
                  ✅ Benefits of DNSSEC
                </Typography>
                <List dense>
                  <ListItem><ListItemText primary="Prevents DNS cache poisoning attacks" /></ListItem>
                  <ListItem><ListItemText primary="Ensures DNS responses haven't been modified" /></ListItem>
                  <ListItem><ListItemText primary="Provides chain of trust from root DNS" /></ListItem>
                  <ListItem><ListItemText primary="Required for DANE (DNS-based authentication)" /></ListItem>
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, color: "#f59e0b" }}>
                  ⚠️ DNSSEC Considerations
                </Typography>
                <List dense>
                  <ListItem><ListItemText primary="Increases DNS response size" /></ListItem>
                  <ListItem><ListItemText primary="Key management complexity" /></ListItem>
                  <ListItem><ListItemText primary="Not all resolvers validate DNSSEC" /></ListItem>
                  <ListItem><ListItemText primary="Misconfiguration can break DNS resolution" /></ListItem>
                </List>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Tools & Commands */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon />
            DNS Reconnaissance Tools & Commands
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Common command-line tools for DNS reconnaissance:
          </Typography>

          {[
            {
              tool: "dig",
              description: "DNS lookup utility (most comprehensive)",
              commands: [
                "dig example.com ANY            # All records",
                "dig example.com MX             # Mail servers",
                "dig @8.8.8.8 example.com A     # Query specific DNS",
                "dig +short example.com A       # Just the answer",
                "dig example.com AXFR           # Zone transfer attempt",
              ],
            },
            {
              tool: "nslookup",
              description: "Interactive DNS query tool",
              commands: [
                "nslookup example.com",
                "nslookup -type=mx example.com",
                "nslookup -type=txt example.com",
                "nslookup -type=ns example.com",
              ],
            },
            {
              tool: "host",
              description: "Simple DNS lookup utility",
              commands: [
                "host example.com",
                "host -t mx example.com",
                "host -t txt example.com",
                "host -a example.com            # All records",
              ],
            },
            {
              tool: "dnsrecon",
              description: "Python DNS enumeration tool",
              commands: [
                "dnsrecon -d example.com",
                "dnsrecon -d example.com -t std    # Standard enum",
                "dnsrecon -d example.com -t brt    # Brute force subdomains",
                "dnsrecon -d example.com -t axfr   # Zone transfer",
              ],
            },
          ].map((item) => (
            <Paper key={item.tool} sx={{ p: 2, mb: 2, bgcolor: "#1e1e1e" }}>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 0.5, color: "#4ec9b0" }}>
                {item.tool}
              </Typography>
              <Typography variant="caption" sx={{ color: "#808080", display: "block", mb: 1 }}>
                {item.description}
              </Typography>
              <Box component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", m: 0 }}>
                {item.commands.join("\n")}
              </Box>
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      {/* Best Practices */}
      <Paper sx={{ p: 3, background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)} 0%, ${alpha("#059669", 0.05)} 100%)`, border: `1px solid ${alpha("#10b981", 0.3)}` }}>
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
          <SecurityIcon color="success" />
          DNS Security Best Practices
        </Typography>
        <Grid container spacing={2}>
          {[
            "Restrict zone transfers to authorized secondary DNS servers",
            "Implement SPF, DMARC, and DKIM for email authentication",
            "Enable DNSSEC for critical domains",
            "Add CAA records to control certificate issuance",
            "Regularly audit DNS records for unused or stale entries",
            "Monitor for unauthorized subdomain creation",
            "Use split-horizon DNS to separate internal/external records",
            "Keep DNS software up to date with security patches",
          ].map((practice, i) => (
            <Grid item xs={12} sm={6} key={i}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                <CheckCircleIcon fontSize="small" color="success" sx={{ mt: 0.25 }} />
                <Typography variant="body2">{practice}</Typography>
              </Box>
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
          sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
        >
          Back to Learning Hub
        </Button>
      </Box>
    </Container>
    </LearnPageLayout>
  );
}
