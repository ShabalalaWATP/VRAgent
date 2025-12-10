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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
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
  IconButton,
  Tooltip,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import TravelExploreIcon from "@mui/icons-material/TravelExplore";
import PersonSearchIcon from "@mui/icons-material/PersonSearch";
import DnsIcon from "@mui/icons-material/Dns";
import BusinessIcon from "@mui/icons-material/Business";
import SecurityIcon from "@mui/icons-material/Security";
import CodeIcon from "@mui/icons-material/Code";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import ImageIcon from "@mui/icons-material/Image";
import GitHubIcon from "@mui/icons-material/GitHub";
import PublicIcon from "@mui/icons-material/Public";
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

const CodeBlock: React.FC<{ code: string; language?: string }> = ({ code, language = "bash" }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper sx={{ p: 2, bgcolor: "#1a1a2e", borderRadius: 2, position: "relative", my: 2, border: "1px solid rgba(249, 115, 22, 0.3)" }}>
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#f97316" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "grey.400" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box component="pre" sx={{ m: 0, overflow: "auto", color: "#e2e8f0", fontSize: "0.85rem", fontFamily: "monospace", pt: 3 }}>
        {code}
      </Box>
    </Paper>
  );
};

const OSINTReconPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
      <Container maxWidth="lg">
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
            Back to Learn Hub
          </Button>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <TravelExploreIcon sx={{ fontSize: 40, color: "#f97316" }} />
            <Typography
              variant="h3"
              sx={{
                fontWeight: 700,
                background: "linear-gradient(135deg, #f97316 0%, #ea580c 100%)",
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                color: "transparent",
              }}
            >
              OSINT & Reconnaissance
            </Typography>
          </Box>
          <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
            Open Source Intelligence gathering and target reconnaissance techniques
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip icon={<PersonSearchIcon />} label="Passive Recon" size="small" />
            <Chip icon={<DnsIcon />} label="Domain Intel" size="small" />
            <Chip icon={<BusinessIcon />} label="Organization" size="small" />
          </Box>
        </Box>

        {/* Tabs */}
        <Paper sx={{ bgcolor: "#12121a", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.1)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#f97316" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Fundamentals" />
            <Tab icon={<DnsIcon />} label="Domain Recon" />
            <Tab icon={<PersonSearchIcon />} label="People & Orgs" />
            <Tab icon={<ImageIcon />} label="Images & Metadata" />
            <Tab icon={<GitHubIcon />} label="Code & Repos" />
            <Tab icon={<PublicIcon />} label="Advanced OSINT" />
            <Tab icon={<CodeIcon />} label="Tools" />
          </Tabs>

          {/* Tab 0: Fundamentals */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3 }}>
                OSINT Fundamentals
              </Typography>

              <Alert severity="warning" sx={{ mb: 3 }}>
                <strong>Legal Note:</strong> Only gather information you're authorized to collect. Respect privacy laws and terms of service.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">What is OSINT?</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Open Source Intelligence (OSINT) is intelligence collected from publicly available sources. It's the foundation of any security assessment.
                  </Typography>
                  <Grid container spacing={2}>
                    {[
                      { title: "Passive Recon", desc: "No direct target interaction", color: "#10b981" },
                      { title: "Active Recon", desc: "Direct probing (leaves traces)", color: "#ef4444" },
                      { title: "Social Engineering", desc: "Human intelligence gathering", color: "#8b5cf6" },
                    ].map((item) => (
                      <Grid item xs={12} sm={4} key={item.title}>
                        <Paper sx={{ p: 2, bgcolor: "#0f1024", border: `1px solid ${item.color}30` }}>
                          <Typography sx={{ color: item.color, fontWeight: 600 }}>{item.title}</Typography>
                          <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">OSINT Framework Categories</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Domain & IP Intelligence",
                      "Email & Username Searches",
                      "Social Media Analysis",
                      "Image & Metadata Analysis",
                      "Document & File Discovery",
                      "Code Repository Mining",
                      "Dark Web Monitoring",
                      "Geolocation Intelligence",
                    ].map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#f97316" }} /></ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Reconnaissance Methodology</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Follow a structured approach to maximize coverage:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Phase</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Activities</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Output</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["1. Scope Definition", "Define targets, rules of engagement", "Target list, boundaries"],
                          ["2. Passive Recon", "WHOIS, DNS, cert transparency, public records", "Domains, IPs, emails"],
                          ["3. Semi-Passive", "Search engines, social media, job postings", "People, tech stack, structure"],
                          ["4. Active Recon", "Port scanning, banner grabbing, crawling", "Services, versions, endpoints"],
                          ["5. Analysis", "Correlate data, identify patterns", "Attack surface map"],
                          ["6. Documentation", "Organize findings, prioritize targets", "Recon report"],
                        ].map(([phase, activities, output]) => (
                          <TableRow key={phase}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 500 }}>{phase}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{activities}</TableCell>
                            <TableCell sx={{ color: "#4ade80" }}>{output}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">OPSEC Considerations</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="error" sx={{ mb: 2 }}>
                    Your reconnaissance activities can be detected. Practice good operational security.
                  </Alert>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #ef444430" }}>
                        <Typography sx={{ color: "#ef4444", fontWeight: 600, mb: 1 }}>Detection Risks</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "Your IP logged in access logs",
                            "Account creation tracked",
                            "Search patterns analyzed",
                            "API rate limits triggering alerts",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #10b98130" }}>
                        <Typography sx={{ color: "#10b981", fontWeight: 600, mb: 1 }}>Mitigations</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "Use VPN/Tor for sensitive searches",
                            "Rotate IPs and user agents",
                            "Use sock puppet accounts",
                            "Spread queries over time",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 1: Domain Recon */}
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3 }}>
                Domain & Infrastructure Reconnaissance
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                Domain recon reveals subdomains, IP ranges, hosting providers, and technology stacks - the foundation of your attack surface map.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Subdomain Enumeration</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Subdomains often host dev environments, admin panels, and forgotten services with weaker security.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# Subfinder - Fast passive subdomain discovery
subfinder -d target.com -o subdomains.txt
subfinder -d target.com -all -recursive  # Deep recursive scan

# Amass - Comprehensive enumeration (passive + active)
amass enum -passive -d target.com -o amass_passive.txt
amass enum -active -d target.com -o amass_active.txt
amass enum -brute -d target.com -w wordlist.txt  # Bruteforce

# Assetfinder - Quick discovery
assetfinder --subs-only target.com | sort -u

# Findomain - Fast cross-platform tool
findomain -t target.com -o

# crt.sh - Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Combine multiple tools for best coverage
subfinder -d target.com -silent | anew subs.txt
assetfinder --subs-only target.com | anew subs.txt
amass enum -passive -d target.com | anew subs.txt
cat subs.txt | httpx -silent -o live_subs.txt  # Probe live hosts`}
                  />
                  <Grid container spacing={2} sx={{ mt: 2 }}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #10b98130" }}>
                        <Typography sx={{ color: "#10b981", fontWeight: 600, mb: 1 }}>Passive Sources</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "Certificate Transparency (crt.sh)",
                            "DNS aggregators (SecurityTrails)",
                            "Web archives (Wayback Machine)",
                            "Search engine caches",
                            "VirusTotal passive DNS",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 16 }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #ef444430" }}>
                        <Typography sx={{ color: "#ef4444", fontWeight: 600, mb: 1 }}>Active Techniques</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "DNS bruteforcing (detected!)",
                            "Virtual host enumeration",
                            "Zone transfer attempts",
                            "DNSSEC walking",
                            "Reverse DNS sweeps",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemIcon><WarningIcon sx={{ color: "#ef4444", fontSize: 16 }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">DNS & WHOIS Intelligence</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    DNS records reveal mail servers, cloud providers, and internal naming conventions. WHOIS exposes registration details and contact info.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# WHOIS lookup - Registration details
whois target.com
whois -h whois.arin.net 192.168.1.1  # IP WHOIS

# DNS record enumeration
dig target.com ANY +noall +answer
dig target.com A +short
dig target.com MX +short         # Mail servers
dig target.com NS +short         # Name servers
dig target.com TXT +short        # SPF, DKIM, DMARC
dig target.com CNAME +short
dig _dmarc.target.com TXT        # DMARC policy

# Reverse DNS lookup
dig -x 192.168.1.1 +short
host 192.168.1.1

# DNS zone transfer (often blocked)
dig axfr @ns1.target.com target.com
host -l target.com ns1.target.com

# DNSRecon - Comprehensive DNS enumeration
dnsrecon -d target.com -t std,brt,srv,axfr
dnsrecon -d target.com -D wordlist.txt -t brt  # Bruteforce

# Fierce - DNS reconnaissance
fierce --domain target.com

# MassDNS - High-performance DNS resolver
massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt`}
                  />
                  <TableContainer sx={{ mt: 2 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Record Type</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Intelligence Value</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Example Finding</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["A/AAAA", "IP addresses, hosting provider", "AWS, Azure, on-prem datacenter"],
                          ["MX", "Mail infrastructure, filtering", "Google Workspace, O365, Proofpoint"],
                          ["NS", "DNS provider, potential takeover", "Route53, Cloudflare"],
                          ["TXT", "SPF/DKIM/DMARC, verification tokens", "Weak SPF = spoofing possible"],
                          ["CNAME", "Third-party services, CDNs", "Subdomain takeover candidates"],
                          ["SOA", "Primary NS, admin email", "admin@target.com"],
                        ].map(([type, value, example]) => (
                          <TableRow key={type}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 600, fontFamily: "monospace" }}>{type}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{value}</TableCell>
                            <TableCell sx={{ color: "#4ade80", fontSize: "0.85rem" }}>{example}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Shodan, Censys & Internet Scanners</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Internet-wide scanners index exposed services, banners, and vulnerabilities without you touching the target.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# === SHODAN ===
# CLI setup
pip install shodan
shodan init YOUR_API_KEY

# Basic searches
shodan search "hostname:target.com"
shodan host 192.168.1.1
shodan domain target.com  # All known hosts

# Advanced Shodan dorks
ssl.cert.subject.cn:"target.com"              # SSL cert matches
http.title:"Login" org:"Target Inc"           # Login pages
port:3389 org:"Target"                         # Exposed RDP
product:"Apache" org:"Target" vuln:CVE-2021   # Vulnerable Apache
"X-Jenkins" org:"Target"                       # Jenkins instances
http.favicon.hash:-335242539 org:"Target"     # By favicon hash

# === CENSYS ===
censys search "services.tls.certificates.leaf.names: target.com"
censys search "services.http.response.headers.server: nginx" AND "ip: 192.168.0.0/16"

# === OTHER SCANNERS ===
# Fofa (Chinese Shodan)
# ZoomEye
# BinaryEdge
# GreyNoise (identify scanners hitting you)

# === FAVICON HASH (find related infra) ===
# Calculate favicon hash
python3 -c "import mmh3,requests,codecs; print(mmh3.hash(codecs.encode(requests.get('https://target.com/favicon.ico').content,'base64')))"
# Search: http.favicon.hash:<hash>`}
                  />
                  <Grid container spacing={2} sx={{ mt: 2 }}>
                    {[
                      { name: "Shodan", desc: "Best for IoT, ICS, exposed services", color: "#ef4444" },
                      { name: "Censys", desc: "Best for TLS certs, detailed metadata", color: "#f97316" },
                      { name: "Fofa", desc: "Largest Chinese internet index", color: "#8b5cf6" },
                      { name: "ZoomEye", desc: "Good for Asian infrastructure", color: "#06b6d4" },
                    ].map((scanner) => (
                      <Grid item xs={6} md={3} key={scanner.name}>
                        <Paper sx={{ p: 2, bgcolor: "#0f1024", border: `1px solid ${scanner.color}30`, textAlign: "center" }}>
                          <Typography sx={{ color: scanner.color, fontWeight: 700 }}>{scanner.name}</Typography>
                          <Typography variant="caption" sx={{ color: "grey.500" }}>{scanner.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Technology Stack Discovery</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Wappalyzer CLI - Identify web technologies
npx wappalyzer https://target.com

# WhatWeb - Web scanner
whatweb target.com -v
whatweb -i urls.txt --log-json=results.json

# Webanalyze (Go-based Wappalyzer)
webanalyze -host target.com -crawl 2

# BuiltWith lookup
# builtwith.com - Commercial but detailed

# HTTP headers analysis
curl -I https://target.com
curl -sI https://target.com | grep -i "server\|x-powered\|x-aspnet\|x-generator"

# JavaScript libraries
curl -s https://target.com | grep -oE 'src="[^"]+\.js"' | head -20

# Identify CMS
cmsmap -t https://target.com

# WordPress specific
wpscan --url https://target.com --enumerate u,p,t`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Historical Data & Archives</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Old versions of websites often contain sensitive info, exposed endpoints, or credentials that were later removed.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# Wayback Machine - Historical snapshots
# web.archive.org/web/*/target.com/*

# Waybackurls - Extract URLs from Wayback
waybackurls target.com | sort -u > wayback_urls.txt
cat wayback_urls.txt | grep -E "\.(js|json|xml|config|env|sql|bak)$"

# Gau (GetAllUrls) - Multiple sources
gau target.com --subs | sort -u
gau --providers wayback,commoncrawl,otx target.com

# Common Crawl
echo target.com | python3 cc.py  # Custom script to query

# Look for interesting files in archives
waybackurls target.com | grep -iE "admin|backup|config|password|secret|api|token"

# Check for removed robots.txt entries
curl "https://web.archive.org/cdx/search/cdx?url=target.com/robots.txt&output=text&fl=timestamp,original&collapse=digest"`}
                  />
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    Always check archived versions - developers often commit secrets then remove them, but archives remember everything.
                  </Alert>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 2: People & Organizations */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3 }}>
                People & Organization Intelligence
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                Human intelligence is often the weakest link. Employee names, emails, and roles enable targeted phishing and social engineering.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Email Discovery & Verification</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Corporate email formats are predictable. Once you know the pattern, you can generate valid addresses for any employee.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# theHarvester - Multi-source email discovery
theHarvester -d target.com -b all -l 500
theHarvester -d target.com -b linkedin,google,bing,yahoo

# Hunter.io API - Email finder
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"
# Returns: email pattern (first.last@), confidence scores, sources

# Phonebook.cz - Free email/domain lookup
# phonebook.cz - search by domain

# Clearbit Connect - Email lookup
# Chrome extension for Gmail

# Email format patterns to try:
first.last@target.com
flast@target.com
firstl@target.com
first_last@target.com
first@target.com

# Verify email exists (without sending)
# SMTP VRFY (often disabled)
telnet mail.target.com 25
VRFY user@target.com

# Email verification APIs
# hunter.io/email-verifier
# emailhippo.com
# neverbounce.com`}
                  />
                  <Grid container spacing={2} sx={{ mt: 2 }}>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #f9731630", height: "100%" }}>
                        <Typography sx={{ color: "#f97316", fontWeight: 600, mb: 1 }}>Google Dorks for Emails</Typography>
                        <Box component="pre" sx={{ fontSize: "0.75rem", color: "grey.400", m: 0, whiteSpace: "pre-wrap" }}>
{`site:target.com "@target.com"
site:target.com filetype:pdf
"@target.com" -site:target.com
site:linkedin.com "target.com"
site:github.com "@target.com"`}
                        </Box>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #10b98130", height: "100%" }}>
                        <Typography sx={{ color: "#10b981", fontWeight: 600, mb: 1 }}>Email Sources</Typography>
                        <List dense sx={{ py: 0 }}>
                          {["Company website/team pages", "Press releases", "Conference talks", "GitHub commits", "Court/legal documents"].map((s) => (
                            <ListItem key={s} sx={{ py: 0.15 }}>
                              <ListItemText primary={s} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.8rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #a5b4fc30", height: "100%" }}>
                        <Typography sx={{ color: "#a5b4fc", fontWeight: 600, mb: 1 }}>Verification Tools</Typography>
                        <List dense sx={{ py: 0 }}>
                          {["Hunter.io", "EmailHippo", "NeverBounce", "Kickbox", "ZeroBounce"].map((t) => (
                            <ListItem key={t} sx={{ py: 0.15 }}>
                              <ListItemText primary={t} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.8rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">LinkedIn Intelligence</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    LinkedIn is a goldmine for organizational structure, employee roles, tech stack, and social engineering targets.
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024" }}>
                        <Typography sx={{ color: "#f97316", fontWeight: 600, mb: 1 }}>What to Extract</Typography>
                        <TableContainer>
                          <Table size="small">
                            <TableBody>
                              {[
                                ["Employee Names", "Build phishing target list"],
                                ["Job Titles", "Identify admins, developers, executives"],
                                ["Job Postings", "Reveals tech stack, tools, projects"],
                                ["Org Chart", "Map reporting structure"],
                                ["Work History", "Previous employers, shared connections"],
                                ["Posted Content", "Interests, opinions, social proof"],
                                ["Connections", "Vendors, partners, clients"],
                              ].map(([item, use]) => (
                                <TableRow key={item}>
                                  <TableCell sx={{ color: "#a5b4fc", fontWeight: 500, fontSize: "0.85rem", py: 0.5 }}>{item}</TableCell>
                                  <TableCell sx={{ color: "grey.400", fontSize: "0.85rem", py: 0.5 }}>{use}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <CodeBlock
                        language="bash"
                        code={`# LinkedIn search operators
site:linkedin.com/in "target company"
site:linkedin.com/in "target company" "IT"
site:linkedin.com/in "target company" admin
site:linkedin.com/jobs "target company"

# CrossLinked - LinkedIn enum
python3 crosslinked.py -f '{first}.{last}@target.com' \
  -t 'Target Company' -j 2

# LinkedIn2Username
linkedin2username.py -c "Target Company"

# Job posting analysis
# Look for: specific tools, frameworks,
# cloud providers, security products`}
                      />
                    </Grid>
                  </Grid>
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    LinkedIn aggressively blocks scraping. Use sock puppets, rate limit requests, and consider premium APIs.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Credential Leaks & Breaches</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="error" sx={{ mb: 2 }}>
                    Only search breach databases with explicit authorization. Using leaked credentials without permission is illegal.
                  </Alert>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #ef444430" }}>
                        <Typography sx={{ color: "#ef4444", fontWeight: 600, mb: 1 }}>Breach Search Services</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            ["Have I Been Pwned", "Free, API available, ethical"],
                            ["DeHashed", "Paid, full credential access"],
                            ["LeakCheck", "Paid, good coverage"],
                            ["IntelX", "Extensive archive, expensive"],
                            ["Snusbase", "Paid, searchable dumps"],
                            ["WeLeakInfo", "Seized by FBI, clones exist"],
                          ].map(([name, note]) => (
                            <ListItem key={name} sx={{ py: 0.35 }}>
                              <ListItemIcon><WarningIcon sx={{ color: "#fbbf24", fontSize: 18 }} /></ListItemIcon>
                              <ListItemText primary={name} secondary={note} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <CodeBlock
                        language="bash"
                        code={`# HIBP API - Check email breaches
curl -H "hibp-api-key: KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com"

# h8mail - Email breach hunter
h8mail -t user@target.com
h8mail -t emails.txt -o results.csv

# Pwndb - Tor hidden service
# Search by email or domain

# What to look for:
# - Passwords (plaintext or hashed)
# - Password patterns (reuse detection)
# - Associated usernames
# - IP addresses from logins
# - Security questions/answers`}
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Organization Mapping</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Build a complete picture of the target organization: subsidiaries, acquisitions, partners, and vendors.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# Company information sources
# SEC EDGAR - Public company filings (10-K, 10-Q)
# OpenCorporates - Global company registry
# Crunchbase - Funding, acquisitions, leadership
# ZoomInfo/Apollo - B2B intelligence

# Public records
# Business registrations
# Court documents (PACER)
# Patent/trademark filings (USPTO)
# Government contracts (USAspending.gov)

# Organizational relationships
# Whois for shared registrant info
# Shared IP ranges / ASN
# Shared SSL certificates
# DNS records pointing to same infra
# Job postings mentioning vendors`}
                  />
                  <TableContainer sx={{ mt: 2 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Source</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Intelligence Type</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Use Case</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["SEC Filings", "Subsidiaries, risk factors, IT systems", "Find acquired companies with weak security"],
                          ["Job Postings", "Tech stack, team size, projects", "Identify vulnerable technologies"],
                          ["Press Releases", "Partners, vendors, launches", "Supply chain attack vectors"],
                          ["Court Records", "Lawsuits, disputes, ex-employees", "Insider threat/disgruntled employees"],
                          ["Patent Filings", "R&D focus, inventors", "Key personnel, trade secrets"],
                        ].map(([source, intel, use]) => (
                          <TableRow key={source}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 500 }}>{source}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{intel}</TableCell>
                            <TableCell sx={{ color: "#4ade80" }}>{use}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 3: Images & Metadata */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3 }}>
                Image & Metadata Analysis
              </Typography>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">EXIF Data Extraction</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Images often contain rich metadata including GPS coordinates, camera details, timestamps, and software used.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# ExifTool - Extract all metadata
exiftool image.jpg
exiftool -gps:all image.jpg

# Extract GPS coordinates specifically  
exiftool -GPSLatitude -GPSLongitude image.jpg

# Batch process directory
exiftool -r -ext jpg -GPSPosition /path/to/images/

# Remove all metadata (sanitize)
exiftool -all= image.jpg

# Extract thumbnail from EXIF
exiftool -b -ThumbnailImage image.jpg > thumb.jpg`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Reverse Image Search</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #f9731630" }}>
                        <Typography sx={{ color: "#f97316", fontWeight: 600, mb: 1 }}>Search Engines</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            ["Google Images", "Largest index, good for popular images"],
                            ["TinEye", "Finds modified versions, tracks history"],
                            ["Yandex", "Best for faces and Eastern content"],
                            ["Bing Visual", "Good for products and locations"],
                          ].map(([name, desc]) => (
                            <ListItem key={name} sx={{ py: 0.5 }}>
                              <ListItemIcon><CheckCircleIcon sx={{ color: "#f97316", fontSize: 18 }} /></ListItemIcon>
                              <ListItemText primary={name} secondary={desc} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #a5b4fc30" }}>
                        <Typography sx={{ color: "#a5b4fc", fontWeight: 600, mb: 1 }}>Specialized Tools</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            ["PimEyes", "Face recognition search"],
                            ["FaceCheck.ID", "Face matching across web"],
                            ["Karma Decay", "Reddit image search"],
                            ["SauceNAO", "Anime/artwork source finder"],
                          ].map(([name, desc]) => (
                            <ListItem key={name} sx={{ py: 0.5 }}>
                              <ListItemIcon><CheckCircleIcon sx={{ color: "#a5b4fc", fontSize: 18 }} /></ListItemIcon>
                              <ListItemText primary={name} secondary={desc} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Geolocation from Images</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Even without GPS data, visual clues can reveal location: signs, architecture, vegetation, vehicles, sun position.
                  </Alert>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Clue Type</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>What to Look For</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Tools</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Text/Signs", "Language, phone numbers, business names", "Google Translate, Maps"],
                          ["Architecture", "Building styles, window patterns, roof types", "Google Street View"],
                          ["Vehicles", "License plates, car models, drive side", "PlatesManias, local registries"],
                          ["Nature", "Plants, terrain, sun angle, shadows", "SunCalc, PeakVisor"],
                          ["Infrastructure", "Power lines, road markings, traffic signs", "Google Earth, Mapillary"],
                          ["Weather", "Cloud patterns, precipitation, lighting", "Historical weather data"],
                        ].map(([type, look, tools]) => (
                          <TableRow key={type}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 500 }}>{type}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{look}</TableCell>
                            <TableCell sx={{ color: "#4ade80" }}>{tools}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Document Metadata</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# PDF metadata extraction
pdfinfo document.pdf
exiftool document.pdf

# FOCA - Windows tool for document metadata
# Extracts users, software, paths from Office docs

# Metagoofil - Harvest documents from a domain
metagoofil -d target.com -t pdf,doc,xls -o output/

# Extract metadata from all documents
for f in *.pdf; do exiftool "$f" >> metadata.txt; done

# Office documents often reveal:
# - Author names (domain usernames)
# - Internal paths (\\\\server\\share)
# - Software versions
# - Printer names`}
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 4: Code & Repos */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3 }}>
                Code Repository Intelligence
              </Typography>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">GitHub Reconnaissance</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# GitHub Dorks - Finding secrets
# API keys and tokens
"target.com" password OR secret OR api_key
org:targetcompany password
org:targetcompany filename:.env

# Configuration files
org:targetcompany filename:config extension:json
org:targetcompany filename:settings.py
org:targetcompany filename:database.yml

# Credentials in code
org:targetcompany "BEGIN RSA PRIVATE KEY"
org:targetcompany "AWS_ACCESS_KEY"
org:targetcompany "AKIA" extension:py

# Internal references
org:targetcompany "internal" OR "staging" OR "dev"
org:targetcompany filename:docker-compose`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Secret Scanning Tools</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# TruffleHog - Find secrets in git history
trufflehog git https://github.com/org/repo
trufflehog filesystem --directory=/path/to/code

# GitLeaks - Scan for hardcoded secrets
gitleaks detect --source=/path/to/repo
gitleaks detect --source=https://github.com/org/repo

# git-secrets - AWS credential detection
git secrets --scan

# Gitrob - GitHub organization scanner
gitrob analyze org_name

# Shhgit - Real-time GitHub secret monitoring
shhgit --search-query "org:targetcompany"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Developer Profiling</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Developer accounts can reveal emails, real names, other projects, and company associations.
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024" }}>
                        <Typography sx={{ color: "#f97316", fontWeight: 600, mb: 1 }}>GitHub Profile Data</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "Email from commit history",
                            "Real name and location",
                            "Linked social accounts",
                            "Organization memberships",
                            "Starred repos (interests)",
                            "Contribution patterns",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <CodeBlock
                        language="bash"
                        code={`# Extract emails from commits
git log --format='%ae' | sort -u

# GitHub API for user details
curl https://api.github.com/users/username

# GitMemory - View deleted commits
# gitmemory.com/username/repo

# List all commits by user
git log --author="name@email.com"`}
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Other Code Platforms</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Platform</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Search URL</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Notes</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["GitLab", "gitlab.com/search?search=target", "Self-hosted instances too"],
                          ["Bitbucket", "bitbucket.org/repo/all?name=target", "Atlassian integration"],
                          ["SourceForge", "sourceforge.net/directory/?q=target", "Legacy projects"],
                          ["Gist", "gist.github.com/search?q=target", "Code snippets"],
                          ["Pastebin", "pastebin.com/search?q=target", "Often leaked data"],
                          ["Replit", "replit.com/search?q=target", "Educational code"],
                        ].map(([platform, url, notes]) => (
                          <TableRow key={platform}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 500 }}>{platform}</TableCell>
                            <TableCell sx={{ color: "grey.300", fontFamily: "monospace", fontSize: "0.8rem" }}>{url}</TableCell>
                            <TableCell sx={{ color: "#4ade80" }}>{notes}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 5: Advanced OSINT */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3 }}>
                Advanced OSINT Techniques
              </Typography>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Dark Web Reconnaissance</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="error" sx={{ mb: 2 }}>
                    Dark web research requires extreme caution. Use isolated VMs, Tails OS, and never interact with illegal content.
                  </Alert>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #ef444430" }}>
                        <Typography sx={{ color: "#ef4444", fontWeight: 600, mb: 1 }}>Safety Measures</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "Use Tails OS (amnesic system)",
                            "Tor Browser with NoScript",
                            "Disable JavaScript where possible",
                            "Never use personal credentials",
                            "Isolated VM environment",
                            "VPN before Tor (optional)",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024", border: "1px solid #f9731630" }}>
                        <Typography sx={{ color: "#f97316", fontWeight: 600, mb: 1 }}>Search Resources</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "Ahmia.fi (Tor search engine)",
                            "OnionLand Search",
                            "DarkSearch.io",
                            "IntelX (breach data)",
                            "Tor2web proxies (careful!)",
                            "Darknet market forums",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Sock Puppet Creation</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Fake personas for undercover research. Essential for accessing private groups or conducting social engineering assessments.
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Element</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Tools/Resources</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Tips</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Profile Photo", "thispersondoesnotexist.com, AI generators", "Reverse image check before use"],
                          ["Name", "Fake Name Generator, census data", "Match demographics of target"],
                          ["Email", "Protonmail, disposable services", "Age the account before use"],
                          ["Phone", "Google Voice, Burner apps, VoIP", "Separate from real identity"],
                          ["History", "Build post history over time", "Consistent interests/location"],
                          ["Location", "Match VPN exit to claimed location", "Research local details"],
                        ].map(([element, tools, tips]) => (
                          <TableRow key={element}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 500 }}>{element}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{tools}</TableCell>
                            <TableCell sx={{ color: "#4ade80" }}>{tips}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Social Media Deep Dive</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Sherlock - Username search across platforms
sherlock username

# Maigret - Extended username search
maigret username --all-sites

# Twint - Twitter scraping (no API needed)
twint -u username --limit 1000
twint -s "target company" --since 2023-01-01

# Instaloader - Instagram data
instaloader profile username
instaloader --login=your_user username

# Social Analyzer - Multi-platform analysis
python3 social-analyzer.py --username "target"

# Facebook Graph Search alternatives
# Use advanced search operators on Google:
site:facebook.com "works at target company"
site:facebook.com "studied at" "target university"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Wireless & Physical Recon</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024" }}>
                        <Typography sx={{ color: "#f97316", fontWeight: 600, mb: 1 }}>WiFi Intelligence</Typography>
                        <CodeBlock
                          language="bash"
                          code={`# WiGLE - WiFi network database
# wigle.net - Search by SSID, BSSID

# Wardriving results
# Find networks near target location

# BSSID lookup
# macvendors.com - Identify device manufacturer`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: "#0f1024" }}>
                        <Typography sx={{ color: "#a5b4fc", fontWeight: 600, mb: 1 }}>Physical Location Intel</Typography>
                        <List dense sx={{ py: 0 }}>
                          {[
                            "Google Maps/Earth imagery",
                            "Historical satellite (Google Earth Pro)",
                            "Mapillary street-level photos",
                            "Building permits (public records)",
                            "Company registration addresses",
                            "Delivery/shipping endpoints",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Automation & Frameworks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# SpiderFoot - Automated OSINT collection
spiderfoot -l 127.0.0.1:5001  # Start web UI
sf.py -m all -s target.com -o output.json

# Recon-ng - Modular recon framework
recon-ng
marketplace search
marketplace install all
modules load recon/domains-hosts/hackertarget
options set SOURCE target.com
run

# theHarvester - Email and subdomain discovery
theHarvester -d target.com -b all -f output

# Maltego - Visual link analysis
# Commercial but has community edition

# OSINT Framework automation
# Use Python to chain multiple tools
# Example workflow script in next section`}
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 6: Tools */}
          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ color: "#f97316", mb: 3 }}>
                OSINT Tools Reference
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                Master a few tools deeply rather than using many superficially. Start with theHarvester, Amass, and Shodan.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Essential OSINT Toolkit</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer component={Paper} sx={{ bgcolor: "#1a1a2e" }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Tool</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Category</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Description</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Install</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Maltego", "Visualization", "Link analysis and data mining GUI", "maltego.com (free CE)"],
                          ["Shodan", "Infrastructure", "Internet-connected device search engine", "pip install shodan"],
                          ["theHarvester", "Email/Domain", "Email, subdomain, host discovery", "apt install theharvester"],
                          ["Recon-ng", "Framework", "Modular reconnaissance framework", "apt install recon-ng"],
                          ["SpiderFoot", "Automation", "Automated OSINT collection", "pip install spiderfoot"],
                          ["Amass", "Subdomains", "Attack surface mapping & enumeration", "apt install amass"],
                          ["Subfinder", "Subdomains", "Fast passive subdomain enumeration", "go install subfinder"],
                          ["httpx", "Probing", "Fast HTTP toolkit for alive checking", "go install httpx"],
                          ["Nuclei", "Scanning", "Template-based vulnerability scanner", "go install nuclei"],
                          ["FOCA", "Metadata", "Document metadata extraction (Windows)", "GitHub releases"],
                          ["Metagoofil", "Documents", "Public document harvesting", "apt install metagoofil"],
                          ["ExifTool", "Metadata", "Image/document metadata extraction", "apt install exiftool"],
                          ["Sherlock", "Usernames", "Username search across 300+ sites", "pip install sherlock"],
                          ["Maigret", "Usernames", "Extended username search", "pip install maigret"],
                          ["GHunt", "Google", "Google account investigation", "pip install ghunt"],
                          ["holehe", "Email", "Check if email used on sites", "pip install holehe"],
                        ].map(([tool, cat, desc, install]) => (
                          <TableRow key={tool}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 600 }}>{tool}</TableCell>
                            <TableCell><Chip label={cat} size="small" sx={{ bgcolor: "#f9731630", color: "#f97316" }} /></TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{desc}</TableCell>
                            <TableCell sx={{ color: "#4ade80", fontFamily: "monospace", fontSize: "0.75rem" }}>{install}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Google Dorks Cheatsheet</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <CodeBlock
                        language="text"
                        code={`# === FILE DISCOVERY ===
site:target.com filetype:pdf
site:target.com filetype:xlsx
site:target.com filetype:docx
site:target.com filetype:pptx
site:target.com filetype:txt
site:target.com ext:sql
site:target.com ext:bak
site:target.com ext:log

# === SENSITIVE DIRECTORIES ===
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:portal
site:target.com inurl:dashboard
site:target.com intitle:"index of"
site:target.com intitle:"directory listing"
site:target.com inurl:wp-admin
site:target.com inurl:phpmyadmin`}
                      />
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <CodeBlock
                        language="text"
                        code={`# === EXPOSED SECRETS ===
site:target.com filetype:env
site:target.com filetype:config
site:target.com "password" filetype:log
site:target.com "api_key" OR "apikey"
site:target.com "AWS_SECRET"
site:target.com inurl:"id_rsa"
site:target.com filetype:pem

# === CODE REPOSITORIES ===
site:github.com "target.com"
site:github.com "@target.com"
site:gitlab.com "target.com" password
site:bitbucket.org "target.com"
site:pastebin.com "target.com"
site:trello.com "target.com"

# === ERRORS & DEBUG ===
site:target.com "error" "warning"
site:target.com "stack trace"
site:target.com "SQL syntax"
site:target.com inurl:debug`}
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Online OSINT Resources</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    {[
                      { title: "Domain/IP", items: ["Shodan.io", "Censys.io", "SecurityTrails", "DNSDumpster", "ViewDNS.info", "BuiltWith"], color: "#ef4444" },
                      { title: "Email", items: ["Hunter.io", "Phonebook.cz", "EmailRep.io", "Have I Been Pwned", "Clearbit", "Voilanorbert"], color: "#f97316" },
                      { title: "People", items: ["Pipl", "Spokeo", "BeenVerified", "ThatsThem", "TruePeopleSearch", "Whitepages"], color: "#8b5cf6" },
                      { title: "Social Media", items: ["Social Searcher", "Mention", "TweetDeck", "Social Blade", "Hashatit", "Snapchat Map"], color: "#06b6d4" },
                      { title: "Images", items: ["TinEye", "Yandex Images", "PimEyes", "FaceCheck.ID", "Google Images", "Bing Visual"], color: "#10b981" },
                      { title: "Archives", items: ["Wayback Machine", "Archive.today", "CachedView", "Google Cache", "Bing Cache", "Common Crawl"], color: "#a5b4fc" },
                    ].map((cat) => (
                      <Grid item xs={12} sm={6} md={4} key={cat.title}>
                        <Paper sx={{ p: 2, bgcolor: "#0f1024", border: `1px solid ${cat.color}30`, height: "100%" }}>
                          <Typography sx={{ color: cat.color, fontWeight: 600, mb: 1 }}>{cat.title}</Typography>
                          <List dense sx={{ py: 0 }}>
                            {cat.items.map((item) => (
                              <ListItem key={item} sx={{ py: 0.15 }}>
                                <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.400", fontSize: "0.85rem" } }} />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">OSINT Automation Script</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography sx={{ color: "grey.300", mb: 2 }}>
                    Chain multiple tools together for comprehensive automated reconnaissance.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`#!/bin/bash
# OSINT Automation Script
DOMAIN=$1
OUTPUT="recon_$DOMAIN"
mkdir -p $OUTPUT

echo "[*] Starting recon on $DOMAIN"

# Subdomain enumeration
echo "[+] Enumerating subdomains..."
subfinder -d $DOMAIN -silent | anew $OUTPUT/subs.txt
assetfinder --subs-only $DOMAIN | anew $OUTPUT/subs.txt
amass enum -passive -d $DOMAIN | anew $OUTPUT/subs.txt

# Probe live hosts
echo "[+] Probing live hosts..."
cat $OUTPUT/subs.txt | httpx -silent -o $OUTPUT/live.txt

# Screenshot live hosts
echo "[+] Taking screenshots..."
cat $OUTPUT/live.txt | gowitness file -f - -P $OUTPUT/screenshots/

# Technology detection
echo "[+] Detecting technologies..."
cat $OUTPUT/live.txt | httpx -tech-detect -o $OUTPUT/tech.txt

# Wayback URLs
echo "[+] Fetching historical URLs..."
waybackurls $DOMAIN | anew $OUTPUT/wayback.txt

# Email harvesting
echo "[+] Harvesting emails..."
theHarvester -d $DOMAIN -b all -f $OUTPUT/emails

# DNS records
echo "[+] Gathering DNS records..."
dnsrecon -d $DOMAIN -t std -j $OUTPUT/dns.json

echo "[*] Recon complete! Results in $OUTPUT/"`}
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>
        </Paper>

        {/* Footer */}
        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#f97316", color: "#f97316" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
  );
};

export default OSINTReconPage;
