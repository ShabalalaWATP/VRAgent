import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
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
  Drawer,
  Fab,
  Divider,
  LinearProgress,
  alpha,
  useTheme,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import TravelExploreIcon from "@mui/icons-material/TravelExplore";
import PersonSearchIcon from "@mui/icons-material/PersonSearch";
import DnsIcon from "@mui/icons-material/Dns";
import SecurityIcon from "@mui/icons-material/Security";
import CodeIcon from "@mui/icons-material/Code";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import ImageIcon from "@mui/icons-material/Image";
import GitHubIcon from "@mui/icons-material/GitHub";
import PublicIcon from "@mui/icons-material/Public";
import QuizIcon from "@mui/icons-material/Quiz";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import SchoolIcon from "@mui/icons-material/School";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value: _value, index: _index, ...other } = props;
  return (
    <div role="tabpanel" {...other}>
      <Box sx={{ py: 3 }}>{children}</Box>
    </div>
  );
}

const ACCENT_COLOR = "#f97316";

const CodeBlock: React.FC<{ code: string; language?: string }> = ({ code, language = "bash" }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: alpha("#0f172a", 0.9),
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: `1px solid ${alpha(ACCENT_COLOR, 0.25)}`,
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: ACCENT_COLOR, color: "#0f172a", fontWeight: 700 }} />
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

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = ACCENT_COLOR;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Basics",
    question: "What does OSINT stand for?",
    options: [
      "Open Source Intelligence",
      "Operational Security Intelligence",
      "Offensive Security Incident Triage",
      "Online Search Integration",
    ],
    correctAnswer: 0,
    explanation: "OSINT is intelligence gathered from publicly available sources.",
  },
  {
    id: 2,
    topic: "Basics",
    question: "Passive reconnaissance means:",
    options: [
      "Collecting information without directly interacting with targets",
      "Sending probes and scans to target systems",
      "Exploiting vulnerabilities to gather data",
      "Launching phishing campaigns",
    ],
    correctAnswer: 0,
    explanation: "Passive recon avoids direct contact with the target systems.",
  },
  {
    id: 3,
    topic: "Basics",
    question: "Active reconnaissance means:",
    options: [
      "Interacting directly with target systems or services",
      "Only using search engines",
      "Collecting public records only",
      "Working offline without internet access",
    ],
    correctAnswer: 0,
    explanation: "Active recon involves direct interaction such as scanning or probing.",
  },
  {
    id: 4,
    topic: "Basics",
    question: "Why begin with passive recon?",
    options: [
      "It reduces detection risk and provides context",
      "It guarantees zero false positives",
      "It replaces the need for validation",
      "It automatically exploits targets",
    ],
    correctAnswer: 0,
    explanation: "Passive recon is low risk and builds a foundation of context.",
  },
  {
    id: 5,
    topic: "Domains",
    question: "What does a WHOIS lookup provide?",
    options: [
      "Domain registration and ownership details",
      "Open ports and services",
      "HTTP response headers",
      "File hashes from servers",
    ],
    correctAnswer: 0,
    explanation: "WHOIS returns registrar, ownership, and registration data.",
  },
  {
    id: 6,
    topic: "Domains",
    question: "A domain registrar is:",
    options: [
      "The company that manages domain registrations",
      "The DNS server hosting records",
      "A web hosting provider only",
      "An SSL certificate authority",
    ],
    correctAnswer: 0,
    explanation: "Registrars sell and manage domain registrations.",
  },
  {
    id: 7,
    topic: "DNS",
    question: "An A record maps a name to:",
    options: [
      "An IPv4 address",
      "An IPv6 address",
      "A mail server",
      "A text record",
    ],
    correctAnswer: 0,
    explanation: "A records map names to IPv4 addresses.",
  },
  {
    id: 8,
    topic: "DNS",
    question: "An AAAA record maps a name to:",
    options: [
      "An IPv6 address",
      "An IPv4 address",
      "A CNAME alias",
      "A mail exchange server",
    ],
    correctAnswer: 0,
    explanation: "AAAA records map names to IPv6 addresses.",
  },
  {
    id: 9,
    topic: "DNS",
    question: "MX records identify:",
    options: [
      "Mail servers for a domain",
      "Web server software versions",
      "User account names",
      "TLS cipher suites",
    ],
    correctAnswer: 0,
    explanation: "MX records specify mail exchangers for a domain.",
  },
  {
    id: 10,
    topic: "DNS",
    question: "TXT records often include:",
    options: [
      "SPF or DKIM policy data",
      "Only IP addresses",
      "Windows event logs",
      "Operating system versions",
    ],
    correctAnswer: 0,
    explanation: "TXT records commonly carry email security policies like SPF/DKIM.",
  },
  {
    id: 11,
    topic: "DNS",
    question: "NS records identify:",
    options: [
      "Authoritative name servers",
      "Mail servers",
      "Web application frameworks",
      "Database servers",
    ],
    correctAnswer: 0,
    explanation: "NS records list authoritative DNS servers for a zone.",
  },
  {
    id: 12,
    topic: "DNS",
    question: "A CNAME record is used to:",
    options: [
      "Alias one name to another",
      "Store a public key",
      "Provide an IP address",
      "Store a mail exchange",
    ],
    correctAnswer: 0,
    explanation: "CNAME records map a name to another canonical name.",
  },
  {
    id: 13,
    topic: "Subdomains",
    question: "Subdomain enumeration is the process of:",
    options: [
      "Finding hostnames under a domain",
      "Listing running processes",
      "Scanning open ports",
      "Collecting user passwords",
    ],
    correctAnswer: 0,
    explanation: "Subdomain enumeration discovers hostnames under a domain.",
  },
  {
    id: 14,
    topic: "Subdomains",
    question: "Certificate Transparency logs help by:",
    options: [
      "Revealing hostnames in issued certificates",
      "Listing open ports on servers",
      "Showing database schemas",
      "Disabling DNS caching",
    ],
    correctAnswer: 0,
    explanation: "CT logs often expose subdomains in certificates.",
  },
  {
    id: 15,
    topic: "DNS",
    question: "Reverse DNS (PTR) lookups map:",
    options: [
      "An IP address to a hostname",
      "A hostname to an IP address",
      "A domain to a registrar",
      "A URL to a hash",
    ],
    correctAnswer: 0,
    explanation: "PTR records provide hostname mappings for IPs.",
  },
  {
    id: 16,
    topic: "Networking",
    question: "An ASN is used to:",
    options: [
      "Identify IP ranges owned by an organization",
      "Store DNS records for a domain",
      "Encrypt network traffic",
      "Host public web content",
    ],
    correctAnswer: 0,
    explanation: "ASNs help map IP ranges and network ownership.",
  },
  {
    id: 17,
    topic: "Networking",
    question: "Why gather ASN information?",
    options: [
      "To discover related IP ranges and infrastructure",
      "To bypass authentication",
      "To disable logging",
      "To patch vulnerabilities",
    ],
    correctAnswer: 0,
    explanation: "ASN data reveals additional assets and networks.",
  },
  {
    id: 18,
    topic: "Web",
    question: "Virtual host discovery finds:",
    options: [
      "Multiple sites hosted on the same IP",
      "Kernel modules on a server",
      "Local user accounts",
      "Email inbox contents",
    ],
    correctAnswer: 0,
    explanation: "Virtual hosts allow multiple domains on one IP address.",
  },
  {
    id: 19,
    topic: "Web",
    question: "Why probe HTTP/HTTPS hosts after subdomain discovery?",
    options: [
      "To identify which hosts are live and serving web content",
      "To change DNS records",
      "To reset passwords",
      "To disable firewalls",
    ],
    correctAnswer: 0,
    explanation: "Probing validates which hosts respond and are worth deeper review.",
  },
  {
    id: 20,
    topic: "Web",
    question: "robots.txt typically lists:",
    options: [
      "Paths the site asks crawlers to avoid",
      "Database credentials",
      "Firewall rules",
      "Active user sessions",
    ],
    correctAnswer: 0,
    explanation: "robots.txt may hint at hidden or sensitive paths.",
  },
  {
    id: 21,
    topic: "Web",
    question: "Why use the Wayback Machine?",
    options: [
      "To view historical versions of websites",
      "To access private networks",
      "To decrypt HTTPS traffic",
      "To run malware scans",
    ],
    correctAnswer: 0,
    explanation: "Archived pages can reveal old content and endpoints.",
  },
  {
    id: 22,
    topic: "Web",
    question: "A sitemap is useful because it:",
    options: [
      "Lists site URLs and structure",
      "Contains server IP ranges",
      "Stores encrypted passwords",
      "Disables indexing",
    ],
    correctAnswer: 0,
    explanation: "Sitemaps expose important URLs and site structure.",
  },
  {
    id: 23,
    topic: "Search",
    question: "Google dorking refers to:",
    options: [
      "Using advanced search operators to find exposed data",
      "Running vulnerability scans with Google",
      "Brute-forcing login pages",
      "Bypassing HTTPS encryption",
    ],
    correctAnswer: 0,
    explanation: "Search operators can reveal exposed files and data.",
  },
  {
    id: 24,
    topic: "Search",
    question: "The operator `site:` is used to:",
    options: [
      "Restrict results to a specific domain",
      "Search for file types only",
      "Filter by language only",
      "Search for images only",
    ],
    correctAnswer: 0,
    explanation: "`site:` limits results to a domain or host.",
  },
  {
    id: 25,
    topic: "Search",
    question: "The operator `filetype:` is used to:",
    options: [
      "Find specific file formats",
      "Find specific IP ranges",
      "Search only social media",
      "Search only cached pages",
    ],
    correctAnswer: 0,
    explanation: "`filetype:` finds documents like pdf, docx, or xls.",
  },
  {
    id: 26,
    topic: "Search",
    question: "The operator `intitle:` is used to:",
    options: [
      "Search for words in page titles",
      "Search for words in URLs",
      "Search only PDF files",
      "Search only image metadata",
    ],
    correctAnswer: 0,
    explanation: "`intitle:` filters results by page title.",
  },
  {
    id: 27,
    topic: "Search",
    question: "The operator `inurl:` is used to:",
    options: [
      "Search for words in URLs",
      "Search only site titles",
      "Search only local files",
      "Search only social posts",
    ],
    correctAnswer: 0,
    explanation: "`inurl:` filters results by URL contents.",
  },
  {
    id: 28,
    topic: "Code",
    question: "Why search GitHub during OSINT?",
    options: [
      "Developers may leak secrets or internal URLs",
      "GitHub provides DNS records",
      "GitHub hosts email servers",
      "GitHub blocks all searches",
    ],
    correctAnswer: 0,
    explanation: "Repositories sometimes expose tokens, URLs, or config files.",
  },
  {
    id: 29,
    topic: "Leaks",
    question: "Why check paste sites or public gists?",
    options: [
      "They can contain leaked credentials or configs",
      "They show private directory listings",
      "They host DNS servers",
      "They always contain malware",
    ],
    correctAnswer: 0,
    explanation: "Paste sites often contain accidental data leaks.",
  },
  {
    id: 30,
    topic: "Email",
    question: "TheHarvester is commonly used to:",
    options: [
      "Collect emails and related OSINT from public sources",
      "Run port scans",
      "Exploit vulnerabilities",
      "Decrypt traffic",
    ],
    correctAnswer: 0,
    explanation: "TheHarvester aggregates email and domain OSINT.",
  },
  {
    id: 31,
    topic: "Subdomains",
    question: "Amass is best known for:",
    options: [
      "Subdomain enumeration and asset discovery",
      "Password cracking",
      "Packet capture",
      "Web application scanning",
    ],
    correctAnswer: 0,
    explanation: "Amass focuses on subdomain and infrastructure discovery.",
  },
  {
    id: 32,
    topic: "Subdomains",
    question: "Subfinder is used to:",
    options: [
      "Discover subdomains from passive sources",
      "Enumerate local users",
      "Dump memory",
      "Generate SSL certificates",
    ],
    correctAnswer: 0,
    explanation: "Subfinder aggregates passive subdomain sources.",
  },
  {
    id: 33,
    topic: "Subdomains",
    question: "Assetfinder is used to:",
    options: [
      "Find subdomains for a target",
      "Search web content for XSS",
      "Dump credentials",
      "Detect malware on endpoints",
    ],
    correctAnswer: 0,
    explanation: "Assetfinder discovers subdomains for a domain.",
  },
  {
    id: 34,
    topic: "Internet Search",
    question: "Shodan is best described as:",
    options: [
      "A search engine for internet-exposed devices",
      "A DNS resolver",
      "A vulnerability scanner only",
      "A password manager",
    ],
    correctAnswer: 0,
    explanation: "Shodan indexes exposed devices and services.",
  },
  {
    id: 35,
    topic: "Internet Search",
    question: "Censys provides:",
    options: [
      "Internet scan data and certificate search",
      "Only malware samples",
      "Only OS patching data",
      "Only social media results",
    ],
    correctAnswer: 0,
    explanation: "Censys indexes hosts, services, and certificates.",
  },
  {
    id: 36,
    topic: "Internet Search",
    question: "SecurityTrails is useful for:",
    options: [
      "DNS history and domain intelligence",
      "Memory forensics",
      "Packet decryption",
      "Firewall rule editing",
    ],
    correctAnswer: 0,
    explanation: "SecurityTrails focuses on DNS and domain data.",
  },
  {
    id: 37,
    topic: "Leaks",
    question: "Have I Been Pwned helps by:",
    options: [
      "Checking if emails appear in breach data",
      "Enumerating DNS records",
      "Detecting open ports",
      "Generating phishing emails",
    ],
    correctAnswer: 0,
    explanation: "HIBP identifies emails present in known breaches.",
  },
  {
    id: 38,
    topic: "Metadata",
    question: "Metadata is:",
    options: [
      "Data about data, such as author or timestamps",
      "Encrypted log files only",
      "Only image thumbnails",
      "Network packet headers",
    ],
    correctAnswer: 0,
    explanation: "Metadata can reveal authoring details or internal paths.",
  },
  {
    id: 39,
    topic: "Metadata",
    question: "EXIF data can reveal:",
    options: [
      "Camera model, timestamps, and sometimes GPS",
      "Firewall rules",
      "Database tables",
      "User passwords",
    ],
    correctAnswer: 0,
    explanation: "EXIF may include device and location details.",
  },
  {
    id: 40,
    topic: "Images",
    question: "Reverse image search is used to:",
    options: [
      "Find where an image appears online",
      "Extract DNS records",
      "Scan for open ports",
      "Encrypt images",
    ],
    correctAnswer: 0,
    explanation: "Reverse search locates identical or similar images.",
  },
  {
    id: 41,
    topic: "People",
    question: "Why analyze social media profiles?",
    options: [
      "They can reveal roles, projects, and contacts",
      "They provide DNS configurations",
      "They always contain passwords",
      "They disable logging",
    ],
    correctAnswer: 0,
    explanation: "Profiles provide org structure and context.",
  },
  {
    id: 42,
    topic: "People",
    question: "Username enumeration helps to:",
    options: [
      "Find accounts across multiple platforms",
      "Reset user passwords automatically",
      "Disable MFA",
      "Patch servers",
    ],
    correctAnswer: 0,
    explanation: "Usernames often repeat across services.",
  },
  {
    id: 43,
    topic: "Web",
    question: "Why use cached pages (Google/Bing)?",
    options: [
      "To view content that has changed or been removed",
      "To bypass authentication",
      "To scan ports",
      "To decrypt TLS traffic",
    ],
    correctAnswer: 0,
    explanation: "Caches can reveal older content and endpoints.",
  },
  {
    id: 44,
    topic: "DNS",
    question: "Passive DNS provides:",
    options: [
      "Historical mappings of domains to IPs",
      "Live shell access",
      "Password hashes",
      "Source code repositories",
    ],
    correctAnswer: 0,
    explanation: "Passive DNS shows historical resolution data.",
  },
  {
    id: 45,
    topic: "Analysis",
    question: "Link analysis is used to:",
    options: [
      "Map relationships between entities",
      "Encrypt DNS traffic",
      "Disable logging",
      "Extract kernel modules",
    ],
    correctAnswer: 0,
    explanation: "Link analysis helps connect people, domains, and assets.",
  },
  {
    id: 46,
    topic: "Basics",
    question: "OSINT sources are typically:",
    options: [
      "Publicly available or legally accessible",
      "Always private and restricted",
      "Only internal company databases",
      "Only dark web content",
    ],
    correctAnswer: 0,
    explanation: "OSINT uses publicly accessible information.",
  },
  {
    id: 47,
    topic: "Legal",
    question: "Which activity usually requires explicit authorization?",
    options: [
      "Active scanning of target systems",
      "Reading public web pages",
      "Searching public profiles",
      "Using public DNS records",
    ],
    correctAnswer: 0,
    explanation: "Active probing can be intrusive and often needs permission.",
  },
  {
    id: 48,
    topic: "Legal",
    question: "Why avoid doxxing in OSINT work?",
    options: [
      "It violates privacy and ethical guidelines",
      "It improves data accuracy",
      "It is required by law",
      "It reduces documentation needs",
    ],
    correctAnswer: 0,
    explanation: "OSINT should respect privacy and legal boundaries.",
  },
  {
    id: 49,
    topic: "OPSEC",
    question: "A good OPSEC practice during OSINT is to:",
    options: [
      "Use dedicated accounts and isolate research activity",
      "Use personal accounts for all research",
      "Share credentials across team members",
      "Disable browser protections",
    ],
    correctAnswer: 0,
    explanation: "Dedicated accounts reduce exposure and attribution risk.",
  },
  {
    id: 50,
    topic: "OPSEC",
    question: "Why avoid contacting the target during passive OSINT?",
    options: [
      "It can alert the target and bias findings",
      "It improves data quality",
      "It is always required",
      "It reduces detection risk",
    ],
    correctAnswer: 0,
    explanation: "Direct contact can tip off the target.",
  },
  {
    id: 51,
    topic: "Validation",
    question: "Why confirm data across multiple sources?",
    options: [
      "To reduce false positives and stale data",
      "To increase noise in reports",
      "To avoid evidence collection",
      "To skip documentation",
    ],
    correctAnswer: 0,
    explanation: "Cross-source validation improves accuracy.",
  },
  {
    id: 52,
    topic: "Domains",
    question: "Typosquatting refers to:",
    options: [
      "Domains that mimic common misspellings",
      "Domains that use long TLDs only",
      "Domains without any DNS records",
      "Domains owned by registrars",
    ],
    correctAnswer: 0,
    explanation: "Typosquatting targets misspelled domains.",
  },
  {
    id: 53,
    topic: "Email",
    question: "SPF records indicate:",
    options: [
      "Which servers can send mail for a domain",
      "Which web servers host a domain",
      "Which ports are open on a host",
      "Which databases are exposed",
    ],
    correctAnswer: 0,
    explanation: "SPF defines authorized mail senders.",
  },
  {
    id: 54,
    topic: "Email",
    question: "DKIM records are used to:",
    options: [
      "Validate email authenticity with cryptographic signatures",
      "Encrypt files on disk",
      "Store DNS zone files",
      "Disable phishing detection",
    ],
    correctAnswer: 0,
    explanation: "DKIM uses cryptographic signatures to validate email.",
  },
  {
    id: 55,
    topic: "Email",
    question: "DMARC provides:",
    options: [
      "Policy guidance for SPF and DKIM alignment",
      "An alternative to TLS",
      "A network segmentation policy",
      "A password manager",
    ],
    correctAnswer: 0,
    explanation: "DMARC specifies how to handle SPF/DKIM failures.",
  },
  {
    id: 56,
    topic: "Certificates",
    question: "Certificate Transparency logs are useful because they:",
    options: [
      "List certificates issued for domains, often exposing subdomains",
      "Show live web traffic",
      "Store server passwords",
      "Block DNS resolution",
    ],
    correctAnswer: 0,
    explanation: "CT logs provide visibility into cert issuance.",
  },
  {
    id: 57,
    topic: "Risk",
    question: "A dangling CNAME can indicate:",
    options: [
      "Potential subdomain takeover risk",
      "A patched system",
      "An internal-only host",
      "A closed port",
    ],
    correctAnswer: 0,
    explanation: "Dangling CNAMEs can be claimed by attackers.",
  },
  {
    id: 58,
    topic: "Cloud",
    question: "Public cloud storage buckets are risky because they:",
    options: [
      "Can expose data if misconfigured for public access",
      "Always require MFA",
      "Automatically encrypt all data",
      "Cannot be enumerated",
    ],
    correctAnswer: 0,
    explanation: "Misconfigured buckets can leak data publicly.",
  },
  {
    id: 59,
    topic: "Tools",
    question: "Maltego is often used for:",
    options: [
      "Link analysis and relationship mapping",
      "Port scanning",
      "Password cracking",
      "Kernel debugging",
    ],
    correctAnswer: 0,
    explanation: "Maltego maps relationships between entities.",
  },
  {
    id: 60,
    topic: "Tools",
    question: "Recon-ng is best described as:",
    options: [
      "A modular OSINT framework",
      "A malware analysis sandbox",
      "A packet capture tool",
      "A firewall manager",
    ],
    correctAnswer: 0,
    explanation: "Recon-ng provides modules for OSINT collection.",
  },
  {
    id: 61,
    topic: "Active Recon",
    question: "Port scanning is generally considered:",
    options: [
      "Active reconnaissance",
      "Passive reconnaissance",
      "Pure OSINT",
      "Offline analysis only",
    ],
    correctAnswer: 0,
    explanation: "Port scanning interacts directly with target systems.",
  },
  {
    id: 62,
    topic: "DNS",
    question: "A DNS zone transfer (AXFR) attempt is:",
    options: [
      "An active check for misconfigured DNS servers",
      "A passive recon technique",
      "A search engine query",
      "A social media lookup",
    ],
    correctAnswer: 0,
    explanation: "AXFR is an active request to copy DNS zones.",
  },
  {
    id: 63,
    topic: "People",
    question: "LinkedIn is commonly used to:",
    options: [
      "Identify employees, roles, and org structure",
      "Scan open ports",
      "Download DNS zones",
      "Retrieve TLS certificates",
    ],
    correctAnswer: 0,
    explanation: "LinkedIn helps map staff and organizational roles.",
  },
  {
    id: 64,
    topic: "Email",
    question: "Email pattern discovery helps by:",
    options: [
      "Predicting user email formats for a domain",
      "Patching mail servers",
      "Decrypting emails",
      "Removing spam filters",
    ],
    correctAnswer: 0,
    explanation: "Patterns help validate email address formats.",
  },
  {
    id: 65,
    topic: "Reporting",
    question: "Good OSINT reporting includes:",
    options: [
      "Sources and timestamps for findings",
      "Only conclusions without evidence",
      "No data validation",
      "Unverified rumors",
    ],
    correctAnswer: 0,
    explanation: "Evidence and timestamps improve credibility and reproducibility.",
  },
  {
    id: 66,
    topic: "Reporting",
    question: "Why minimize sensitive personal data in reports?",
    options: [
      "To respect privacy and reduce risk",
      "To weaken findings",
      "To avoid documentation",
      "To increase false positives",
    ],
    correctAnswer: 0,
    explanation: "Reports should be privacy-aware and need-to-know.",
  },
  {
    id: 67,
    topic: "Validation",
    question: "A single OSINT source should be treated as:",
    options: [
      "A lead that needs corroboration",
      "Guaranteed truth",
      "Legally binding evidence",
      "A replacement for verification",
    ],
    correctAnswer: 0,
    explanation: "OSINT sources can be inaccurate; validate where possible.",
  },
  {
    id: 68,
    topic: "Risk",
    question: "Why monitor for exposed `.env` or config files?",
    options: [
      "They often contain secrets and internal URLs",
      "They only store comments",
      "They are always encrypted",
      "They are unrelated to security",
    ],
    correctAnswer: 0,
    explanation: "Config files can leak credentials and endpoints.",
  },
  {
    id: 69,
    topic: "Tools",
    question: "dnsrecon is used for:",
    options: [
      "DNS enumeration and record collection",
      "Memory forensics",
      "Password cracking",
      "Disk imaging",
    ],
    correctAnswer: 0,
    explanation: "dnsrecon collects DNS records and performs checks.",
  },
  {
    id: 70,
    topic: "Tools",
    question: "dig or nslookup are used to:",
    options: [
      "Query DNS records",
      "Scan open ports",
      "Enumerate Windows services",
      "Perform code audits",
    ],
    correctAnswer: 0,
    explanation: "dig and nslookup query DNS data.",
  },
  {
    id: 71,
    topic: "Web",
    question: "Why check HTTP response headers?",
    options: [
      "They can reveal technologies or misconfigurations",
      "They provide password hashes",
      "They expose DNS zones",
      "They show kernel modules",
    ],
    correctAnswer: 0,
    explanation: "Headers can indicate software stacks and configuration details.",
  },
  {
    id: 72,
    topic: "Risk",
    question: "A public `.git` directory can expose:",
    options: [
      "Source code and commit history",
      "Only log files",
      "Only images",
      "Only CSS files",
    ],
    correctAnswer: 0,
    explanation: "Exposed Git metadata can leak code and secrets.",
  },
  {
    id: 73,
    topic: "OPSEC",
    question: "Why separate research browsing from personal accounts?",
    options: [
      "To reduce attribution and privacy risk",
      "To increase target visibility",
      "To bypass authentication",
      "To avoid documentation",
    ],
    correctAnswer: 0,
    explanation: "Separating accounts reduces correlation and exposure.",
  },
  {
    id: 74,
    topic: "Web",
    question: "What is a common OSINT use of `site:pastebin.com`?",
    options: [
      "Find leaked references to a target",
      "Scan for open ports",
      "Reset credentials",
      "Disable caching",
    ],
    correctAnswer: 0,
    explanation: "Site-restricted searches can reveal leaked references.",
  },
  {
    id: 75,
    topic: "Basics",
    question: "Which statement best summarizes OSINT value?",
    options: [
      "It builds a broader picture of a target using public data",
      "It replaces all technical testing",
      "It guarantees no false positives",
      "It always requires direct scanning",
    ],
    correctAnswer: 0,
    explanation: "OSINT provides context and leads from public sources.",
  },
];

const outlineSections = [
  {
    id: "fundamentals",
    title: "OSINT Fundamentals",
    icon: <SecurityIcon />,
    color: "#f97316",
    status: "Complete",
    description: "Passive vs active recon, workflow stages, legal boundaries",
  },
  {
    id: "domain-recon",
    title: "Domain & DNS Recon",
    icon: <DnsIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "WHOIS, DNS records, subdomains, infrastructure mapping",
  },
  {
    id: "people-orgs",
    title: "People & Organization Intel",
    icon: <PersonSearchIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "Org structure, social presence, emails, and personas",
  },
  {
    id: "images-metadata",
    title: "Images & Metadata",
    icon: <ImageIcon />,
    color: "#10b981",
    status: "Complete",
    description: "EXIF data, reverse image search, document metadata",
  },
  {
    id: "code-repos",
    title: "Code & Repository Recon",
    icon: <GitHubIcon />,
    color: "#0ea5e9",
    status: "Complete",
    description: "GitHub search, leaked secrets, dependency trails",
  },
  {
    id: "advanced-osint",
    title: "Advanced OSINT",
    icon: <PublicIcon />,
    color: "#f59e0b",
    status: "Complete",
    description: "Dark web, sock puppets, automation, link analysis",
  },
  {
    id: "tools",
    title: "Tools & Automation",
    icon: <CodeIcon />,
    color: "#ec4899",
    status: "Complete",
    description: "Tooling reference, automation scripts, and workflows",
  },
];

const quickStats = [
  { value: "7", label: "Core Modules", color: "#f97316" },
  { value: "75", label: "Quiz Questions", color: "#3b82f6" },
  { value: "3", label: "Recon Phases", color: "#10b981" },
  { value: "50+", label: "Sources & Tools", color: "#8b5cf6" },
];

const OSINTReconPage: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const accent = ACCENT_COLOR;

  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const tabValue = 0;

  const pageContext = `OSINT & Reconnaissance learning page covering passive and active recon, domain/DNS enumeration, people and organization intelligence, image/metadata analysis, code repository recon, advanced OSINT workflows, and essential tooling.`;

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <TravelExploreIcon /> },
    { id: "outline", label: "Outline", icon: <ListAltIcon /> },
    { id: "prerequisites", label: "Prerequisites", icon: <CheckCircleIcon /> },
    { id: "fundamentals", label: "Fundamentals", icon: <SecurityIcon /> },
    { id: "domain-recon", label: "Domain Recon", icon: <DnsIcon /> },
    { id: "people-orgs", label: "People & Orgs", icon: <PersonSearchIcon /> },
    { id: "images-metadata", label: "Images & Metadata", icon: <ImageIcon /> },
    { id: "code-repos", label: "Code & Repos", icon: <GitHubIcon /> },
    { id: "advanced-osint", label: "Advanced OSINT", icon: <PublicIcon /> },
    { id: "tools", label: "Tools", icon: <CodeIcon /> },
    { id: "next-steps", label: "Next Steps", icon: <SchoolIcon /> },
    { id: "key-takeaways", label: "Takeaways", icon: <TipsAndUpdatesIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      let currentSection = "";

      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            currentSection = sectionId;
          }
        }
      }
      setActiveSection(currentSection);
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? accent : "text.secondary",
                      fontSize: "0.75rem",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="OSINT & Reconnaissance" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: accent,
            "&:hover": { bgcolor: "#ea580c" },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha(accent, 0.15),
            color: accent,
            "&:hover": { bgcolor: alpha(accent, 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer - Mobile */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.1),
                  },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? accent : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(accent, 0.2),
                      color: accent,
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
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

          {/* Hero Banner */}
          <Paper
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#f97316", 0.16)} 0%, ${alpha("#f59e0b", 0.16)} 50%, ${alpha("#0ea5e9", 0.16)} 100%)`,
              border: `1px solid ${alpha(accent, 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Box
              sx={{
                position: "absolute",
                top: -50,
                right: -50,
                width: 200,
                height: 200,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha("#f97316", 0.12)} 0%, transparent 70%)`,
              }}
            />
            <Box
              sx={{
                position: "absolute",
                bottom: -30,
                left: "30%",
                width: 150,
                height: 150,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha("#0ea5e9", 0.12)} 0%, transparent 70%)`,
              }}
            />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: `linear-gradient(135deg, #f97316, #f59e0b)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#f97316", 0.3)}`,
                  }}
                >
                  <TravelExploreIcon sx={{ fontSize: 44, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    OSINT & Reconnaissance
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                    Open source intelligence for mapping targets and context
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Passive Recon" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
                <Chip label="Domain Intel" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600 }} />
                <Chip label="People & Org" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
                <Chip label="OpSec Mindset" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
              </Box>

              {/* Quick Stats */}
              <Grid container spacing={2}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper
                      sx={{
                        p: 2,
                        textAlign: "center",
                        borderRadius: 2,
                        bgcolor: alpha(stat.color, 0.1),
                        border: `1px solid ${alpha(stat.color, 0.2)}`,
                      }}
                    >
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                        {stat.value}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                        {stat.label}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* ==================== INTRODUCTION ==================== */}
          <Typography id="intro" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            OSINT & Recon Overview
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Build a reliable picture of a target using public signals, then validate with careful follow-up.
          </Typography>

          <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha(accent, 0.04), border: `1px solid ${alpha(accent, 0.15)}` }}>
            <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
              <strong>Open Source Intelligence (OSINT)</strong> turns public data into actionable context. You start with
              passive sources like DNS, public records, social media, and code repositories, then correlate those signals to
              map people, infrastructure, and relationships.
            </Typography>
            <Box sx={{ my: 3 }}>
              <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
                Reconnaissance blends collection with validation. You gather data, check for consistency, and document
                sources so findings can be reproduced. Done well, OSINT reduces blind spots, improves targeting, and
                highlights the highest-value areas for deeper investigation.
              </Typography>
            </Box>
            <Alert severity="warning">
              <strong>Legal note:</strong> Only collect information you are authorized to gather, respect privacy laws, and
              follow terms of service for every source.
            </Alert>
          </Paper>

          {/* ==================== COURSE OUTLINE ==================== */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              SUMMARY
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography id="outline" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Course Outline
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            A structured path through OSINT fundamentals, workflows, and tools.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {outlineSections.map((section, index) => (
              <Grid item xs={12} sm={6} md={4} key={section.id}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 3,
                    border: `1px solid ${alpha(section.color, section.status === "Complete" ? 0.3 : 0.15)}`,
                    bgcolor: section.status === "Complete" ? alpha(section.color, 0.03) : "transparent",
                    opacity: section.status === "Complete" ? 1 : 0.75,
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      borderColor: section.color,
                      opacity: 1,
                      boxShadow: `0 8px 24px ${alpha(section.color, 0.15)}`,
                    },
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 1 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Box
                        sx={{
                          width: 32,
                          height: 32,
                          borderRadius: 1.5,
                          bgcolor: alpha(section.color, 0.1),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          color: section.color,
                        }}
                      >
                        {section.icon}
                      </Box>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary" }}>
                        {String(index + 1).padStart(2, "0")}
                      </Typography>
                    </Box>
                    <Chip
                      label={section.status}
                      size="small"
                      icon={<CheckCircleIcon sx={{ fontSize: 14 }} />}
                      sx={{
                        fontSize: "0.65rem",
                        height: 22,
                        bgcolor: alpha("#10b981", 0.1),
                        color: "#10b981",
                        "& .MuiChip-icon": {
                          color: "#10b981",
                        },
                      }}
                    />
                  </Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {section.title}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.5 }}>
                    {section.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* ==================== PREREQUISITES ==================== */}
          <Typography id="prerequisites" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Prerequisites
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Recommended background knowledge and habits that make OSINT work effective.
          </Typography>

          <Grid container spacing={3} sx={{ mb: 5 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
                  Helpful to Have
                </Typography>
                <List dense>
                  {[
                    "Basic web and DNS concepts",
                    "Comfort with search operators",
                    "Note-taking and source tracking",
                    "Patience for validation work",
                    "Awareness of privacy and legal boundaries",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                  Nice to Have
                </Typography>
                <List dense>
                  {[
                    "Basic networking fundamentals",
                    "Python or Bash scripting",
                    "Familiarity with breach data",
                    "Understanding of web tech stacks",
                    "Experience with DNS tooling",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <TipsAndUpdatesIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                  We'll Teach You
                </Typography>
                <List dense>
                  {[
                    "A repeatable recon workflow",
                    "Source validation strategies",
                    "OpSec hygiene for OSINT",
                    "Tooling for automation",
                    "Reporting and documentation",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <SchoolIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          {/* ==================== FUNDAMENTALS ==================== */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Typography id="fundamentals" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
                OSINT Fundamentals
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Core definitions, recon phases, and the standard workflow.
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

          {/* ==================== DOMAIN RECON ==================== */}
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Typography id="domain-recon" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
                Domain & Infrastructure Reconnaissance
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Map domains, subdomains, and infrastructure to build an accurate attack surface.
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

          {/* ==================== PEOPLE & ORGS ==================== */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Typography id="people-orgs" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
                People & Organization Intelligence
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Identify people, roles, and relationships without direct contact.
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

          {/* ==================== IMAGES & METADATA ==================== */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Typography id="images-metadata" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
                Image & Metadata Analysis
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Extract signals from media, documents, and historical context.
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

          {/* ==================== CODE & REPOS ==================== */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Typography id="code-repos" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
                Code Repository Intelligence
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Mine code hosting platforms for configuration leaks and internal references.
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

          {/* ==================== ADVANCED OSINT ==================== */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Typography id="advanced-osint" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
                Advanced OSINT Techniques
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                High-sensitivity sources, deeper validation, and operational safety.
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

          {/* ==================== TOOLS ==================== */}
          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 3 }}>
              <Typography id="tools" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
                OSINT Tools Reference
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                A curated toolkit for discovery, automation, and validation.
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

          {/* ==================== NEXT STEPS ==================== */}
          <Typography id="next-steps" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Next Steps
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Continue with adjacent topics that build on OSINT skills.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {[
              { title: "Cyber Threat Intel", path: "/learn/cti", color: "#8b5cf6", description: "Turn OSINT into strategic intelligence" },
              { title: "Threat Hunting", path: "/learn/threat-hunting", color: "#0ea5e9", description: "Apply intel to proactive defense" },
              { title: "Scanning Fundamentals", path: "/learn/scanning", color: "#f97316", description: "Validate recon with active scanning" },
              { title: "Nmap Guide", path: "/learn/nmap", color: "#22c55e", description: "Map services and live hosts" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.title}>
                <Paper
                  onClick={() => navigate(item.path)}
                  sx={{
                    p: 2.5,
                    textAlign: "center",
                    cursor: "pointer",
                    borderRadius: 3,
                    border: `1px solid ${alpha(item.color, 0.2)}`,
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-4px)",
                      borderColor: item.color,
                      boxShadow: `0 8px 24px ${alpha(item.color, 0.2)}`,
                    },
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>
                    {item.title}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {item.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Key Takeaways */}
          <Paper
            id="key-takeaways"
            sx={{
              p: 4,
              mb: 5,
              borderRadius: 3,
              bgcolor: alpha("#10b981", 0.03),
              border: `1px solid ${alpha("#10b981", 0.15)}`,
              scrollMarginTop: 180,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon sx={{ color: "#10b981" }} />
              Key Takeaways
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>
                  Start Passive, Then Validate
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Build context from public sources, then confirm with targeted probes if authorized.
                </Typography>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>
                  Document Every Source
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Track where each signal came from so findings are repeatable and defensible.
                </Typography>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>
                  Protect Your OpSec
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Separate personas, reduce attribution, and follow legal boundaries at every step.
                </Typography>
              </Grid>
            </Grid>
          </Paper>

          {/* ==================== QUIZ SECTION ==================== */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              TEST YOUR KNOWLEDGE
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography id="quiz" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Knowledge Quiz
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Test your OSINT and reconnaissance fundamentals with a quick randomized quiz.
          </Typography>

          <Paper
            sx={{
              mt: 2,
              p: 4,
              borderRadius: 3,
              border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
            }}
          >
            <QuizSection
              questions={quizQuestions}
              accentColor={QUIZ_ACCENT_COLOR}
              title="OSINT and Reconnaissance Knowledge Check"
              description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
              questionsPerQuiz={QUIZ_QUESTION_COUNT}
            />
          </Paper>

          {/* Footer Navigation */}
          <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
            <Button
              variant="outlined"
              size="large"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{
                borderRadius: 2,
                px: 4,
                py: 1.5,
                fontWeight: 600,
                borderColor: alpha(accent, 0.3),
                color: accent,
                "&:hover": {
                  borderColor: accent,
                  bgcolor: alpha(accent, 0.05),
                },
              }}
            >
              Return to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default OSINTReconPage;
