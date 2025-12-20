import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
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
  IconButton,
  Tooltip,
  Alert,
  Card,
  CardContent,
  Divider,
  alpha,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import SecurityIcon from "@mui/icons-material/Security";
import SearchIcon from "@mui/icons-material/Search";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import TimelineIcon from "@mui/icons-material/Timeline";
import StorageIcon from "@mui/icons-material/Storage";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import CodeIcon from "@mui/icons-material/Code";
import ScienceIcon from "@mui/icons-material/Science";
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

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "bash",
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
        p: 2,
        bgcolor: "#121424",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(14, 165, 233, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#0ea5e9", color: "#0b1020" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#e2e8f0" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const DataExfiltrationPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page covers data exfiltration detection and prevention with MITRE ATT&CK mapping. Topics include:
- Exfiltration techniques mapped to ATT&CK T1041-T1567
- 15+ exfiltration channels (web uploads, DNS tunneling, steganography, cloud services, encrypted channels)
- Data locations at risk (file shares, databases, email/chat, developer repos, cloud storage, endpoints)
- Advanced detection with SIEM queries, network analysis, and behavioral indicators
- DLP strategies, egress filtering, and prevention controls
- Incident response playbook with timeline reconstruction
- Real-world case studies and attack scenarios
- Hands-on lab exercises with safe boundaries
The page includes beginner-friendly explanations and advanced technical details.`;

  const mitreAttackTechniques = [
    { id: "T1041", name: "Exfiltration Over C2 Channel", desc: "Data sent over the same channel used for command and control." },
    { id: "T1048", name: "Exfiltration Over Alternative Protocol", desc: "Using non-standard protocols like DNS, ICMP, or SMTP." },
    { id: "T1048.001", name: "Exfiltration Over Symmetric Encrypted Non-C2", desc: "Encrypted channels separate from C2." },
    { id: "T1048.002", name: "Exfiltration Over Asymmetric Encrypted Non-C2", desc: "Using asymmetric encryption for data transfer." },
    { id: "T1048.003", name: "Exfiltration Over Unencrypted Non-C2", desc: "Cleartext transfer over non-C2 channels." },
    { id: "T1052", name: "Exfiltration Over Physical Medium", desc: "USB drives, external disks, or other physical media." },
    { id: "T1567", name: "Exfiltration Over Web Service", desc: "Using legitimate cloud services like GitHub, Dropbox, Google Drive." },
    { id: "T1567.001", name: "Exfiltration to Code Repository", desc: "Pushing data to Git repos or code hosting platforms." },
    { id: "T1567.002", name: "Exfiltration to Cloud Storage", desc: "Uploading to cloud storage services." },
    { id: "T1029", name: "Scheduled Transfer", desc: "Data exfiltrated at specific times to blend with normal traffic." },
    { id: "T1030", name: "Data Transfer Size Limits", desc: "Breaking data into small chunks to avoid detection." },
    { id: "T1537", name: "Transfer Data to Cloud Account", desc: "Moving data to attacker-controlled cloud accounts." },
  ];

  const advancedTechniques = [
    {
      name: "DNS Tunneling",
      desc: "Encoding data in DNS queries/responses to bypass firewalls.",
      tools: "dnscat2, iodine, dns2tcp",
      detection: "High volume DNS queries, unusual TXT records, long subdomain names (>50 chars).",
      mitreId: "T1048.003",
    },
    {
      name: "ICMP Tunneling",
      desc: "Hiding data in ICMP echo request/reply packets.",
      tools: "icmpsh, ptunnel, ICMP-Shell",
      detection: "Large ICMP payloads, high ICMP frequency, unusual ICMP types.",
      mitreId: "T1048.003",
    },
    {
      name: "Steganography",
      desc: "Hiding data within images, audio, or video files.",
      tools: "steghide, OpenStego, snow",
      detection: "Unusual file metadata, statistical analysis of image entropy.",
      mitreId: "T1027.003",
    },
    {
      name: "HTTPS to Legitimate Services",
      desc: "Using trusted domains like pastebin, GitHub, or cloud APIs.",
      tools: "gist, S3 buckets, Azure Blob",
      detection: "Unusual upload patterns, API calls to new cloud services.",
      mitreId: "T1567.002",
    },
    {
      name: "Email Attachments",
      desc: "Sending data as email attachments to external addresses.",
      tools: "Standard email clients, SMTP scripts",
      detection: "Large attachments to external domains, unusual recipients.",
      mitreId: "T1048.003",
    },
    {
      name: "Protocol Mismatch",
      desc: "Using port 443 for non-HTTPS traffic or port 53 for non-DNS.",
      tools: "Custom tunneling tools",
      detection: "Protocol analysis on standard ports, DPI inspection.",
      mitreId: "T1571",
    },
    {
      name: "Slow Exfiltration",
      desc: "Trickling data out over days/weeks to avoid volume alerts.",
      tools: "Custom scripts with delays",
      detection: "Long-term baseline comparison, cumulative transfer analysis.",
      mitreId: "T1030",
    },
    {
      name: "Cloud-to-Cloud Transfer",
      desc: "Moving data between cloud services to mask the source.",
      tools: "Cloud sync tools, APIs",
      detection: "Cross-tenant sharing, unusual cloud-to-cloud API calls.",
      mitreId: "T1537",
    },
  ];

  const realWorldScenarios = [
    {
      title: "Insider Threat - Departing Employee",
      scenario: "An employee about to leave downloads large amounts of data to a personal cloud drive over several weeks.",
      indicators: ["Increased file access outside normal hours", "New cloud sync client installed", "Large downloads from SharePoint/OneDrive", "Access to folders not related to current role"],
      response: "Review access patterns, check cloud storage logs, interview employee, preserve evidence.",
    },
    {
      title: "Compromised Service Account",
      scenario: "Attackers use a compromised service account to stage and exfiltrate database exports.",
      indicators: ["Service account accessing unusual file shares", "Large SQL exports created", "Outbound connections to rare domains", "Archive files in temp directories"],
      response: "Disable account, analyze network logs, check for persistence mechanisms, rotate credentials.",
    },
    {
      title: "Supply Chain Compromise",
      scenario: "Malicious code in a third-party library exfiltrates sensitive data via DNS queries.",
      indicators: ["Unexpected DNS queries from application servers", "Long DNS subdomain names", "TXT record queries to new domains", "Spike in DNS traffic volume"],
      response: "Block suspicious domains, audit dependencies, deploy DNS monitoring, review code.",
    },
    {
      title: "Ransomware Double Extortion",
      scenario: "Attackers exfiltrate data before encrypting systems, threatening to publish if ransom isn't paid.",
      indicators: ["Large archive creation before encryption", "Outbound transfers to rare IPs", "Rclone or similar tools executed", "Rapid file access across multiple shares"],
      response: "Isolate systems, analyze exfil scope, engage legal/PR, preserve forensic evidence.",
    },
  ];

  const siemQueries = [
    {
      name: "Large Outbound Transfers",
      platform: "Splunk",
      query: `index=proxy sourcetype=web_proxy bytes_out>50000000
| stats sum(bytes_out) as total_bytes by src_ip, dest_host
| where total_bytes > 100000000
| sort -total_bytes`,
      description: "Find hosts sending more than 100MB to external destinations.",
    },
    {
      name: "DNS Tunneling Detection",
      platform: "Splunk",
      query: `index=dns sourcetype=dns
| eval subdomain_len=len(mvindex(split(query,"."),0))
| where subdomain_len > 50
| stats count by query, src_ip
| where count > 10`,
      description: "Detect unusually long DNS subdomains (potential tunneling).",
    },
    {
      name: "Archive Creation Before Transfer",
      platform: "Microsoft Sentinel",
      query: `DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteIPType == "Public"
    | where ActionType == "ConnectionSuccess"
) on DeviceId
| where Timestamp1 between (Timestamp .. (Timestamp + 1h))
| project DeviceName, FileName, RemoteIP, Timestamp`,
      description: "Correlate archive creation with subsequent network connections.",
    },
    {
      name: "Cloud Storage Uploads",
      platform: "Elastic/ELK",
      query: `GET _search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"destination.domain": "*dropbox* OR *drive.google* OR *onedrive*"}},
        {"range": {"http.request.bytes": {"gte": 10000000}}}
      ]
    }
  }
}`,
      description: "Find large uploads to known cloud storage services.",
    },
  ];

  const networkIndicators = [
    { indicator: "Beaconing patterns", desc: "Regular interval connections to external hosts (e.g., every 60 seconds).", threshold: "Check for consistent timing patterns over 24+ hours." },
    { indicator: "Data volume spikes", desc: "Unusual egress volume compared to baseline.", threshold: ">2 standard deviations from 30-day average." },
    { indicator: "New destinations", desc: "First-time connections to external domains/IPs.", threshold: "Any connection to domains not seen in past 90 days." },
    { indicator: "Protocol anomalies", desc: "Traffic on standard ports that doesn't match expected protocol.", threshold: "Any mismatch detected by DPI." },
    { indicator: "Long connections", desc: "Persistent connections that stay open for hours.", threshold: ">4 hours for non-streaming traffic." },
    { indicator: "High DNS query rate", desc: "Excessive DNS queries from a single host.", threshold: ">1000 unique queries per hour." },
    { indicator: "Encoded payloads", desc: "Base64 or hex-encoded data in HTTP/DNS requests.", threshold: "Pattern matching on request bodies." },
  ];

  const dlpStrategies = [
    {
      category: "Content Inspection",
      controls: [
        "Regex patterns for credit cards, SSNs, API keys",
        "Keyword matching for classified terms",
        "Document fingerprinting for sensitive files",
        "OCR for images containing text",
      ],
    },
    {
      category: "Contextual Analysis",
      controls: [
        "User behavior baseline comparison",
        "File access patterns outside normal hours",
        "Volume thresholds per user/department",
        "Destination reputation scoring",
      ],
    },
    {
      category: "Endpoint Controls",
      controls: [
        "Block USB writes or require encryption",
        "Screen capture prevention",
        "Clipboard monitoring for sensitive data",
        "Print job logging and restrictions",
      ],
    },
    {
      category: "Network Controls",
      controls: [
        "SSL/TLS inspection for encrypted traffic",
        "Block known file-sharing domains",
        "Egress filtering by category",
        "DNS sinkholing for suspicious domains",
      ],
    },
  ];

  const incidentPlaybook = [
    {
      phase: "Detection",
      actions: [
        "Alert triggered by DLP, SIEM, or user report",
        "Validate alert is not a false positive",
        "Identify affected user, host, and data type",
        "Assign severity based on data classification",
      ],
      timeframe: "0-15 minutes",
    },
    {
      phase: "Containment",
      actions: [
        "Disable external sharing permissions",
        "Block destination domain/IP at firewall",
        "Suspend user account if insider threat",
        "Isolate endpoint if malware suspected",
      ],
      timeframe: "15-60 minutes",
    },
    {
      phase: "Investigation",
      actions: [
        "Collect logs: proxy, firewall, endpoint, cloud audit",
        "Build timeline of events",
        "Identify all accessed/transferred files",
        "Determine scope: how much data, how long, where",
      ],
      timeframe: "1-24 hours",
    },
    {
      phase: "Eradication",
      actions: [
        "Remove malware or unauthorized tools",
        "Revoke compromised credentials",
        "Delete staged/transferred copies if possible",
        "Patch exploited vulnerabilities",
      ],
      timeframe: "1-7 days",
    },
    {
      phase: "Recovery",
      actions: [
        "Restore normal access with enhanced monitoring",
        "Implement additional controls to prevent recurrence",
        "Update DLP policies based on lessons learned",
        "Conduct post-incident review",
      ],
      timeframe: "1-2 weeks",
    },
    {
      phase: "Notification",
      actions: [
        "Legal review for regulatory requirements (GDPR, HIPAA, etc.)",
        "Notify affected individuals if required",
        "Report to authorities if applicable",
        "Internal communication to stakeholders",
      ],
      timeframe: "As required by law",
    },
  ];

  const advancedLabExercises = [
    {
      name: "DNS Tunneling Detection Lab",
      difficulty: "Intermediate",
      steps: [
        "Set up a lab DNS server with logging enabled",
        "Generate fake DNS tunnel traffic using dnscat2 (lab only)",
        "Analyze DNS logs for long subdomain patterns",
        "Write a detection rule for >50 character subdomains",
        "Document findings and create alert thresholds",
      ],
      tools: "BIND/dnsmasq, dnscat2, Wireshark, Python",
    },
    {
      name: "Cloud Exfiltration Simulation",
      difficulty: "Beginner",
      steps: [
        "Create a test file with fake sensitive markers",
        "Upload to a personal cloud storage in lab",
        "Review cloud audit logs (if available) or proxy logs",
        "Identify the upload event and metadata",
        "Write a report documenting the exfil path",
      ],
      tools: "Cloud storage account, proxy logs",
    },
    {
      name: "Baseline Deviation Analysis",
      difficulty: "Advanced",
      steps: [
        "Collect 30 days of egress data for a lab network",
        "Calculate mean and standard deviation per host",
        "Simulate an exfiltration event with large transfer",
        "Detect the anomaly using statistical analysis",
        "Tune thresholds to reduce false positives",
      ],
      tools: "SIEM, Python/pandas, network logs",
    },
    {
      name: "Timeline Reconstruction",
      difficulty: "Intermediate",
      steps: [
        "Given a set of log files, reconstruct the attack timeline",
        "Identify: initial access, discovery, staging, exfiltration",
        "Map events to MITRE ATT&CK techniques",
        "Create a visual timeline with timestamps",
        "Present findings in a mock incident report",
      ],
      tools: "Log files, timeline tools, spreadsheet",
    },
  ];

  const objectives = [
    "Explain data exfiltration in plain language.",
    "Identify common exfiltration paths and signals.",
    "Understand where sensitive data usually lives.",
    "Review detection sources and safe checks.",
    "Practice a safe, lab-only exercise.",
  ];
  const beginnerPath = [
    "1) Read the glossary and objectives.",
    "2) Learn the main exfiltration channels.",
    "3) Identify where sensitive data lives in your org.",
    "4) Review detection signals and telemetry sources.",
    "5) Run a safe lab exercise and write a short report.",
  ];
  const whatItIsNot = [
    "It is not a guide to stealing data or bypassing security.",
    "It is not a replacement for legal or compliance advice.",
    "It is not about running offensive tools on real systems.",
  ];
  const whyHard = [
    "Many legitimate business activities look like data movement.",
    "Sensitive data often lives in multiple locations and copies.",
    "Attackers can move data slowly to avoid detection thresholds.",
  ];
  const roles = [
    { role: "SOC analyst", focus: "Monitor alerts and investigate egress anomalies." },
    { role: "IT admin", focus: "Control sharing settings and device permissions." },
    { role: "Security engineer", focus: "Tune DLP policies and telemetry pipelines." },
    { role: "Compliance", focus: "Ensure regulatory requirements are met." },
  ];
  const misconceptions = [
    {
      myth: "Exfiltration always means a huge data dump.",
      reality: "Small, repeated transfers can be harder to detect.",
    },
    {
      myth: "If DLP is enabled, exfiltration is impossible.",
      reality: "DLP reduces risk but still requires tuning and monitoring.",
    },
    {
      myth: "Only external attackers exfiltrate data.",
      reality: "Insiders or compromised accounts can also do it.",
    },
  ];

  const glossary = [
    { term: "Exfiltration", desc: "Moving data out of a system or network without permission." },
    { term: "Data loss", desc: "Accidental or malicious exposure of sensitive data." },
    { term: "DLP", desc: "Data Loss Prevention tools that detect or block leaks." },
    { term: "Egress", desc: "Outbound network traffic leaving a network." },
    { term: "Staging", desc: "Collecting data in a temporary place before transfer." },
  ];
  const dataClassification = [
    { level: "Public", desc: "Safe to share externally." },
    { level: "Internal", desc: "For employees only; limited external sharing." },
    { level: "Confidential", desc: "Sensitive business data; restricted access." },
    { level: "Restricted", desc: "Highly sensitive data with strict controls." },
  ];
  const dataTypes = [
    { type: "PII", desc: "Personal data like names, addresses, IDs." },
    { type: "Credentials", desc: "Passwords, tokens, API keys, SSH keys." },
    { type: "Source code", desc: "Proprietary code and intellectual property." },
    { type: "Financial", desc: "Invoices, payroll, payment data." },
    { type: "Health", desc: "Medical records or sensitive health info." },
  ];
  const fileTypeIndicators = [
    "Archives: .zip, .7z, .rar",
    "Database exports: .sql, .csv, .bak",
    "Spreadsheets: .xlsx, .csv",
    "Source code: .git bundles, .tar.gz",
    "Documents: .pdf, .docx",
  ];
  const exfilPhases = [
    "Discovery: find sensitive data locations.",
    "Collection: gather files into a staging area.",
    "Compression: package data into archives.",
    "Transfer: move data out through a channel.",
    "Cleanup: remove traces or delete temporary files.",
  ];
  const exfilExamples = [
    "A user uploads a report to a personal cloud drive.",
    "A compromised account shares a private folder externally.",
    "An archive is created and sent via email to an outside address.",
  ];

  const channels = [
    {
      title: "Web uploads",
      desc: "Data sent to cloud storage or web apps via HTTPS.",
      signal: "Large uploads to new domains or file-sharing sites.",
    },
    {
      title: "Email and collaboration tools",
      desc: "Sending sensitive files through email or chat.",
      signal: "Attachments leaving the org or external shares.",
    },
    {
      title: "External storage",
      desc: "Copying data to USB drives or external disks.",
      signal: "Large file copy activity or new device mounts.",
    },
    {
      title: "DNS and covert channels",
      desc: "Encoding data into DNS or unusual protocols.",
      signal: "High-volume DNS queries or unusual domain patterns.",
    },
    {
      title: "Rsync/SCP/SFTP",
      desc: "Command-line transfers to external servers.",
      signal: "Outbound SSH sessions to unknown hosts.",
    },
    {
      title: "Messaging and paste services",
      desc: "Copying data into paste bins, chat apps, or web forms.",
      signal: "Access to paste services or unsanctioned chat tools.",
    },
    {
      title: "Cloud sync clients",
      desc: "Sync tools moving files to personal accounts.",
      signal: "Large sync events or new sync folders.",
    },
  ];

  const dataLocations = [
    { location: "File shares and network drives", risk: "Large data sets and archives." },
    { location: "Databases and exports", risk: "CSV/SQL dumps in temp folders." },
    { location: "Email and chat", risk: "Sensitive content shared externally." },
    { location: "Developer repos", risk: "Secrets in code or config files." },
    { location: "Cloud storage", risk: "Public links or shared buckets." },
    { location: "Endpoints (downloads/temp)", risk: "Staged archives on local disks." },
    { location: "SaaS exports", risk: "Bulk exports of customer or HR data." },
    { location: "Backups and snapshots", risk: "Large archives stored outside policy." },
  ];

  const signals = [
    "Unusually large outbound transfers or spikes in egress.",
    "Uploads to new or rarely used domains.",
    "Compressed archives created shortly before transfer.",
    "Access to sensitive folders outside normal hours.",
    "New external sharing permissions on files.",
  ];
  const behaviorSignals = [
    "Repeated small uploads over time to the same external destination.",
    "High-volume DNS queries to a single domain.",
    "Use of command-line transfer tools by non-admins.",
    "Sensitive files accessed by service accounts.",
  ];
  const stagingSignals = [
    "Large numbers of files copied into a new folder.",
    "Archives created with unusual names or hidden locations.",
    "Temporary files created and deleted in short bursts.",
    "Use of compression tools outside standard workflows.",
  ];

  const telemetry = [
    "Proxy and firewall logs (egress and destination domains).",
    "Cloud storage audit logs (shares and downloads).",
    "Endpoint file access and compression events.",
    "Email and collaboration audit logs.",
    "DLP alerts and policy triggers.",
  ];
  const detectionMatrix = [
    {
      stage: "Staging",
      signal: "Large file copy or archive creation.",
      evidence: "Endpoint file events and zip creation logs.",
    },
    {
      stage: "Transfer",
      signal: "Large outbound upload or new destination.",
      evidence: "Proxy/firewall logs and cloud audit logs.",
    },
    {
      stage: "Sharing",
      signal: "External link created or permissions changed.",
      evidence: "Cloud storage audit logs.",
    },
  ];
  const evidenceChecklist = [
    "Source host, user, and timestamp",
    "Destination domain or IP",
    "Files accessed or transferred",
    "Compression or staging artifacts",
    "Policy or DLP alerts",
  ];

  const prevention = [
    "Classify data and label sensitive files.",
    "Use DLP policies to detect and block risky transfers.",
    "Restrict external sharing by default.",
    "Monitor large outbound transfers and new domains.",
    "Use least privilege for data access.",
  ];
  const controlIdeas = [
    "Require approvals for external sharing links.",
    "Block unsanctioned cloud storage services.",
    "Limit USB access or enforce encryption.",
    "Enforce egress filtering and allowlists.",
    "Set data retention and minimize stored sensitive data.",
  ];
  const responseSteps = [
    "Identify affected data and scope of exposure.",
    "Revoke sharing links and rotate exposed credentials.",
    "Contain the account or device if needed.",
    "Notify stakeholders per policy and compliance rules.",
    "Document the timeline and lessons learned.",
  ];

  const labSteps = [
    "Use a lab machine with fake data only.",
    "Create a test file labeled as sensitive.",
    "Compress it locally and note the timestamp.",
    "Review logs for file creation and access.",
    "Write a short report with what you observed.",
  ];
  const safeBoundaries = [
    "Use fake or synthetic data only.",
    "Do not upload real data to external services.",
    "Keep the lab isolated from production systems.",
    "Get approval before any testing outside the lab.",
  ];
  const reportTemplate = `Host: <name>  Date: <utc>
Data type: <PII/Code/Financial/etc>
Location: <path or share>
Observed action: <archive, upload, share>
Destination: <domain or service>
Evidence: <logs or screenshots>
Risk: <why this matters>
Recommendation: <block, monitor, educate>`;

  const safeChecks = `# List large files in a lab folder (read-only)
Get-ChildItem -Path C:\\LabData -Recurse | Sort-Object Length -Descending | Select-Object -First 10 Name, Length

# Check recent zip files (lab)
Get-ChildItem -Path C:\\LabData -Recurse -Filter *.zip | Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName, LastWriteTime

# Linux example (lab)
find ~/labdata -type f -printf "%s %p\\n" | sort -nr | head -n 10`;

  return (
    <LearnPageLayout pageTitle="Data Exfiltration" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <CloudUploadIcon sx={{ fontSize: 42, color: "#0ea5e9" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #0ea5e9 0%, #38bdf8 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Data Exfiltration
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Data exfiltration means moving data out of a system or network without permission.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, exfiltration is like taking files out of a building without authorization. It can happen
            through websites, email, cloud drives, or even USB devices. This page shows the common paths and how to
            spot early warning signs.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
            Exfiltration is often the last step of a breach. Attackers may take small amounts of data repeatedly
            to avoid detection. Knowing where sensitive data lives and how it can leave helps you respond faster.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            The focus here is defensive: recognize risks, improve monitoring, and build good documentation habits.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            Everything here is beginner-friendly and focuses on safe observation, logging, and documentation.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<SecurityIcon />} label="Data Paths" size="small" />
          <Chip icon={<SearchIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Prevention" size="small" />
          <Chip icon={<WarningIcon />} label="Risk Signals" size="small" />
          <Chip icon={<BugReportIcon />} label="MITRE ATT&CK" size="small" sx={{ bgcolor: alpha("#ef4444", 0.2), color: "#ef4444" }} />
        </Box>

        <Paper sx={{ bgcolor: "#111424", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#0ea5e9" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<BugReportIcon />} label="ATT&CK Techniques" />
            <Tab icon={<CloudUploadIcon />} label="Channels" />
            <Tab icon={<StorageIcon />} label="Data Locations" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<CodeIcon />} label="SIEM Queries" />
            <Tab icon={<ShieldIcon />} label="Prevention" />
            <Tab icon={<TimelineIcon />} label="Incident Response" />
            <Tab icon={<ScienceIcon />} label="Labs" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {objectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  What This Is Not
                </Typography>
                <List dense>
                  {whatItIsNot.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Why This Is Hard
                </Typography>
                <List dense>
                  {whyHard.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Term</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Meaning</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {glossary.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Data Classification Levels
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Level</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dataClassification.map((item) => (
                        <TableRow key={item.level}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.level}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Data Types at Risk
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Type</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dataTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Common File Indicators
                </Typography>
                <List dense>
                  {fileTypeIndicators.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Exfiltration Phases (Simple)
                </Typography>
                <List dense>
                  {exfilPhases.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Simple Examples
                </Typography>
                <List dense>
                  {exfilExamples.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(14,165,233,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#0ea5e9", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#a5b4fc", mb: 0.5 }}>
                          Reality
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {item.reality}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Who Uses This Knowledge
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Role</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Focus</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {roles.map((item) => (
                        <TableRow key={item.role}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.role}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.focus}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 1: ATT&CK Techniques (NEW) */}
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                MITRE ATT&CK provides a standardized framework for understanding adversary behavior. 
                The techniques below are commonly used for data exfiltration.
              </Alert>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#ef4444", mb: 2 }}>
                  MITRE ATT&CK Exfiltration Techniques
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#ef4444" }}>ID</TableCell>
                        <TableCell sx={{ color: "#ef4444" }}>Technique</TableCell>
                        <TableCell sx={{ color: "#ef4444" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {mitreAttackTechniques.map((item) => (
                        <TableRow key={item.id}>
                          <TableCell sx={{ color: "#f97316", fontFamily: "monospace", fontWeight: 600 }}>{item.id}</TableCell>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.name}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 2 }}>
                Advanced Exfiltration Techniques
              </Typography>
              <Grid container spacing={2}>
                {advancedTechniques.map((item) => (
                  <Grid item xs={12} md={6} key={item.name}>
                    <Card sx={{ height: "100%", bgcolor: "#0c0f1c", border: "1px solid rgba(239,68,68,0.2)" }}>
                      <CardContent>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                          <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 700 }}>
                            {item.name}
                          </Typography>
                          <Chip label={item.mitreId} size="small" sx={{ bgcolor: alpha("#ef4444", 0.2), color: "#ef4444", fontFamily: "monospace" }} />
                        </Box>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 1.5 }}>
                          {item.desc}
                        </Typography>
                        <Divider sx={{ my: 1, borderColor: "rgba(255,255,255,0.1)" }} />
                        <Typography variant="caption" sx={{ color: "#94a3b8", display: "block", mb: 0.5 }}>
                          <strong>Tools:</strong> {item.tools}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "#f59e0b", display: "block" }}>
                          <strong>Detection:</strong> {item.detection}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2 }}>
                  Real-World Attack Scenarios
                </Typography>
                {realWorldScenarios.map((scenario, idx) => (
                  <Accordion key={idx} sx={{ bgcolor: "#0b1020", mb: 1, "&:before": { display: "none" } }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                      <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 600 }}>
                        {scenario.title}
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                        {scenario.scenario}
                      </Typography>
                      <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>
                        Key Indicators:
                      </Typography>
                      <List dense>
                        {scenario.indicators.map((ind) => (
                          <ListItem key={ind} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}>
                              <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                            </ListItemIcon>
                            <ListItemText primary={ind} primaryTypographyProps={{ variant: "body2", sx: { color: "grey.300" } }} />
                          </ListItem>
                        ))}
                      </List>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mt: 1, mb: 0.5 }}>
                        Response:
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        {scenario.response}
                      </Typography>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 2: Channels */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Grid container spacing={2}>
                {channels.map((item) => (
                  <Grid item xs={12} md={6} key={item.title}>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: "#0c0f1c",
                        borderRadius: 2,
                        border: "1px solid rgba(14,165,233,0.2)",
                        height: "100%",
                      }}
                    >
                      <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 600 }}>
                        {item.title}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        {item.desc}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "#94a3b8" }}>
                        Signal: {item.signal}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </TabPanel>

          {/* Tab 3: Data Locations */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#0ea5e9" }}>Location</TableCell>
                      <TableCell sx={{ color: "#0ea5e9" }}>Risk</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {dataLocations.map((item) => (
                      <TableRow key={item.location}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.location}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          </TabPanel>

          {/* Tab 4: Detection */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Detection Signals
                </Typography>
                <List dense>
                  {signals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Behavior Signals
                </Typography>
                <List dense>
                  {behaviorSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Staging Indicators
                </Typography>
                <List dense>
                  {stagingSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Sources
                </Typography>
                <List dense>
                  {telemetry.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Detection Matrix (Simple)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Stage</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Signal</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Evidence</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {detectionMatrix.map((item) => (
                        <TableRow key={item.stage}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.stage}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.signal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.evidence}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Evidence Checklist
                </Typography>
                <List dense>
                  {evidenceChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2 }}>
                  Network Indicators
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Indicator</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Description</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Threshold</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {networkIndicators.map((item) => (
                        <TableRow key={item.indicator}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.indicator}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                          <TableCell sx={{ color: "#94a3b8", fontSize: "0.8rem" }}>{item.threshold}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 5: SIEM Queries (NEW) */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                These queries are templates for common SIEM platforms. Adjust field names and thresholds for your environment.
              </Alert>

              {siemQueries.map((query, idx) => (
                <Paper key={idx} sx={{ mb: 3, bgcolor: "#0c0f1c", borderRadius: 2, overflow: "hidden" }}>
                  <Box sx={{ p: 2, borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 600 }}>
                        {query.name}
                      </Typography>
                      <Chip label={query.platform} size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.2), color: "#0ea5e9" }} />
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.400", mt: 0.5 }}>
                      {query.description}
                    </Typography>
                  </Box>
                  <CodeBlock code={query.query} language={query.platform.toLowerCase().includes("elastic") ? "json" : "spl"} />
                </Paper>
              ))}

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2 }}>
                  Query Tuning Tips
                </Typography>
                <List dense>
                  {[
                    "Start with high thresholds and lower gradually to reduce false positives",
                    "Whitelist known good destinations (backup services, approved cloud apps)",
                    "Correlate multiple signals (staging + transfer) for higher confidence",
                    "Use time-based analysis to detect slow exfiltration over days/weeks",
                    "Create separate queries for different data types (PII, source code, etc.)",
                    "Document baseline values per department or user group",
                  ].map((tip) => (
                    <ListItem key={tip} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                      </ListItemIcon>
                      <ListItemText primary={tip} primaryTypographyProps={{ variant: "body2", sx: { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 6: Prevention */}
          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Prevention Checklist
                </Typography>
                <List dense>
                  {prevention.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Control Ideas
                </Typography>
                <List dense>
                  {controlIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Typography variant="h6" sx={{ color: "#a855f7", mt: 3, mb: 2 }}>
                DLP Strategy Categories
              </Typography>
              <Grid container spacing={2}>
                {dlpStrategies.map((strategy) => (
                  <Grid item xs={12} md={6} key={strategy.category}>
                    <Card sx={{ height: "100%", bgcolor: "#0c0f1c", border: "1px solid rgba(168,85,247,0.2)" }}>
                      <CardContent>
                        <Typography variant="subtitle1" sx={{ color: "#a855f7", fontWeight: 700, mb: 1.5 }}>
                          {strategy.category}
                        </Typography>
                        <List dense>
                          {strategy.controls.map((control) => (
                            <ListItem key={control} sx={{ py: 0.25, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckCircleIcon sx={{ fontSize: 14, color: "#a855f7" }} />
                              </ListItemIcon>
                              <ListItemText primary={control} primaryTypographyProps={{ variant: "body2", sx: { color: "grey.300" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Response Steps
                </Typography>
                <List dense>
                  {responseSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 7: Incident Response (NEW) */}
          <TabPanel value={tabValue} index={7}>
            <Box sx={{ p: 3 }}>
              <Alert severity="warning" sx={{ mb: 3 }}>
                This playbook provides a framework for responding to data exfiltration incidents. 
                Adapt timelines and actions to your organization's policies and regulatory requirements.
              </Alert>

              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2 }}>
                Incident Response Playbook
              </Typography>
              
              {incidentPlaybook.map((phase, idx) => (
                <Paper key={idx} sx={{ mb: 2, bgcolor: "#0c0f1c", borderRadius: 2, overflow: "hidden" }}>
                  <Box sx={{ 
                    p: 2, 
                    display: "flex", 
                    justifyContent: "space-between", 
                    alignItems: "center",
                    borderBottom: "1px solid rgba(255,255,255,0.1)",
                    bgcolor: alpha("#ef4444", 0.1),
                  }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Box sx={{ 
                        width: 32, 
                        height: 32, 
                        borderRadius: "50%", 
                        bgcolor: "#ef4444", 
                        display: "flex", 
                        alignItems: "center", 
                        justifyContent: "center",
                        color: "#fff",
                        fontWeight: 700,
                      }}>
                        {idx + 1}
                      </Box>
                      <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 700 }}>
                        {phase.phase}
                      </Typography>
                    </Box>
                    <Chip label={phase.timeframe} size="small" sx={{ bgcolor: alpha("#f59e0b", 0.2), color: "#f59e0b" }} />
                  </Box>
                  <Box sx={{ p: 2 }}>
                    <List dense>
                      {phase.actions.map((action) => (
                        <ListItem key={action} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                          </ListItemIcon>
                          <ListItemText primary={action} primaryTypographyProps={{ variant: "body2", sx: { color: "grey.300" } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                </Paper>
              ))}

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 2 }}>
                  Timeline Reconstruction Tips
                </Typography>
                <List dense>
                  {[
                    "Normalize all timestamps to UTC before analysis",
                    "Collect logs from multiple sources: endpoint, network, cloud, email",
                    "Look for the first suspicious event (patient zero)",
                    "Map events to MITRE ATT&CK techniques for reporting",
                    "Create a visual timeline for executive briefings",
                    "Document gaps in logging coverage for future improvement",
                    "Preserve chain of custody for potential legal proceedings",
                  ].map((tip) => (
                    <ListItem key={tip} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <TimelineIcon sx={{ fontSize: 16, color: "#0ea5e9" }} />
                      </ListItemIcon>
                      <ListItemText primary={tip} primaryTypographyProps={{ variant: "body2", sx: { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 8: Labs */}
          <TabPanel value={tabValue} index={8}>
            <Box sx={{ p: 3 }}>
              <Alert severity="warning" sx={{ mb: 3 }}>
                All lab exercises should be performed in isolated environments with synthetic data only.
                Never use real sensitive data or production systems.
              </Alert>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Beginner Lab Walkthrough (Safe)
                </Typography>
                <List dense>
                  {labSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Safe Boundaries
                </Typography>
                <List dense>
                  {safeBoundaries.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Typography variant="h6" sx={{ color: "#a855f7", mb: 2 }}>
                Advanced Lab Exercises
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {advancedLabExercises.map((lab) => (
                  <Grid item xs={12} md={6} key={lab.name}>
                    <Card sx={{ height: "100%", bgcolor: "#0c0f1c", border: "1px solid rgba(168,85,247,0.2)" }}>
                      <CardContent>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1.5 }}>
                          <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 700 }}>
                            {lab.name}
                          </Typography>
                          <Chip 
                            label={lab.difficulty} 
                            size="small" 
                            sx={{ 
                              bgcolor: lab.difficulty === "Beginner" ? alpha("#22c55e", 0.2) : 
                                       lab.difficulty === "Intermediate" ? alpha("#f59e0b", 0.2) : alpha("#ef4444", 0.2),
                              color: lab.difficulty === "Beginner" ? "#22c55e" : 
                                     lab.difficulty === "Intermediate" ? "#f59e0b" : "#ef4444",
                            }} 
                          />
                        </Box>
                        <Typography variant="caption" sx={{ color: "#94a3b8", display: "block", mb: 1.5 }}>
                          <strong>Tools:</strong> {lab.tools}
                        </Typography>
                        <Divider sx={{ my: 1, borderColor: "rgba(255,255,255,0.1)" }} />
                        <List dense>
                          {lab.steps.map((step, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <Typography variant="caption" sx={{ color: "#a855f7", fontWeight: 700 }}>{idx + 1}.</Typography>
                              </ListItemIcon>
                              <ListItemText primary={step} primaryTypographyProps={{ variant: "body2", sx: { color: "grey.300" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Report Template
                </Typography>
                <CodeBlock code={reportTemplate} language="text" />
              </Paper>

              <Accordion sx={{ bgcolor: "#0c0f1c", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                  <Typography variant="h6" sx={{ color: "#0ea5e9" }}>Safe File Review Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={safeChecks} language="powershell" />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#0ea5e9", color: "#0ea5e9" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default DataExfiltrationPage;