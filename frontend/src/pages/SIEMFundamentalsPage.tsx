import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Card,
  CardContent,
  Alert,
  Divider,
  useMediaQuery,
  Drawer,
  Fab,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import StorageIcon from "@mui/icons-material/Storage";
import SearchIcon from "@mui/icons-material/Search";
import NotificationsActiveIcon from "@mui/icons-material/NotificationsActive";
import TimelineIcon from "@mui/icons-material/Timeline";
import BuildIcon from "@mui/icons-material/Build";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CodeIcon from "@mui/icons-material/Code";
import SecurityIcon from "@mui/icons-material/Security";
import SettingsIcon from "@mui/icons-material/Settings";
import SchoolIcon from "@mui/icons-material/School";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import WarningIcon from "@mui/icons-material/Warning";
import SpeedIcon from "@mui/icons-material/Speed";
import ScienceIcon from "@mui/icons-material/Science";
import DnsIcon from "@mui/icons-material/Dns";
import QuizIcon from "@mui/icons-material/Quiz";
import MenuIcon from "@mui/icons-material/Menu";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import InfoIcon from "@mui/icons-material/Info";
import DashboardIcon from "@mui/icons-material/Dashboard";
import { Link } from "react-router-dom";

// Theme colors for consistent styling
const themeColors = {
  primary: "#3b82f6",
  primaryLight: "#60a5fa",
  secondary: "#8b5cf6",
  accent: "#10b981",
  bgCard: "#111424",
  bgNested: "#0c0f1c",
  border: "rgba(59, 130, 246, 0.2)",
  textMuted: "#94a3b8",
};

// Section navigation items for sidebar
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <InfoIcon fontSize="small" /> },
  { id: "overview", label: "Overview", icon: <DashboardIcon fontSize="small" /> },
  { id: "log-sources", label: "Log Sources", icon: <DnsIcon fontSize="small" /> },
  { id: "query-examples", label: "Query Examples", icon: <CodeIcon fontSize="small" /> },
  { id: "detection-rules", label: "Detection Rules", icon: <SecurityIcon fontSize="small" /> },
  { id: "architecture", label: "Architecture", icon: <AccountTreeIcon fontSize="small" /> },
  { id: "soc-metrics", label: "SOC Metrics", icon: <SpeedIcon fontSize="small" /> },
  { id: "labs", label: "Labs", icon: <ScienceIcon fontSize="small" /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon fontSize="small" /> },
];

// CodeBlock component
const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({
  code,
  language = "sql",
  title,
}) => {
  return (
    <Box sx={{ mb: 2 }}>
      {title && (
        <Typography variant="caption" sx={{ color: "#94a3b8", mb: 0.5, display: "block" }}>
          {title}
        </Typography>
      )}
      <Box
        component="pre"
        sx={{
          p: 2,
          borderRadius: 1,
          bgcolor: "#0d1117",
          color: "#c9d1d9",
          overflow: "auto",
          fontSize: "0.8rem",
          fontFamily: "'Fira Code', 'Consolas', monospace",
          border: "1px solid #30363d",
          maxHeight: 350,
          "&::-webkit-scrollbar": { height: 8, width: 8 },
          "&::-webkit-scrollbar-thumb": { bgcolor: "#30363d", borderRadius: 4 },
        }}
      >
        <code>{code}</code>
      </Box>
    </Box>
  );
};



interface CoreConcept {
  title: string;
  description: string;
  color: string;
}

const coreConcepts: CoreConcept[] = [
  { title: "Log Collection", description: "Aggregate logs from endpoints, servers, network devices, cloud services", color: "#3b82f6" },
  { title: "Normalization", description: "Parse and standardize log formats for consistent querying", color: "#8b5cf6" },
  { title: "Correlation", description: "Link related events across sources to identify attack patterns", color: "#ef4444" },
  { title: "Alerting", description: "Generate notifications when detection rules trigger", color: "#f59e0b" },
  { title: "Dashboards", description: "Visualize security metrics and operational status", color: "#10b981" },
  { title: "Retention", description: "Store logs for compliance, forensics, and historical analysis", color: "#6366f1" },
];

const platforms = [
  { name: "Splunk", type: "Commercial", note: "Industry leader, SPL query language", queryLang: "SPL" },
  { name: "Elastic/ELK", type: "Open Source", note: "Elasticsearch, Logstash, Kibana stack", queryLang: "KQL/Lucene" },
  { name: "Microsoft Sentinel", type: "Cloud", note: "Azure-native, KQL queries", queryLang: "KQL" },
  { name: "IBM QRadar", type: "Commercial", note: "Enterprise SIEM with UEBA", queryLang: "AQL" },
  { name: "Wazuh", type: "Open Source", note: "OSSEC-based, great for compliance", queryLang: "Lucene" },
  { name: "Google Chronicle", type: "Cloud", note: "Petabyte-scale, YARA-L rules", queryLang: "YARA-L" },
];

const useCases = [
  "Failed login attempts (brute force detection)",
  "Privilege escalation events",
  "Unusual outbound traffic patterns",
  "Malware execution indicators",
  "Data exfiltration signals",
  "Lateral movement detection",
];

// Log sources with details
const logSources = [
  {
    category: "Endpoints",
    icon: "💻",
    sources: [
      { name: "Windows Event Logs", description: "Security, System, Application events", priority: "Critical" },
      { name: "Sysmon", description: "Process creation, network connections, file changes", priority: "Critical" },
      { name: "EDR Telemetry", description: "CrowdStrike, Defender, Carbon Black", priority: "Critical" },
      { name: "PowerShell Logs", description: "Script block logging, module logging", priority: "High" },
    ],
  },
  {
    category: "Network",
    icon: "🌐",
    sources: [
      { name: "Firewall Logs", description: "Allow/deny decisions, traffic flows", priority: "Critical" },
      { name: "DNS Logs", description: "Query/response data, crucial for C2 detection", priority: "Critical" },
      { name: "Proxy Logs", description: "Web traffic, URL categories, user-agent strings", priority: "High" },
      { name: "NetFlow/IPFIX", description: "Network traffic metadata", priority: "Medium" },
    ],
  },
  {
    category: "Identity",
    icon: "🔐",
    sources: [
      { name: "Active Directory", description: "Authentication, group changes, account modifications", priority: "Critical" },
      { name: "Azure AD / Entra ID", description: "Cloud identity events, conditional access", priority: "Critical" },
      { name: "VPN Logs", description: "Remote access authentication and sessions", priority: "High" },
      { name: "MFA Logs", description: "Multi-factor authentication events", priority: "High" },
    ],
  },
  {
    category: "Cloud",
    icon: "☁️",
    sources: [
      { name: "AWS CloudTrail", description: "API calls, management events", priority: "Critical" },
      { name: "Azure Activity Logs", description: "Subscription-level events", priority: "Critical" },
      { name: "GCP Audit Logs", description: "Admin activity, data access", priority: "Critical" },
      { name: "O365/M365 Logs", description: "Email, SharePoint, Teams activity", priority: "High" },
    ],
  },
  {
    category: "Applications",
    icon: "📱",
    sources: [
      { name: "Web Server Logs", description: "Apache, Nginx, IIS access logs", priority: "Medium" },
      { name: "Database Audit Logs", description: "SQL queries, authentication", priority: "High" },
      { name: "Custom App Logs", description: "Business application events", priority: "Medium" },
      { name: "Container Logs", description: "Docker, Kubernetes audit logs", priority: "High" },
    ],
  },
];

// Query examples for different platforms
const queryExamples = {
  splunk: {
    bruteForce: `index=windows EventCode=4625
| stats count by src_ip, user
| where count > 10
| sort - count`,
    privilegeEsc: `index=windows (EventCode=4672 OR EventCode=4728 OR EventCode=4732)
| eval action=case(
    EventCode=4672, "Special Privileges Assigned",
    EventCode=4728, "User Added to Security Group",
    EventCode=4732, "User Added to Local Group"
)
| table _time, user, action, src_ip`,
    suspiciousProcess: `index=sysmon EventCode=1
| search (ParentImage="*\\\\cmd.exe" OR ParentImage="*\\\\powershell.exe")
| search Image="*\\\\whoami.exe" OR Image="*\\\\net.exe" OR Image="*\\\\nltest.exe"
| table _time, Computer, User, ParentImage, Image, CommandLine`,
    lateralMovement: `index=windows (EventCode=4624 LogonType=3) OR EventCode=4648
| stats count, values(TargetUserName), values(IpAddress) by ComputerName
| where count > 5`,
  },
  sentinel: {
    bruteForce: `SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, TargetAccount
| where FailedAttempts > 10
| order by FailedAttempts desc`,
    privilegeEsc: `SecurityEvent
| where EventID in (4672, 4728, 4732)
| extend Action = case(
    EventID == 4672, "Special Privileges Assigned",
    EventID == 4728, "User Added to Security Group",
    EventID == 4732, "User Added to Local Group",
    "Unknown"
)
| project TimeGenerated, Account, Action, Computer`,
    suspiciousProcess: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe")
| where FileName in~ ("whoami.exe", "net.exe", "nltest.exe", "ipconfig.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
    dnsExfil: `DnsEvents
| where Name contains "."
| extend SubdomainLength = strlen(tostring(split(Name, ".")[0]))
| where SubdomainLength > 50
| summarize Count = count() by Name, ClientIP
| order by Count desc`,
  },
  elastic: {
    bruteForce: `{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.code": "4625" } }
      ],
      "filter": {
        "range": { "@timestamp": { "gte": "now-1h" } }
      }
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip" },
      "aggs": {
        "by_user": { "terms": { "field": "user.name" } }
      }
    }
  }
}`,
    malwareIndicator: `{
  "query": {
    "bool": {
      "should": [
        { "wildcard": { "process.name": "*mimikatz*" } },
        { "wildcard": { "process.command_line": "*-enc*" } },
        { "match": { "file.hash.sha256": "known_malware_hash" } }
      ],
      "minimum_should_match": 1
    }
  }
}`,
  },
};

// Detection rules / use cases
const detectionRules = [
  {
    name: "Brute Force Authentication",
    mitre: "T1110",
    description: "Detect multiple failed login attempts from same source",
    logic: "Count failed logins (4625) > threshold within time window",
    threshold: ">10 failures in 5 minutes",
    severity: "Medium",
    falsePositives: ["Misconfigured service accounts", "Password changes"],
  },
  {
    name: "Suspicious PowerShell Execution",
    mitre: "T1059.001",
    description: "Detect encoded or obfuscated PowerShell commands",
    logic: "PowerShell with -enc, -encoded, downloadstring, IEX",
    threshold: "Any occurrence",
    severity: "High",
    falsePositives: ["Legitimate admin scripts", "Software deployment"],
  },
  {
    name: "Lateral Movement via PsExec",
    mitre: "T1021.002",
    description: "Detect PsExec or similar remote execution tools",
    logic: "Service creation + network logon + named pipes",
    threshold: "Correlation of events",
    severity: "High",
    falsePositives: ["Admin tools", "Software deployment"],
  },
  {
    name: "DNS Tunneling",
    mitre: "T1071.004",
    description: "Detect data exfiltration via DNS queries",
    logic: "Long subdomain names, high query volume to single domain",
    threshold: "Subdomain > 50 chars OR > 1000 queries/hour",
    severity: "High",
    falsePositives: ["CDN lookups", "Legitimate TXT records"],
  },
  {
    name: "Kerberoasting",
    mitre: "T1558.003",
    description: "Detect service ticket requests for offline cracking",
    logic: "Event 4769 with RC4 encryption (0x17) for service accounts",
    threshold: "Multiple SPNs requested in short time",
    severity: "High",
    falsePositives: ["Legitimate service access"],
  },
  {
    name: "Golden Ticket Attack",
    mitre: "T1558.001",
    description: "Detect forged Kerberos tickets",
    logic: "TGT with unusual lifetime or issued by non-DC",
    threshold: "Any anomalous ticket",
    severity: "Critical",
    falsePositives: ["Rare - requires investigation"],
  },
  {
    name: "Data Exfiltration via Cloud Storage",
    mitre: "T1567",
    description: "Detect uploads to personal cloud storage",
    logic: "Large uploads to dropbox, drive, onedrive (non-corporate)",
    threshold: ">100MB or sensitive file types",
    severity: "High",
    falsePositives: ["Approved file sharing"],
  },
  {
    name: "Credential Dumping",
    mitre: "T1003",
    description: "Detect LSASS access or credential harvesting tools",
    logic: "Process access to lsass.exe, procdump, mimikatz indicators",
    threshold: "Any occurrence",
    severity: "Critical",
    falsePositives: ["AV/EDR scanning", "Debugging tools"],
  },
];

// SOC metrics
const socMetrics = [
  { name: "MTTD", fullName: "Mean Time to Detect", description: "Average time from attack start to detection", target: "< 24 hours" },
  { name: "MTTR", fullName: "Mean Time to Respond", description: "Average time from detection to containment", target: "< 4 hours" },
  { name: "Alert Volume", fullName: "Daily Alert Count", description: "Number of alerts generated per day", target: "Manageable by team" },
  { name: "True Positive Rate", fullName: "Precision", description: "Percentage of alerts that are real incidents", target: "> 80%" },
  { name: "Coverage", fullName: "Detection Coverage", description: "MITRE ATT&CK techniques covered", target: "> 70%" },
  { name: "Dwell Time", fullName: "Attacker Dwell Time", description: "Time attacker remains undetected", target: "< 24 hours" },
];

// Lab exercises
const labExercises = [
  {
    name: "Log Source Onboarding",
    difficulty: "Beginner",
    duration: "30 min",
    objectives: [
      "Configure Windows Event Log forwarding",
      "Set up Sysmon with recommended config",
      "Validate log ingestion in SIEM",
      "Create basic field extractions",
    ],
  },
  {
    name: "Write Your First Detection Rule",
    difficulty: "Beginner",
    duration: "45 min",
    objectives: [
      "Identify brute force pattern in logs",
      "Write query to detect failed logins",
      "Set appropriate thresholds",
      "Create alert with context",
    ],
  },
  {
    name: "Investigate a Simulated Incident",
    difficulty: "Intermediate",
    duration: "60 min",
    objectives: [
      "Triage initial alert",
      "Pivot across log sources",
      "Build attack timeline",
      "Document findings",
    ],
  },
  {
    name: "Tune Noisy Alerts",
    difficulty: "Intermediate",
    duration: "45 min",
    objectives: [
      "Analyze false positive patterns",
      "Create whitelist/exception rules",
      "Validate tuning doesn't miss true positives",
      "Document tuning rationale",
    ],
  },
  {
    name: "Build a Detection Dashboard",
    difficulty: "Intermediate",
    duration: "60 min",
    objectives: [
      "Identify key metrics to visualize",
      "Create panels for alert trends",
      "Add drill-down capabilities",
      "Set up scheduled reports",
    ],
  },
  {
    name: "MITRE ATT&CK Coverage Mapping",
    difficulty: "Advanced",
    duration: "90 min",
    objectives: [
      "Map existing rules to ATT&CK techniques",
      "Identify coverage gaps",
      "Prioritize new detection development",
      "Create coverage heatmap",
    ],
  },
];

// Architecture components
const architectureComponents = [
  {
    layer: "Data Collection",
    components: [
      { name: "Agents", description: "Splunk UF, Beats, Wazuh Agent, Sysmon" },
      { name: "Syslog", description: "rsyslog, syslog-ng for network devices" },
      { name: "APIs", description: "Cloud provider APIs, SaaS integrations" },
      { name: "Log Shippers", description: "Logstash, Fluentd, Vector" },
    ],
  },
  {
    layer: "Data Processing",
    components: [
      { name: "Parsing", description: "Field extraction, timestamp normalization" },
      { name: "Enrichment", description: "GeoIP, threat intel, asset context" },
      { name: "Filtering", description: "Drop noise, aggregate duplicates" },
      { name: "Routing", description: "Index selection, data tiering" },
    ],
  },
  {
    layer: "Storage",
    components: [
      { name: "Hot Storage", description: "Fast SSD for recent data (7-30 days)" },
      { name: "Warm Storage", description: "Balanced cost/performance (30-90 days)" },
      { name: "Cold Storage", description: "Archive for compliance (1-7 years)" },
      { name: "Index Management", description: "Retention policies, rollover" },
    ],
  },
  {
    layer: "Analysis",
    components: [
      { name: "Search", description: "Ad-hoc queries, investigation" },
      { name: "Correlation", description: "Multi-event pattern matching" },
      { name: "Alerting", description: "Real-time and scheduled rules" },
      { name: "ML/UEBA", description: "Anomaly detection, baselining" },
    ],
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#3b82f6";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "What does SIEM stand for?",
    options: [
      "Security Information and Event Management",
      "System Integrity and Endpoint Monitoring",
      "Secure Identity and Encryption Model",
      "Signal Intelligence and Evidence Management",
    ],
    correctAnswer: 0,
    explanation: "SIEM stands for Security Information and Event Management.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "The primary goal of a SIEM is to:",
    options: [
      "Replace antivirus tools",
      "Centralize, correlate, and alert on security events",
      "Manage software licenses",
      "Patch operating systems",
    ],
    correctAnswer: 1,
    explanation: "SIEMs aggregate logs, correlate events, and generate security alerts.",
  },
  {
    id: 3,
    topic: "Normalization",
    question: "Log normalization is the process of:",
    options: [
      "Compressing logs",
      "Deleting duplicates",
      "Parsing and mapping fields to a common schema",
      "Encrypting log storage",
    ],
    correctAnswer: 2,
    explanation: "Normalization maps different log formats to consistent field names.",
  },
  {
    id: 4,
    topic: "Correlation",
    question: "Event correlation is used to:",
    options: [
      "Link related events across sources to identify patterns",
      "Lower storage costs",
      "Disable noisy alerts",
      "Update agent versions",
    ],
    correctAnswer: 0,
    explanation: "Correlation connects events to reveal multi-stage activity.",
  },
  {
    id: 5,
    topic: "Alerting",
    question: "SIEM alerting triggers when:",
    options: [
      "Any log is ingested",
      "Detection rules match defined conditions",
      "Monthly reports are generated",
      "Agents reboot",
    ],
    correctAnswer: 1,
    explanation: "Alerts fire when rules match the configured logic.",
  },
  {
    id: 6,
    topic: "Retention",
    question: "Log retention is primarily used for:",
    options: [
      "Reducing CPU usage",
      "Disabling alerts",
      "Compliance and forensics",
      "Replacing backups",
    ],
    correctAnswer: 2,
    explanation: "Retention supports investigations and regulatory requirements.",
  },
  {
    id: 7,
    topic: "Log Sources",
    question: "Which is a common endpoint log source?",
    options: ["Windows Event Logs", "BGP tables", "CDN cache metrics", "Printer toner alerts"],
    correctAnswer: 0,
    explanation: "Windows Event Logs are a core endpoint telemetry source.",
  },
  {
    id: 8,
    topic: "Log Sources",
    question: "Which is a common network log source?",
    options: ["HR payroll exports", "Firewall logs", "Notebook battery logs", "Screen brightness"],
    correctAnswer: 1,
    explanation: "Firewalls provide network allow/deny and traffic data.",
  },
  {
    id: 9,
    topic: "Log Sources",
    question: "Which is a common identity log source?",
    options: ["Active Directory authentication logs", "CPU temperature", "Browser bookmarks", "UPS status"],
    correctAnswer: 0,
    explanation: "AD authentication logs are critical for identity monitoring.",
  },
  {
    id: 10,
    topic: "Log Sources",
    question: "Which is a common cloud log source?",
    options: ["Local syslog only", "Spreadsheet exports", "AWS CloudTrail", "Printer queues"],
    correctAnswer: 2,
    explanation: "CloudTrail records AWS API activity.",
  },
  {
    id: 11,
    topic: "Endpoint Telemetry",
    question: "Sysmon is used to collect:",
    options: [
      "Disk defragmentation reports",
      "Detailed process and network events on Windows",
      "BIOS updates only",
      "Email filtering results",
    ],
    correctAnswer: 1,
    explanation: "Sysmon provides rich process, file, and network events.",
  },
  {
    id: 12,
    topic: "Capacity",
    question: "EPS stands for:",
    options: ["Events per second", "Encrypted packet stream", "Endpoint policy status", "External proxy service"],
    correctAnswer: 0,
    explanation: "EPS measures log ingestion volume.",
  },
  {
    id: 13,
    topic: "Correlation",
    question: "Time synchronization is important because it:",
    options: [
      "Reduces storage",
      "Improves color themes",
      "Disables alerts",
      "Enables accurate correlation across sources",
    ],
    correctAnswer: 3,
    explanation: "Accurate timestamps are required to align events.",
  },
  {
    id: 14,
    topic: "Enrichment",
    question: "Enrichment adds:",
    options: [
      "Random noise",
      "Only compression",
      "Context like GeoIP, asset owner, criticality",
      "Firmware updates",
    ],
    correctAnswer: 2,
    explanation: "Enrichment adds context to improve triage decisions.",
  },
  {
    id: 15,
    topic: "Storage",
    question: "Hot storage is used for:",
    options: ["Archived long-term data", "Recent data with fast search", "Data disposal", "Backup only"],
    correctAnswer: 1,
    explanation: "Hot storage keeps recent data for quick searches.",
  },
  {
    id: 16,
    topic: "Storage",
    question: "Cold storage is typically used for:",
    options: ["Low-cost archival retention", "Real-time analytics", "Low latency alerts", "Only test data"],
    correctAnswer: 0,
    explanation: "Cold storage is cheaper and slower for long-term retention.",
  },
  {
    id: 17,
    topic: "Normalization",
    question: "A key benefit of normalization is:",
    options: ["More passwords", "Less visibility", "Fewer fields", "Consistent queries across diverse sources"],
    correctAnswer: 3,
    explanation: "Consistent fields enable reusable queries.",
  },
  {
    id: 18,
    topic: "Detection",
    question: "Brute force detection often looks for:",
    options: [
      "Single successful login",
      "Disk usage spikes",
      "High count of failed logins in a window",
      "Antivirus updates",
    ],
    correctAnswer: 2,
    explanation: "Multiple failed logins in a short time suggest brute force.",
  },
  {
    id: 19,
    topic: "Windows Logs",
    question: "Windows Event ID 4625 indicates:",
    options: ["Successful logon", "Failed Windows logon", "Service stopped", "USB insert"],
    correctAnswer: 1,
    explanation: "Event 4625 is a failed logon.",
  },
  {
    id: 20,
    topic: "Correlation",
    question: "A correlation window refers to the:",
    options: ["Time range to link related events", "Retention period", "Compression ratio", "Index name"],
    correctAnswer: 0,
    explanation: "Correlation windows define the time span for linking events.",
  },
  {
    id: 21,
    topic: "Tuning",
    question: "A false positive is an alert that:",
    options: ["Never triggers", "Confirms an attack", "Causes data loss", "Is triggered by benign activity"],
    correctAnswer: 3,
    explanation: "False positives are alerts without real malicious activity.",
  },
  {
    id: 22,
    topic: "Tuning",
    question: "Detection tuning aims to:",
    options: ["Disable all alerts", "Reduce noise while preserving detection", "Delete logs", "Increase false positives"],
    correctAnswer: 1,
    explanation: "Tuning reduces noise while keeping real signals.",
  },
  {
    id: 23,
    topic: "Platforms",
    question: "Which SIEM uses SPL for queries?",
    options: ["Splunk", "Sentinel", "QRadar", "Chronicle"],
    correctAnswer: 0,
    explanation: "Splunk uses the SPL query language.",
  },
  {
    id: 24,
    topic: "Platforms",
    question: "Which SIEM uses KQL?",
    options: ["Splunk", "Wazuh", "Microsoft Sentinel", "QRadar"],
    correctAnswer: 2,
    explanation: "Microsoft Sentinel uses KQL.",
  },
  {
    id: 25,
    topic: "Platforms",
    question: "Which SIEM uses AQL?",
    options: ["Elastic", "IBM QRadar", "Chronicle", "Wazuh"],
    correctAnswer: 1,
    explanation: "QRadar uses the AQL query language.",
  },
  {
    id: 26,
    topic: "Platforms",
    question: "Which platform uses YARA-L for detections?",
    options: ["SPL", "KQL", "AQL", "YARA-L"],
    correctAnswer: 3,
    explanation: "Google Chronicle uses YARA-L.",
  },
  {
    id: 27,
    topic: "Pipeline",
    question: "A common log shipper is:",
    options: ["Wireshark", "Notepad", "Logstash or Fluentd", "Docker Desktop"],
    correctAnswer: 2,
    explanation: "Logstash and Fluentd are used to ship and parse logs.",
  },
  {
    id: 28,
    topic: "Collection",
    question: "Syslog is commonly used for:",
    options: ["Network device logs", "Game telemetry", "Audio levels", "GPU drivers"],
    correctAnswer: 0,
    explanation: "Network devices often forward logs via syslog.",
  },
  {
    id: 29,
    topic: "Parsing",
    question: "Parsing errors can cause:",
    options: ["More accurate alerts", "Missing fields and weaker detections", "Faster responses", "More storage"],
    correctAnswer: 1,
    explanation: "Missing fields reduce detection quality.",
  },
  {
    id: 30,
    topic: "Storage",
    question: "Data tiering is used to:",
    options: ["Disable retention", "Store only in hot storage", "Balance cost and performance", "Encrypt backups only"],
    correctAnswer: 2,
    explanation: "Tiering reduces cost while keeping useful data accessible.",
  },
  {
    id: 31,
    topic: "Correlation",
    question: "Which is a correlation example?",
    options: [
      "Single DNS query",
      "One successful login",
      "Patch installation",
      "Suspicious PowerShell plus network beaconing",
    ],
    correctAnswer: 3,
    explanation: "Correlation links multiple signals into a higher-confidence alert.",
  },
  {
    id: 32,
    topic: "Analytics",
    question: "UEBA stands for:",
    options: [
      "User and Entity Behavior Analytics",
      "Unified Event Backup Archive",
      "User Email Blocking Agent",
      "Universal Endpoint Baseline Analyzer",
    ],
    correctAnswer: 0,
    explanation: "UEBA detects anomalous behavior by users and entities.",
  },
  {
    id: 33,
    topic: "Analytics",
    question: "UEBA is useful for detecting:",
    options: ["Hardware failures", "Anomalous user behavior", "Software licensing", "Patch updates only"],
    correctAnswer: 1,
    explanation: "UEBA highlights behavioral anomalies.",
  },
  {
    id: 34,
    topic: "Detection",
    question: "A well-documented detection rule should include:",
    options: ["No context", "Only a name", "Documented false positives", "Only a screenshot"],
    correctAnswer: 2,
    explanation: "False positive expectations help analysts tune alerts.",
  },
  {
    id: 35,
    topic: "Coverage",
    question: "Mapping detections to MITRE ATT&CK helps:",
    options: ["Reduce storage", "Disable alerts", "Hide risks", "Track coverage gaps"],
    correctAnswer: 3,
    explanation: "ATT&CK mapping shows what techniques are covered or missing.",
  },
  {
    id: 36,
    topic: "Detection",
    question: "DNS tunneling detection often looks for:",
    options: [
      "Short normal domains",
      "Long subdomains and high query volume",
      "No DNS traffic",
      "Only ICMP",
    ],
    correctAnswer: 1,
    explanation: "DNS tunneling often uses long, frequent subdomains.",
  },
  {
    id: 37,
    topic: "Detection",
    question: "Kerberoasting indicators include:",
    options: ["Single password reset", "USB insert", "Many 4769 requests with RC4", "Printer errors"],
    correctAnswer: 2,
    explanation: "Event 4769 with RC4 and many service ticket requests is suspicious.",
  },
  {
    id: 38,
    topic: "Detection",
    question: "Credential dumping detection often targets:",
    options: ["LSASS access or procdump indicators", "New wallpaper", "Screen lock", "CPU temperature"],
    correctAnswer: 0,
    explanation: "LSASS access can indicate credential dumping attempts.",
  },
  {
    id: 39,
    topic: "Correlation",
    question: "Correlation across sources requires:",
    options: ["Randomized fields", "Consistent timestamps and fields", "No parsing", "No NTP"],
    correctAnswer: 1,
    explanation: "Consistent timestamps and fields make cross-source correlation possible.",
  },
  {
    id: 40,
    topic: "Retention",
    question: "Retention periods should be based on:",
    options: ["Random choice", "UI theme", "Vendor defaults only", "Compliance and investigation needs"],
    correctAnswer: 3,
    explanation: "Retention is set by regulatory and operational requirements.",
  },
  {
    id: 41,
    topic: "Metrics",
    question: "A common SIEM KPI is:",
    options: ["Screen resolution", "Keyboard layout", "Alerts by severity over time", "Printer queue length"],
    correctAnswer: 2,
    explanation: "Alerts by severity show detection trends and workload.",
  },
  {
    id: 42,
    topic: "Metrics",
    question: "MTTD stands for:",
    options: ["Mean Time to Detect", "Monthly Trend Tracking Dashboard", "Message Trace Data", "Managed Threat Tuning Data"],
    correctAnswer: 0,
    explanation: "MTTD measures detection speed.",
  },
  {
    id: 43,
    topic: "Metrics",
    question: "MTTR stands for:",
    options: ["Mean Time to Restore", "Mean Time to Respond", "Monthly Triage Rate", "Mitigation Task Ratio"],
    correctAnswer: 1,
    explanation: "MTTR measures response speed.",
  },
  {
    id: 44,
    topic: "Operations",
    question: "Alert fatigue is usually caused by:",
    options: [
      "Too many high-quality alerts",
      "No alerts",
      "Too many low-quality alerts",
      "Perfect detections",
    ],
    correctAnswer: 2,
    explanation: "Excess low-quality alerts exhaust analysts.",
  },
  {
    id: 45,
    topic: "Architecture",
    question: "Indexing strategy should consider:",
    options: ["Monitor size only", "Random naming", "Only storage cost", "Data volume and query patterns"],
    correctAnswer: 3,
    explanation: "Index design impacts search performance and cost.",
  },
  {
    id: 46,
    topic: "Integrity",
    question: "Log integrity controls help:",
    options: ["Ensure evidence is trustworthy", "Hide incidents", "Reduce correlation", "Disable retention"],
    correctAnswer: 0,
    explanation: "Integrity measures protect evidence and audit trails.",
  },
  {
    id: 47,
    topic: "Access",
    question: "Role-based access control helps:",
    options: ["Expose all logs to everyone", "Limit sensitive log access", "Increase false positives", "Disable monitoring"],
    correctAnswer: 1,
    explanation: "RBAC limits access to sensitive data.",
  },
  {
    id: 48,
    topic: "Capacity",
    question: "EPS capacity planning is about:",
    options: ["Password policy", "Malware removal", "Sizing ingestion and storage", "DNS caching"],
    correctAnswer: 2,
    explanation: "EPS determines ingestion and storage requirements.",
  },
  {
    id: 49,
    topic: "Parsing",
    question: "Field extraction enables:",
    options: ["Only raw viewing", "Compression", "Archiving", "Structured queries and filtering"],
    correctAnswer: 3,
    explanation: "Extracted fields allow structured search and filtering.",
  },
  {
    id: 50,
    topic: "Reliability",
    question: "Log drop risk leads to:",
    options: ["Blind spots in detection", "Faster searches", "Better coverage", "Lower MTTD"],
    correctAnswer: 0,
    explanation: "Dropped logs create visibility gaps.",
  },
  {
    id: 51,
    topic: "Baselines",
    question: "A baseline in SIEM refers to:",
    options: ["Security patch list", "Normal behavior profile", "Firewall allow list", "Disk cleanup job"],
    correctAnswer: 1,
    explanation: "Baselines describe expected activity.",
  },
  {
    id: 52,
    topic: "Detection",
    question: "Correlation rules are especially useful to:",
    options: ["Only count logs", "Disable alarms", "Detect multi-step attacks", "Reduce storage"],
    correctAnswer: 2,
    explanation: "Correlation rules capture multi-stage behavior.",
  },
  {
    id: 53,
    topic: "Enrichment",
    question: "Which is an enrichment example?",
    options: ["GeoIP lookup on source IP", "Delete IPs", "Remove timestamps", "Compress with zip"],
    correctAnswer: 0,
    explanation: "GeoIP adds geographic context to alerts.",
  },
  {
    id: 54,
    topic: "Collection",
    question: "A log forwarding agent example is:",
    options: ["Splunk Universal Forwarder", "Browser plugin", "Registry editor", "Screen recorder"],
    correctAnswer: 0,
    explanation: "Forwarders ship logs from endpoints to the SIEM.",
  },
  {
    id: 55,
    topic: "Storage",
    question: "Archive tiers are usually:",
    options: ["Faster and hotter", "No different from hot", "Only for backups", "Colder, slower, cheaper"],
    correctAnswer: 3,
    explanation: "Archive tiers trade speed for lower cost.",
  },
  {
    id: 56,
    topic: "Use Cases",
    question: "A SIEM use case example is:",
    options: ["Change wallpapers", "Rotate keys daily", "Detect abnormal outbound data volume", "Update OS fonts"],
    correctAnswer: 2,
    explanation: "Abnormal outbound volume can indicate exfiltration.",
  },
  {
    id: 57,
    topic: "Normalization",
    question: "Normalization steps often include:",
    options: ["Timestamp normalization", "User training", "Procurement approvals", "Cable management"],
    correctAnswer: 0,
    explanation: "Consistent timestamps are part of normalization.",
  },
  {
    id: 58,
    topic: "Alerting",
    question: "Alert enrichment should add:",
    options: ["Only emojis", "Asset criticality and owner", "Less context", "Hidden fields"],
    correctAnswer: 1,
    explanation: "Context like asset criticality speeds triage.",
  },
  {
    id: 59,
    topic: "Operations",
    question: "A playbook provides:",
    options: ["SIEM license files", "Firewall configs", "Guided response steps for alerts", "Password vaults"],
    correctAnswer: 2,
    explanation: "Playbooks document response steps for recurring alerts.",
  },
  {
    id: 60,
    topic: "Collection",
    question: "Log source onboarding should include:",
    options: ["Only install the agent", "Only add a dashboard", "Only add an index", "Validation that events are ingested and parsed"],
    correctAnswer: 3,
    explanation: "You must validate ingestion and parsing for new sources.",
  },
  {
    id: 61,
    topic: "Log Sources",
    question: "MFA logs are typically part of:",
    options: ["Identity logs", "Network logs", "Application logs", "Hardware logs"],
    correctAnswer: 0,
    explanation: "MFA events belong to identity telemetry.",
  },
  {
    id: 62,
    topic: "Log Sources",
    question: "Proxy logs are useful for:",
    options: ["CPU temperature", "Web traffic and URL analysis", "Printer errors", "Battery stats"],
    correctAnswer: 1,
    explanation: "Proxy logs show web destinations and user agents.",
  },
  {
    id: 63,
    topic: "Windows Logs",
    question: "Windows Event ID 4672 indicates:",
    options: ["Account locked", "Password changed", "Special privileges assigned", "USB inserted"],
    correctAnswer: 2,
    explanation: "Event 4672 signals special privileges assigned.",
  },
  {
    id: 64,
    topic: "Collection",
    question: "SaaS logs are often collected via:",
    options: ["Only syslog", "Only agents", "Local registry", "APIs or connectors"],
    correctAnswer: 3,
    explanation: "Cloud and SaaS logs are commonly pulled via APIs.",
  },
  {
    id: 65,
    topic: "Metrics",
    question: "A SOC dashboard KPI example is:",
    options: ["MTTD and MTTR trends", "Monitor brightness", "Mouse DPI", "Laptop temperature"],
    correctAnswer: 0,
    explanation: "MTTD and MTTR trends show detection and response performance.",
  },
  {
    id: 66,
    topic: "Tuning",
    question: "Reducing correlation rule false positives often involves:",
    options: ["Removing filters", "Adding context and thresholds", "Ignoring logs", "Disabling correlation"],
    correctAnswer: 1,
    explanation: "Thresholds and context reduce noisy correlations.",
  },
  {
    id: 67,
    topic: "Collection",
    question: "Log source priority should favor:",
    options: ["Random systems", "Only dev machines", "Critical systems and security controls", "Only printers"],
    correctAnswer: 2,
    explanation: "High-value systems provide the most security value.",
  },
  {
    id: 68,
    topic: "Retention",
    question: "Compliance retention requirements often mean:",
    options: ["Shorter storage periods", "No logs", "No access controls", "Longer storage periods"],
    correctAnswer: 3,
    explanation: "Regulations commonly require longer log retention.",
  },
  {
    id: 69,
    topic: "Pipeline",
    question: "Data pipeline filtering is used to:",
    options: ["Drop noisy events before indexing", "Encrypt nothing", "Disable parsing", "Duplicate events"],
    correctAnswer: 0,
    explanation: "Filtering reduces noise and storage costs.",
  },
  {
    id: 70,
    topic: "Correlation",
    question: "Cross-cloud correlation requires:",
    options: ["Only on-prem data", "Consistent schema and identity mapping", "No timestamps", "Different time zones"],
    correctAnswer: 1,
    explanation: "Consistent schemas and identities enable cross-environment correlation.",
  },
  {
    id: 71,
    topic: "Coverage",
    question: "Detection coverage gaps are identified by:",
    options: ["Random guessing", "Adding noise", "ATT&CK mapping and rule review", "Removing logs"],
    correctAnswer: 2,
    explanation: "Mapping rules to ATT&CK highlights missing coverage.",
  },
  {
    id: 72,
    topic: "Detection",
    question: "Suspicious PowerShell detections often look for:",
    options: ["Only version number", "Signed binaries only", "Uptime", "Encoded commands and download strings"],
    correctAnswer: 3,
    explanation: "Encoded commands and download strings are common abuse patterns.",
  },
  {
    id: 73,
    topic: "Alerting",
    question: "A good SIEM alert should include:",
    options: ["Who, what, when, where, why", "Only a title", "Only severity", "Only ticket number"],
    correctAnswer: 0,
    explanation: "Complete context helps analysts triage quickly.",
  },
  {
    id: 74,
    topic: "Detection",
    question: "Cloud storage exfiltration detection often uses:",
    options: ["System reboots", "Large uploads to personal storage", "Normal backups", "Printer activity"],
    correctAnswer: 1,
    explanation: "Unusual large uploads to personal storage can signal exfiltration.",
  },
  {
    id: 75,
    topic: "Storage",
    question: "Which is a reasonable retention tiering example?",
    options: [
      "All hot forever",
      "No storage",
      "7 days hot, 90 days warm, 1 year cold",
      "Delete after 1 hour",
    ],
    correctAnswer: 2,
    explanation: "Tiering keeps recent data hot and older data in cheaper tiers.",
  },
];

export default function SIEMFundamentalsPage() {
  const theme = useTheme();
  const [activeSection, setActiveSection] = useState("intro");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const isMobile = useMediaQuery("(max-width:900px)");

  const scrollToSection = (sectionId: string) => {
    setActiveSection(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      const yOffset = -80;
      const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: "smooth" });
    }
    setMobileNavOpen(false);
  };

  useEffect(() => {
    const handleScroll = () => {
      const sectionIds = sectionNavItems.map((item) => item.id);
      for (const id of sectionIds) {
        const element = document.getElementById(id);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 120 && rect.bottom >= 120) {
            setActiveSection(id);
            break;
          }
        }
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const sidebarNav = (
    <Box sx={{ position: "sticky", top: 90 }}>
      <Paper sx={{ p: 2, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
        <Typography variant="subtitle2" sx={{ color: themeColors.primary, fontWeight: 700, mb: 2, px: 1 }}>
          CONTENTS
        </Typography>
        <List dense disablePadding>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              component="button"
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1,
                mb: 0.5,
                cursor: "pointer",
                border: "none",
                width: "100%",
                textAlign: "left",
                bgcolor: activeSection === item.id ? `${themeColors.primary}20` : "transparent",
                "&:hover": { bgcolor: `${themeColors.primary}15` },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? themeColors.primary : themeColors.textMuted }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  fontWeight: activeSection === item.id ? 600 : 400,
                  color: activeSection === item.id ? themeColors.primary : themeColors.textMuted,
                }}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

  const pageContext = `SIEM Fundamentals Guide - Comprehensive Security Information and Event Management training. Covers core concepts (log collection, normalization, correlation, alerting, dashboards, retention), log source categories (endpoints with Windows Events/Sysmon/EDR, network with firewall/DNS/proxy, identity with AD/Azure AD/VPN, cloud with AWS CloudTrail/Azure/GCP, applications). Includes platform comparison (Splunk SPL, Elastic KQL, Microsoft Sentinel KQL, QRadar AQL, Wazuh, Chronicle YARA-L). Features detection rule examples mapped to MITRE ATT&CK (brute force T1110, PowerShell T1059.001, lateral movement T1021, DNS tunneling T1071.004, Kerberoasting T1558.003, credential dumping T1003). Covers SIEM architecture (collection, processing, storage tiers, analysis layer), SOC metrics (MTTD, MTTR, true positive rate, coverage), and hands-on labs from beginner to advanced.`;

  return (
    <LearnPageLayout pageTitle="SIEM Fundamentals" pageContext={pageContext}>
      <Container maxWidth="xl" sx={{ py: 4 }}>
        <Grid container spacing={3}>
          {/* Left Sidebar Navigation */}
          {!isMobile && (
            <Grid item md={2.5}>
              {sidebarNav}
            </Grid>
          )}

          {/* Main Content */}
          <Grid item xs={12} md={9.5}>
            {/* Introduction Section */}
            <Paper id="intro" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Chip
                component={Link}
                to="/learn"
                icon={<ArrowBackIcon />}
                label="Back to Learning Hub"
                clickable
                variant="outlined"
                sx={{ borderRadius: 2, mb: 2, borderColor: themeColors.border, color: themeColors.textMuted }}
              />
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 64,
                    height: 64,
                    borderRadius: 2,
                    bgcolor: alpha(themeColors.primary, 0.1),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <StorageIcon sx={{ fontSize: 36, color: themeColors.primary }} />
                </Box>
                <Box>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "#fff" }}>
                    SIEM Fundamentals
                  </Typography>
                  <Typography variant="body1" sx={{ color: themeColors.textMuted }}>
                    Security Information and Event Management
                  </Typography>
                </Box>
              </Box>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Blue Team" size="small" sx={{ bgcolor: alpha(themeColors.primary, 0.2), color: themeColors.primary }} />
                <Chip label="Detection" size="small" sx={{ bgcolor: alpha(themeColors.accent, 0.1), color: themeColors.accent }} />
                <Chip label="Monitoring" size="small" sx={{ bgcolor: alpha(themeColors.secondary, 0.1), color: themeColors.secondary }} />
                <Chip label="MITRE ATT&CK" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
              </Box>

              {/* Stats */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {[
                  { label: "Log Sources", value: "20+", color: themeColors.primary },
                  { label: "Detection Rules", value: "8", color: "#ef4444" },
                  { label: "Query Examples", value: "10+", color: "#f59e0b" },
                  { label: "Lab Exercises", value: "6", color: themeColors.accent },
                ].map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: themeColors.bgNested, borderTop: `3px solid ${stat.color}` }}>
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                      <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{stat.label}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* What You'll Learn */}
              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <SchoolIcon /> What You'll Learn
                </Typography>
                <Grid container spacing={1}>
                  {[
                    "SIEM core concepts and architecture",
                    "Critical log sources for security monitoring",
                    "Query languages (SPL, KQL, Lucene)",
                    "Detection rule development with MITRE mapping",
                    "SOC metrics and KPIs",
                    "Hands-on lab exercises",
                  ].map((item) => (
                    <Grid item xs={12} sm={6} key={item}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: themeColors.accent }} />
                        <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{item}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Paper>

            {/* Overview Section */}
            <Paper id="overview" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DashboardIcon /> Overview
              </Typography>

              {/* What is a SIEM */}
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#fff" }}>
                  <StorageIcon sx={{ color: themeColors.primary }} /> What is a SIEM?
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  A SIEM (Security Information and Event Management) system collects, normalizes, and analyzes log data 
                  from across your environment to detect threats, support investigations, and meet compliance requirements. 
                  It's the central nervous system of a Security Operations Center (SOC).
                </Typography>
                <Alert severity="info" sx={{ bgcolor: alpha(themeColors.primary, 0.1), border: `1px solid ${alpha(themeColors.primary, 0.3)}` }}>
                  Modern SIEMs often include SOAR (Security Orchestration, Automation and Response) capabilities 
                  and UEBA (User and Entity Behavior Analytics) for advanced threat detection.
                </Alert>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  🧭 The SIEM Data Journey (End-to-End)
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  Think of a SIEM as a factory line for security signals. Raw events enter from dozens of sources, get cleaned up,
                  enriched, and then turned into actionable alerts. Beginners often get stuck because they only see the alert,
                  not the path it took to get there. Understanding this journey helps you troubleshoot missing detections,
                  reduce noise, and explain results to stakeholders.
                </Typography>
                <List dense>
                  {[
                    "Collection: agents, syslog, or APIs gather events and deliver them to the SIEM.",
                    "Parsing: the SIEM extracts fields like user, host, IP, process, and action.",
                    "Normalization: fields are mapped to a consistent schema so queries work across sources.",
                    "Enrichment: add context (asset criticality, geo-IP, threat intel, user role).",
                    "Correlation: multiple events are linked to reveal a pattern or tactic.",
                    "Alerting: rules create notifications when thresholds or behaviors match.",
                    "Response: analysts triage, investigate, contain, and document the incident.",
                    "Retention: logs are stored for compliance, audits, and historical investigations.",
                  ].map((step) => (
                    <ListItem key={step} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <TimelineIcon sx={{ fontSize: 16, color: themeColors.accent }} />
                      </ListItemIcon>
                      <ListItemText primary={step} primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }} />
                    </ListItem>
                  ))}
                </List>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mt: 1 }}>
                  If any stage is weak (for example, missing DNS logs or poor parsing), the whole detection chain suffers.
                  This is why SIEM engineers spend as much time on data quality as they do on detection logic.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  📘 Beginner Glossary (Plain-Language)
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { term: "Event", desc: "A single record like a logon, file write, or firewall decision." },
                    { term: "Alert", desc: "A rule-based notification that something looks suspicious." },
                    { term: "Incident", desc: "A confirmed security issue that needs containment and remediation." },
                    { term: "False Positive", desc: "An alert that looks bad but turns out to be normal behavior." },
                    { term: "Baseline", desc: "A model of what 'normal' looks like for a user or system." },
                    { term: "EPS", desc: "Events per second, a rough measure of log volume and SIEM load." },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} key={item.term}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgCard, borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#fff", mb: 0.5 }}>
                          {item.term}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          {item.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Core Concepts */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>🎯 Core Concepts</Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {coreConcepts.map((concept) => (
                  <Grid item xs={12} sm={6} md={4} key={concept.title}>
                    <Paper
                      sx={{
                        p: 2,
                        height: "100%",
                        bgcolor: themeColors.bgNested,
                        borderRadius: 2,
                        border: `1px solid ${alpha(concept.color, 0.2)}`,
                        "&:hover": { borderColor: concept.color },
                      }}
                    >
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: concept.color, mb: 0.5 }}>
                        {concept.title}
                      </Typography>
                      <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                        {concept.description}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* Platforms */}
              <Paper
                sx={{
                  p: 2.5,
                  mb: 3,
                  bgcolor: themeColors.bgNested,
                  borderRadius: 2,
                  border: `1px solid ${alpha(themeColors.primary, 0.2)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#fff" }}>
                  <BuildIcon sx={{ color: themeColors.primary }} /> Popular SIEM Platforms
                </Typography>
                <Grid container spacing={2}>
                  {platforms.map((p) => (
                    <Grid item xs={12} sm={6} md={4} key={p.name}>
                      <Paper sx={{ p: 2, borderRadius: 2, bgcolor: themeColors.bgCard }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#fff" }}>{p.name}</Typography>
                          <Chip label={p.type} size="small" sx={{ height: 18, fontSize: "0.65rem" }} />
                        </Box>
                        <Typography variant="caption" sx={{ display: "block", color: themeColors.textMuted }}>{p.note}</Typography>
                        <Chip label={p.queryLang} size="small" sx={{ mt: 1, bgcolor: alpha(themeColors.primary, 0.1), color: themeColors.primary }} />
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Use Cases */}
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#fff" }}>
                  <NotificationsActiveIcon sx={{ color: themeColors.accent }} /> Common Detection Use Cases
                </Typography>
                <Grid container spacing={1}>
                  {useCases.map((uc, i) => (
                    <Grid item xs={12} sm={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: themeColors.accent }} />
                        <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{uc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2, border: `1px solid ${alpha(themeColors.accent, 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  🧠 Lesson: Signal vs. Noise for Beginners
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  A common beginner mistake is to collect everything and alert on anything unusual. Real environments are noisy:
                  software updates, admin scripts, and automated jobs can trigger hundreds of "suspicious" events every day.
                  The goal of a SIEM is not to alert on everything, but to prioritize the most meaningful signals.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                  Start with behaviors that are rare and high-impact (for example, new admin creation or credential dumping),
                  then build coverage outward. When you tune a rule, document the decision so future analysts understand why
                  a specific host, process, or service account is excluded.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  🧭 Walkthrough: From Alert to Confirmed Incident
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  This is a realistic, beginner-friendly flow of how a SOC analyst handles a single alert. The goal is to
                  show you how to move from "something happened" to a documented incident with evidence and actions.
                </Typography>
                <Grid container spacing={2}>
                  {[
                    {
                      title: "1) Alert Triggered",
                      desc: "The SIEM fires a brute-force alert: 25 failed logins from 203.0.113.77 against user j.smith in 5 minutes.",
                    },
                    {
                      title: "2) Quick Triage",
                      desc: "Check severity, asset value, and time. The target is a finance workstation, so this gets priority.",
                    },
                    {
                      title: "3) Verify the Signal",
                      desc: "Confirm the event pattern: same source IP, consistent username, and authentication failures (4625).",
                    },
                    {
                      title: "4) Pivot for Context",
                      desc: "Search for successful logins (4624) from the same IP or user. Look for VPN access, MFA failures, or password resets.",
                    },
                    {
                      title: "5) Build a Timeline",
                      desc: "Create a timeline of login attempts, host activity, and any process launches after the attempts.",
                    },
                    {
                      title: "6) Decide: True or False",
                      desc: "If there is a successful login followed by unusual activity, treat it as a real incident.",
                    },
                    {
                      title: "7) Contain & Document",
                      desc: "Block the source IP, reset the account, and document evidence and actions in the case record.",
                    },
                  ].map((step) => (
                    <Grid item xs={12} md={6} key={step.title}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgCard, borderRadius: 2, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#fff", mb: 0.5 }}>
                          {step.title}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          {step.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mt: 2 }}>
                  The key lesson: a single alert is not an incident by itself. It becomes an incident only after you confirm
                  impact and gather evidence. Your goal is to connect the alert to real risk.
                </Typography>
              </Paper>

              {/* Tip */}
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  bgcolor: alpha("#f59e0b", 0.05),
                  border: `1px solid ${alpha("#f59e0b", 0.2)}`,
                  display: "flex",
                  alignItems: "center",
                  gap: 2,
                }}
              >
                <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
                <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                  <strong style={{ color: "#fff" }}>Tip:</strong> Start with high-fidelity, low-volume alerts and tune from there. Alert fatigue kills SOCs.
                </Typography>
              </Paper>
            </Paper>

            {/* Log Sources Section */}
            <Paper id="log-sources" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DnsIcon /> Log Sources
              </Typography>

              <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(themeColors.primary, 0.1), border: `1px solid ${alpha(themeColors.primary, 0.3)}` }}>
                Comprehensive log coverage is essential for effective threat detection. Prioritize critical sources first, then expand coverage based on risk.
              </Alert>

              {logSources.map((category) => (
                <Paper key={category.category} sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#fff" }}>
                    <span>{category.icon}</span> {category.category}
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700, color: themeColors.textMuted, borderColor: themeColors.border }}>Source</TableCell>
                          <TableCell sx={{ fontWeight: 700, color: themeColors.textMuted, borderColor: themeColors.border }}>Description</TableCell>
                          <TableCell sx={{ fontWeight: 700, color: themeColors.textMuted, borderColor: themeColors.border }}>Priority</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {category.sources.map((source) => (
                          <TableRow key={source.name}>
                            <TableCell sx={{ fontWeight: 600, color: "#fff", borderColor: themeColors.border }}>{source.name}</TableCell>
                            <TableCell sx={{ color: themeColors.textMuted, borderColor: themeColors.border }}>{source.description}</TableCell>
                            <TableCell sx={{ borderColor: themeColors.border }}>
                              <Chip
                                label={source.priority}
                                size="small"
                                sx={{
                                  bgcolor: source.priority === "Critical" ? alpha("#ef4444", 0.1) :
                                           source.priority === "High" ? alpha("#f59e0b", 0.1) :
                                           alpha(themeColors.primary, 0.1),
                                  color: source.priority === "Critical" ? "#ef4444" :
                                         source.priority === "High" ? "#f59e0b" : themeColors.primary,
                                }}
                              />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              ))}

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  ✅ Lesson: Log Quality Matters
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  A SIEM is only as good as the data it receives. If timestamps are missing, user fields are inconsistent,
                  or logs are delayed by hours, your detections will be unreliable. Before building complex rules, validate
                  that logs arrive on time, fields are populated, and critical events are not being filtered out.
                </Typography>
                <List dense>
                  {[
                    "Check time sync: if hosts are off by minutes, correlation breaks.",
                    "Verify field completeness: user, host, IP, process, and outcome should be present.",
                    "Measure latency: know the typical delay from event generation to SIEM ingestion.",
                    "Validate volume baselines: sudden drops can mean broken agents or blocked sources.",
                    "Confirm parsing: raw logs should map cleanly to your schema fields.",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: themeColors.accent }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }} />
                    </ListItem>
                  ))}
                </List>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                  Treat log validation as a repeatable checklist. When a detection fails, data quality is the first thing to check.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  📋 Log Source Checklist
                </Typography>
                <List dense>
                  {[
                    "Windows Security Events (4624, 4625, 4648, 4672, 4688, 4698, 4720, 4728)",
                    "Sysmon with SwiftOnSecurity or Olaf Hartong config",
                    "PowerShell Script Block Logging (Event ID 4104)",
                    "DNS query logging from DNS servers or network taps",
                    "Firewall allow/deny logs with source/dest IPs",
                    "Proxy logs with full URLs and user-agent strings",
                    "Authentication logs from all identity providers",
                    "Cloud audit logs (CloudTrail, Azure Activity, GCP Audit)",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: themeColors.secondary }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Query Examples Section */}
            <Paper id="query-examples" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon /> Query Examples
              </Typography>

              <Alert severity="warning" sx={{ mb: 3, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
                Query syntax varies by platform. These examples are templates - adjust field names for your environment.
              </Alert>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  🧩 How to Read a SIEM Query
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  A query is a set of filters and transformations that turn raw logs into evidence. Start by identifying
                  the data source (index/table), then add filters for event types, and finally group or summarize results
                  to highlight patterns. Most SIEM queries follow this sequence even if the syntax looks different.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                  When you copy an example query, always verify the field names. For example, a source IP might be
                  `src_ip`, `source.ip`, or `IpAddress` depending on your platform and schema.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  🧪 Mini Labs: Query Practice With Expected Results
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  These short labs help you practice reading and tuning queries. Each lab lists a goal, the query to run,
                  and what you should expect to see in the results.
                </Typography>
                <Grid container spacing={2}>
                  {[
                    {
                      title: "Lab 1: Brute Force Pattern",
                      goal: "Find users targeted by repeated failed logins in the last hour.",
                      query: queryExamples.sentinel.bruteForce,
                      expected: "A table of TargetAccount and IpAddress with FailedAttempts above the threshold.",
                    },
                    {
                      title: "Lab 2: Suspicious Process Launch",
                      goal: "Identify command-line tools launched by PowerShell or cmd.",
                      query: queryExamples.sentinel.suspiciousProcess,
                      expected: "Rows showing DeviceName, AccountName, and command lines for utilities like whoami or net.",
                    },
                    {
                      title: "Lab 3: DNS Exfiltration Signal",
                      goal: "Detect long subdomains that could encode data.",
                      query: queryExamples.sentinel.dnsExfil,
                      expected: "Domains with unusually long subdomains and a high query count from a single client.",
                    },
                    {
                      title: "Lab 4: Splunk Lateral Movement",
                      goal: "Spot a host making multiple network logons in a short period.",
                      query: queryExamples.splunk.lateralMovement,
                      expected: "Hosts with a burst of LogonType=3 or explicit credential usage.",
                    },
                  ].map((lab) => (
                    <Grid item xs={12} md={6} key={lab.title}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgCard, borderRadius: 2, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#fff", mb: 1 }}>
                          {lab.title}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted, display: "block", mb: 1 }}>
                          Goal: {lab.goal}
                        </Typography>
                        <CodeBlock code={lab.query} language="kql" title="Run This Query" />
                        <Typography variant="caption" sx={{ color: themeColors.textMuted, display: "block" }}>
                          Expected: {lab.expected}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mt: 2 }}>
                  If your results are empty, validate data ingestion and field names first. Then reduce the thresholds to
                  confirm you can see low-volume activity before tuning upward.
                </Typography>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                Splunk (SPL)
              </Typography>
              <Accordion defaultExpanded sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Brute Force Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.bruteForce} language="spl" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Privilege Escalation Events</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.privilegeEsc} language="spl" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Suspicious Process Execution</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.suspiciousProcess} language="spl" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 3, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Lateral Movement Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.lateralMovement} language="spl" />
                </AccordionDetails>
              </Accordion>

              <Divider sx={{ my: 3, borderColor: themeColors.border }} />

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                Microsoft Sentinel (KQL)
              </Typography>
              <Accordion sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Brute Force Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.bruteForce} language="kql" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Privilege Escalation Events</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.privilegeEsc} language="kql" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Suspicious Process Execution</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.suspiciousProcess} language="kql" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 3, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>DNS Exfiltration Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.dnsExfil} language="kql" />
                </AccordionDetails>
              </Accordion>

              <Divider sx={{ my: 3, borderColor: themeColors.border }} />

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.accent }}>
                Elastic (Lucene/JSON DSL)
              </Typography>
              <Accordion sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Brute Force Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.elastic.bruteForce} language="json" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#fff" }}>Malware Indicators</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.elastic.malwareIndicator} language="json" />
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Detection Rules Section */}
            <Paper id="detection-rules" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon /> Detection Rules
              </Typography>

              <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(themeColors.primary, 0.1), border: `1px solid ${alpha(themeColors.primary, 0.3)}` }}>
                Detection rules should be mapped to MITRE ATT&CK techniques for coverage analysis. 
                Always document false positive scenarios for tuning.
              </Alert>

              {detectionRules.map((rule, idx) => (
                <Accordion key={idx} sx={{ mb: 1, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                      <Chip
                        label={rule.severity}
                        size="small"
                        sx={{
                          bgcolor: rule.severity === "Critical" ? alpha("#ef4444", 0.1) :
                                   rule.severity === "High" ? alpha("#f59e0b", 0.1) :
                                   alpha(themeColors.primary, 0.1),
                          color: rule.severity === "Critical" ? "#ef4444" :
                                 rule.severity === "High" ? "#f59e0b" : themeColors.primary,
                          fontWeight: 700,
                        }}
                      />
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, flex: 1, color: "#fff" }}>{rule.name}</Typography>
                      <Chip label={rule.mitre} size="small" variant="outlined" sx={{ mr: 2, borderColor: themeColors.border, color: themeColors.textMuted }} />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                          {rule.description}
                        </Typography>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha(themeColors.primary, 0.05), borderRadius: 2 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: themeColors.primary, mb: 1 }}>
                            Detection Logic
                          </Typography>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{rule.logic}</Typography>
                        </Paper>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>
                            Threshold
                          </Typography>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{rule.threshold}</Typography>
                        </Paper>
                      </Grid>
                      <Grid item xs={12}>
                        <Paper sx={{ p: 2, bgcolor: alpha(themeColors.secondary, 0.05), borderRadius: 2 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: themeColors.secondary, mb: 1 }}>
                            False Positives
                          </Typography>
                          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                            {rule.falsePositives.map((fp) => (
                              <Chip key={fp} label={fp} size="small" variant="outlined" sx={{ borderColor: themeColors.border, color: themeColors.textMuted }} />
                            ))}
                          </Box>
                        </Paper>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              ))}

              <Paper sx={{ p: 2.5, mt: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  📝 Detection Rule Best Practices
                </Typography>
                <List dense>
                  {[
                    "Start with high-confidence, low-volume alerts to avoid fatigue",
                    "Include context in alerts (who, what, when, where, why)",
                    "Map all rules to MITRE ATT&CK for coverage tracking",
                    "Document expected false positives and tuning rationale",
                    "Use correlation rules for multi-stage attack detection",
                    "Set appropriate severity based on business impact",
                    "Include runbook links in alert descriptions",
                    "Test rules with known-good attack simulations",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: themeColors.accent }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Architecture Section */}
            <Paper id="architecture" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <AccountTreeIcon /> Architecture
              </Typography>

              <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(themeColors.primary, 0.1), border: `1px solid ${alpha(themeColors.primary, 0.3)}` }}>
                A well-designed SIEM architecture balances performance, cost, and data retention requirements.
              </Alert>

              {architectureComponents.map((layer, idx) => (
                <Paper key={layer.layer} sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2, borderLeft: `4px solid ${
                  idx === 0 ? themeColors.primary : idx === 1 ? themeColors.secondary : idx === 2 ? "#f59e0b" : themeColors.accent
                }` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                    {idx + 1}. {layer.layer}
                  </Typography>
                  <Grid container spacing={2}>
                    {layer.components.map((comp) => (
                      <Grid item xs={12} sm={6} key={comp.name}>
                        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                          <CheckCircleIcon sx={{ fontSize: 18, color: themeColors.primary, mt: 0.3 }} />
                          <Box>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#fff" }}>{comp.name}</Typography>
                            <Typography variant="caption" sx={{ color: themeColors.textMuted }}>{comp.description}</Typography>
                          </Box>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>
              ))}

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  🔧 Architecture Considerations
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { title: "Scalability", desc: "Plan for 2-3x current log volume growth", icon: "📈" },
                    { title: "High Availability", desc: "Clustered indexers, redundant collectors", icon: "🔄" },
                    { title: "Data Tiering", desc: "Hot → Warm → Cold based on access patterns", icon: "❄️" },
                    { title: "Network Placement", desc: "Collectors near log sources, central indexers", icon: "🌐" },
                    { title: "Encryption", desc: "TLS for transit, encryption at rest", icon: "🔐" },
                    { title: "Backup/DR", desc: "Regular config backups, cross-region replication", icon: "💾" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={4} key={item.title}>
                      <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: themeColors.bgCard }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#fff" }}>
                          {item.icon} {item.title}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>{item.desc}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Paper>

            {/* SOC Metrics Section */}
            <Paper id="soc-metrics" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SpeedIcon /> SOC Metrics
              </Typography>

              <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(themeColors.primary, 0.1), border: `1px solid ${alpha(themeColors.primary, 0.3)}` }}>
                Measure what matters. These metrics help demonstrate SOC effectiveness and identify improvement areas.
              </Alert>

              <Grid container spacing={3} sx={{ mb: 3 }}>
                {socMetrics.map((metric) => (
                  <Grid item xs={12} sm={6} md={4} key={metric.name}>
                    <Card sx={{ height: "100%", bgcolor: themeColors.bgNested, borderTop: `3px solid ${themeColors.primary}` }}>
                      <CardContent>
                        <Typography variant="h5" sx={{ fontWeight: 800, color: themeColors.primary, mb: 0.5 }}>
                          {metric.name}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: "#fff" }}>
                          {metric.fullName}
                        </Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                          {metric.description}
                        </Typography>
                        <Chip label={`Target: ${metric.target}`} size="small" sx={{ bgcolor: alpha(themeColors.accent, 0.1), color: themeColors.accent }} />
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  📊 Dashboard KPIs
                </Typography>
                <Grid container spacing={2}>
                  {[
                    "Alerts by severity over time",
                    "Top triggered detection rules",
                    "Alerts by source/host",
                    "Mean time to acknowledge",
                    "Analyst workload distribution",
                    "False positive rate by rule",
                    "MITRE ATT&CK coverage heatmap",
                    "Log ingestion rate (EPS/GB)",
                  ].map((kpi) => (
                    <Grid item xs={12} sm={6} md={3} key={kpi}>
                      <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: themeColors.bgCard }}>
                        <Typography variant="body2" sx={{ fontWeight: 600, color: themeColors.textMuted }}>{kpi}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#fff" }}>
                  <WarningIcon sx={{ color: "#f59e0b" }} /> Common Pitfalls
                </Typography>
                <List dense>
                  {[
                    "Alert fatigue from too many low-quality alerts",
                    "Measuring volume (alerts handled) instead of outcomes (incidents prevented)",
                    "Insufficient log coverage leaving blind spots",
                    "Not tuning rules, leading to noise",
                    "Lack of documented playbooks for common alerts",
                    "Single points of failure in architecture",
                    "Not testing detection rules with attack simulations",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Labs Section */}
            <Paper id="labs" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ScienceIcon /> Labs
              </Typography>

              <Alert severity="warning" sx={{ mb: 3, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
                Practice in lab environments. Use tools like Splunk Free, Elastic Free, or cloud free tiers for hands-on learning.
              </Alert>

              <Grid container spacing={3} sx={{ mb: 3 }}>
                {labExercises.map((lab) => (
                  <Grid item xs={12} md={6} key={lab.name}>
                    <Card sx={{ 
                      height: "100%",
                      bgcolor: themeColors.bgNested,
                      borderLeft: `4px solid ${
                        lab.difficulty === "Beginner" ? themeColors.accent :
                        lab.difficulty === "Intermediate" ? "#f59e0b" : "#ef4444"
                      }` 
                    }}>
                      <CardContent>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                          <Typography variant="h6" sx={{ fontWeight: 700, color: "#fff" }}>{lab.name}</Typography>
                          <Box sx={{ display: "flex", gap: 1 }}>
                            <Chip
                              label={lab.difficulty}
                              size="small"
                              sx={{
                                bgcolor: lab.difficulty === "Beginner" ? alpha(themeColors.accent, 0.1) :
                                         lab.difficulty === "Intermediate" ? alpha("#f59e0b", 0.1) :
                                         alpha("#ef4444", 0.1),
                                color: lab.difficulty === "Beginner" ? themeColors.accent :
                                       lab.difficulty === "Intermediate" ? "#f59e0b" : "#ef4444",
                                fontWeight: 700,
                              }}
                            />
                            <Chip label={lab.duration} size="small" variant="outlined" sx={{ borderColor: themeColors.border, color: themeColors.textMuted }} />
                          </Box>
                        </Box>
                        <Divider sx={{ my: 1.5, borderColor: themeColors.border }} />
                        <List dense>
                          {lab.objectives.map((obj, i) => (
                            <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <Typography variant="caption" sx={{ fontWeight: 700, color: themeColors.primary }}>{i + 1}.</Typography>
                              </ListItemIcon>
                              <ListItemText primary={obj} primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#fff" }}>
                  🛠️ Free Lab Resources
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "Splunk Free", desc: "500MB/day ingestion, full features" },
                    { name: "Elastic Cloud Free", desc: "14-day trial, managed cluster" },
                    { name: "Microsoft Sentinel", desc: "Free tier with Azure subscription" },
                    { name: "Wazuh", desc: "Fully open source, Docker deployment" },
                    { name: "DVWA + Sysmon", desc: "Generate attack logs for detection practice" },
                    { name: "Atomic Red Team", desc: "MITRE ATT&CK technique simulations" },
                  ].map((resource) => (
                    <Grid item xs={12} sm={6} md={4} key={resource.name}>
                      <Paper sx={{ p: 2, borderRadius: 2, bgcolor: themeColors.bgCard }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#fff" }}>{resource.name}</Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>{resource.desc}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Paper>

            {/* Quiz Section */}
            <Paper
              id="quiz-section"
              sx={{
                p: 3,
                mb: 4,
                bgcolor: themeColors.bgCard,
                borderRadius: 2,
                border: `1px solid ${themeColors.border}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2, color: themeColors.primary }}>
                <QuizIcon /> Knowledge Check
              </Typography>
              <QuizSection
                questions={quizQuestions}
                accentColor={QUIZ_ACCENT_COLOR}
                title="SIEM Fundamentals Knowledge Check"
                description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
              />
            </Paper>
          </Grid>
        </Grid>

        {/* Mobile Navigation Drawer */}
        <Drawer
          anchor="left"
          open={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
          sx={{ display: { md: "none" } }}
          PaperProps={{ sx: { bgcolor: themeColors.bgCard, width: 280 } }}
        >
          <Box sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ color: themeColors.primary, fontWeight: 700, mb: 2 }}>
              CONTENTS
            </Typography>
            <List dense>
              {sectionNavItems.map((item) => (
                <ListItem
                  key={item.id}
                  component="button"
                  onClick={() => scrollToSection(item.id)}
                  sx={{
                    borderRadius: 1,
                    mb: 0.5,
                    cursor: "pointer",
                    border: "none",
                    width: "100%",
                    textAlign: "left",
                    bgcolor: activeSection === item.id ? `${themeColors.primary}20` : "transparent",
                    "&:hover": { bgcolor: `${themeColors.primary}15` },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? themeColors.primary : themeColors.textMuted }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    primaryTypographyProps={{
                      variant: "body2",
                      fontWeight: activeSection === item.id ? 600 : 400,
                      color: activeSection === item.id ? themeColors.primary : themeColors.textMuted,
                    }}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        </Drawer>

        {/* Mobile FABs */}
        {isMobile && (
          <>
            <Fab
              size="small"
              onClick={() => setMobileNavOpen(true)}
              sx={{
                position: "fixed",
                bottom: 80,
                right: 16,
                bgcolor: themeColors.bgCard,
                color: themeColors.primary,
                border: `1px solid ${themeColors.border}`,
                "&:hover": { bgcolor: themeColors.bgNested },
              }}
            >
              <MenuIcon />
            </Fab>
            <Fab
              size="small"
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              sx={{
                position: "fixed",
                bottom: 16,
                right: 16,
                bgcolor: themeColors.bgCard,
                color: themeColors.primary,
                border: `1px solid ${themeColors.border}`,
                "&:hover": { bgcolor: themeColors.bgNested },
              }}
            >
              <KeyboardArrowUpIcon />
            </Fab>
          </>
        )}
      </Container>
    </LearnPageLayout>
  );
}
