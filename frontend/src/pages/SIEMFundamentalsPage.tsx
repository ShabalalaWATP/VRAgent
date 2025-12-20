import React, { useState } from "react";
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
  alpha,
  useTheme,
  Tabs,
  Tab,
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
import { useNavigate } from "react-router-dom";

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

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

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

export default function SIEMFundamentalsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `SIEM Fundamentals Guide - Comprehensive Security Information and Event Management training. Covers core concepts (log collection, normalization, correlation, alerting, dashboards, retention), log source categories (endpoints with Windows Events/Sysmon/EDR, network with firewall/DNS/proxy, identity with AD/Azure AD/VPN, cloud with AWS CloudTrail/Azure/GCP, applications). Includes platform comparison (Splunk SPL, Elastic KQL, Microsoft Sentinel KQL, QRadar AQL, Wazuh, Chronicle YARA-L). Features detection rule examples mapped to MITRE ATT&CK (brute force T1110, PowerShell T1059.001, lateral movement T1021, DNS tunneling T1071.004, Kerberoasting T1558.003, credential dumping T1003). Covers SIEM architecture (collection, processing, storage tiers, analysis layer), SOC metrics (MTTD, MTTR, true positive rate, coverage), and hands-on labs from beginner to advanced.`;

  return (
    <LearnPageLayout pageTitle="SIEM Fundamentals" pageContext={pageContext}>
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
                bgcolor: alpha("#3b82f6", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <StorageIcon sx={{ fontSize: 36, color: "#3b82f6" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                SIEM Fundamentals
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Security Information and Event Management
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Blue Team" color="primary" size="small" />
            <Chip label="Detection" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
            <Chip label="Monitoring" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
            <Chip label="MITRE ATT&CK" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
          </Box>
        </Box>

        {/* Stats */}
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { label: "Log Sources", value: "20+", color: "#3b82f6" },
            { label: "Detection Rules", value: "8", color: "#ef4444" },
            { label: "Query Examples", value: "10+", color: "#f59e0b" },
            { label: "Lab Exercises", value: "6", color: "#22c55e" },
          ].map((stat) => (
            <Grid item xs={6} sm={3} key={stat.label}>
              <Paper sx={{ p: 2, textAlign: "center", borderTop: `3px solid ${stat.color}` }}>
                <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                <Typography variant="body2" color="text.secondary">{stat.label}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Tabs */}
        <Paper sx={{ borderRadius: 3, overflow: "hidden", mb: 4 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ borderBottom: 1, borderColor: "divider", bgcolor: alpha(theme.palette.background.paper, 0.5) }}
          >
            <Tab icon={<StorageIcon />} label="Overview" iconPosition="start" />
            <Tab icon={<DnsIcon />} label="Log Sources" iconPosition="start" />
            <Tab icon={<CodeIcon />} label="Query Examples" iconPosition="start" />
            <Tab icon={<SecurityIcon />} label="Detection Rules" iconPosition="start" />
            <Tab icon={<AccountTreeIcon />} label="Architecture" iconPosition="start" />
            <Tab icon={<SpeedIcon />} label="SOC Metrics" iconPosition="start" />
            <Tab icon={<ScienceIcon />} label="Labs" iconPosition="start" />
          </Tabs>

          {/* Tab 0: Overview */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              {/* Overview */}
              <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <StorageIcon color="primary" /> What is a SIEM?
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
                  A SIEM (Security Information and Event Management) system collects, normalizes, and analyzes log data 
                  from across your environment to detect threats, support investigations, and meet compliance requirements. 
                  It's the central nervous system of a Security Operations Center (SOC).
                </Typography>
                <Alert severity="info">
                  Modern SIEMs often include SOAR (Security Orchestration, Automation and Response) capabilities 
                  and UEBA (User and Entity Behavior Analytics) for advanced threat detection.
                </Alert>
              </Paper>

              {/* Core Concepts */}
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Core Concepts</Typography>
              <Grid container spacing={2} sx={{ mb: 4 }}>
                {coreConcepts.map((concept) => (
                  <Grid item xs={12} sm={6} md={4} key={concept.title}>
                    <Paper
                      sx={{
                        p: 2,
                        height: "100%",
                        borderRadius: 2,
                        border: `1px solid ${alpha(concept.color, 0.2)}`,
                        "&:hover": { borderColor: concept.color },
                      }}
                    >
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: concept.color, mb: 0.5 }}>
                        {concept.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {concept.description}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* Platforms */}
              <Paper
                sx={{
                  p: 3,
                  mb: 4,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.05)}, ${alpha("#6366f1", 0.05)})`,
                  border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <BuildIcon sx={{ color: "#3b82f6" }} /> Popular SIEM Platforms
                </Typography>
                <Grid container spacing={2}>
                  {platforms.map((p) => (
                    <Grid item xs={12} sm={6} md={4} key={p.name}>
                      <Paper sx={{ p: 2, borderRadius: 2 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{p.name}</Typography>
                          <Chip label={p.type} size="small" sx={{ height: 18, fontSize: "0.65rem" }} />
                        </Box>
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{p.note}</Typography>
                        <Chip label={p.queryLang} size="small" sx={{ mt: 1, bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Use Cases */}
              <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <NotificationsActiveIcon sx={{ color: "#10b981" }} /> Common Detection Use Cases
                </Typography>
                <Grid container spacing={1}>
                  {useCases.map((uc, i) => (
                    <Grid item xs={12} sm={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                        <Typography variant="body2">{uc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
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
                <Typography variant="body2">
                  <strong>Tip:</strong> Start with high-fidelity, low-volume alerts and tune from there. Alert fatigue kills SOCs.
                </Typography>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 1: Log Sources */}
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Comprehensive log coverage is essential for effective threat detection. Prioritize critical sources first, then expand coverage based on risk.
              </Alert>

              {logSources.map((category) => (
                <Paper key={category.category} sx={{ p: 3, mb: 3, borderRadius: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <span>{category.icon}</span> {category.category}
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Source</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Priority</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {category.sources.map((source) => (
                          <TableRow key={source.name}>
                            <TableCell sx={{ fontWeight: 600 }}>{source.name}</TableCell>
                            <TableCell>{source.description}</TableCell>
                            <TableCell>
                              <Chip
                                label={source.priority}
                                size="small"
                                sx={{
                                  bgcolor: source.priority === "Critical" ? alpha("#ef4444", 0.1) :
                                           source.priority === "High" ? alpha("#f59e0b", 0.1) :
                                           alpha("#3b82f6", 0.1),
                                  color: source.priority === "Critical" ? "#ef4444" :
                                         source.priority === "High" ? "#f59e0b" : "#3b82f6",
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

              <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
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
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 2: Query Examples */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Alert severity="warning" sx={{ mb: 3 }}>
                Query syntax varies by platform. These examples are templates - adjust field names for your environment.
              </Alert>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                Splunk (SPL)
              </Typography>
              <Accordion defaultExpanded sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Brute Force Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.bruteForce} language="spl" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Privilege Escalation Events</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.privilegeEsc} language="spl" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Suspicious Process Execution</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.suspiciousProcess} language="spl" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 3 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Lateral Movement Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.splunk.lateralMovement} language="spl" />
                </AccordionDetails>
              </Accordion>

              <Divider sx={{ my: 3 }} />

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                Microsoft Sentinel (KQL)
              </Typography>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Brute Force Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.bruteForce} language="kql" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Privilege Escalation Events</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.privilegeEsc} language="kql" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Suspicious Process Execution</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.suspiciousProcess} language="kql" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 3 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>DNS Exfiltration Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.sentinel.dnsExfil} language="kql" />
                </AccordionDetails>
              </Accordion>

              <Divider sx={{ my: 3 }} />

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                Elastic (Lucene/JSON DSL)
              </Typography>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Brute Force Detection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.elastic.bruteForce} language="json" />
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Malware Indicators</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={queryExamples.elastic.malwareIndicator} language="json" />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 3: Detection Rules */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Detection rules should be mapped to MITRE ATT&CK techniques for coverage analysis. 
                Always document false positive scenarios for tuning.
              </Alert>

              {detectionRules.map((rule, idx) => (
                <Accordion key={idx} sx={{ mb: 1, "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                      <Chip
                        label={rule.severity}
                        size="small"
                        sx={{
                          bgcolor: rule.severity === "Critical" ? alpha("#ef4444", 0.1) :
                                   rule.severity === "High" ? alpha("#f59e0b", 0.1) :
                                   alpha("#3b82f6", 0.1),
                          color: rule.severity === "Critical" ? "#ef4444" :
                                 rule.severity === "High" ? "#f59e0b" : "#3b82f6",
                          fontWeight: 700,
                        }}
                      />
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, flex: 1 }}>{rule.name}</Typography>
                      <Chip label={rule.mitre} size="small" variant="outlined" sx={{ mr: 2 }} />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {rule.description}
                        </Typography>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                            Detection Logic
                          </Typography>
                          <Typography variant="body2">{rule.logic}</Typography>
                        </Paper>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>
                            Threshold
                          </Typography>
                          <Typography variant="body2">{rule.threshold}</Typography>
                        </Paper>
                      </Grid>
                      <Grid item xs={12}>
                        <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                            False Positives
                          </Typography>
                          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                            {rule.falsePositives.map((fp) => (
                              <Chip key={fp} label={fp} size="small" variant="outlined" />
                            ))}
                          </Box>
                        </Paper>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              ))}

              <Paper sx={{ p: 3, mt: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
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
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 4: Architecture */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                A well-designed SIEM architecture balances performance, cost, and data retention requirements.
              </Alert>

              {architectureComponents.map((layer, idx) => (
                <Paper key={layer.layer} sx={{ p: 3, mb: 3, borderRadius: 3, borderLeft: `4px solid ${
                  idx === 0 ? "#3b82f6" : idx === 1 ? "#8b5cf6" : idx === 2 ? "#f59e0b" : "#22c55e"
                }` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                    {idx + 1}. {layer.layer}
                  </Typography>
                  <Grid container spacing={2}>
                    {layer.components.map((comp) => (
                      <Grid item xs={12} sm={6} key={comp.name}>
                        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                          <CheckCircleIcon sx={{ fontSize: 18, color: "#3b82f6", mt: 0.3 }} />
                          <Box>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{comp.name}</Typography>
                            <Typography variant="caption" color="text.secondary">{comp.description}</Typography>
                          </Box>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>
              ))}

              <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
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
                      <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                          {item.icon} {item.title}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 5: SOC Metrics */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Measure what matters. These metrics help demonstrate SOC effectiveness and identify improvement areas.
              </Alert>

              <Grid container spacing={3} sx={{ mb: 4 }}>
                {socMetrics.map((metric) => (
                  <Grid item xs={12} sm={6} md={4} key={metric.name}>
                    <Card sx={{ height: "100%", borderTop: `3px solid #3b82f6` }}>
                      <CardContent>
                        <Typography variant="h5" sx={{ fontWeight: 800, color: "#3b82f6", mb: 0.5 }}>
                          {metric.name}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                          {metric.fullName}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {metric.description}
                        </Typography>
                        <Chip label={`Target: ${metric.target}`} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ p: 3, borderRadius: 3, mb: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
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
                      <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{kpi}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
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
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 6: Labs */}
          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 3 }}>
              <Alert severity="warning" sx={{ mb: 3 }}>
                Practice in lab environments. Use tools like Splunk Free, Elastic Free, or cloud free tiers for hands-on learning.
              </Alert>

              <Grid container spacing={3}>
                {labExercises.map((lab) => (
                  <Grid item xs={12} md={6} key={lab.name}>
                    <Card sx={{ 
                      height: "100%",
                      borderLeft: `4px solid ${
                        lab.difficulty === "Beginner" ? "#22c55e" :
                        lab.difficulty === "Intermediate" ? "#f59e0b" : "#ef4444"
                      }` 
                    }}>
                      <CardContent>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                          <Typography variant="h6" sx={{ fontWeight: 700 }}>{lab.name}</Typography>
                          <Box sx={{ display: "flex", gap: 1 }}>
                            <Chip
                              label={lab.difficulty}
                              size="small"
                              sx={{
                                bgcolor: lab.difficulty === "Beginner" ? alpha("#22c55e", 0.1) :
                                         lab.difficulty === "Intermediate" ? alpha("#f59e0b", 0.1) :
                                         alpha("#ef4444", 0.1),
                                color: lab.difficulty === "Beginner" ? "#22c55e" :
                                       lab.difficulty === "Intermediate" ? "#f59e0b" : "#ef4444",
                                fontWeight: 700,
                              }}
                            />
                            <Chip label={lab.duration} size="small" variant="outlined" />
                          </Box>
                        </Box>
                        <Divider sx={{ my: 1.5 }} />
                        <List dense>
                          {lab.objectives.map((obj, i) => (
                            <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <Typography variant="caption" sx={{ fontWeight: 700, color: "#3b82f6" }}>{i + 1}.</Typography>
                              </ListItemIcon>
                              <ListItemText primary={obj} primaryTypographyProps={{ variant: "body2" }} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ p: 3, mt: 3, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
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
                      <Paper sx={{ p: 2, borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{resource.name}</Typography>
                        <Typography variant="caption" color="text.secondary">{resource.desc}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </TabPanel>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="SOC Analyst Workflow →" clickable onClick={() => navigate("/learn/soc-workflow")} sx={{ fontWeight: 600 }} />
            <Chip label="Threat Hunting →" clickable onClick={() => navigate("/learn/threat-hunting")} sx={{ fontWeight: 600 }} />
            <Chip label="Incident Response →" clickable onClick={() => navigate("/learn/incident-response")} sx={{ fontWeight: 600 }} />
            <Chip label="Log Analysis →" clickable onClick={() => navigate("/learn/log-analysis")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
