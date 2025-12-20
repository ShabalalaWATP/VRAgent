import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  IconButton,
  Chip,
  Grid,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  TextField,
  InputAdornment,
  Link,
  Divider,
  Alert,
  Card,
  CardContent,
} from "@mui/material";
import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";
import LearnPageLayout from "../components/LearnPageLayout";

interface Technique {
  id: string;
  name: string;
  description: string;
}

interface Tactic {
  id: string;
  name: string;
  shortName: string;
  description: string;
  color: string;
  icon: string;
  techniques: Technique[];
}

const tactics: Tactic[] = [
  {
    id: "TA0043",
    name: "Reconnaissance",
    shortName: "Recon",
    description: "Gathering information to plan future adversary operations, such as information about the target organization.",
    color: "#6366f1",
    icon: "🔍",
    techniques: [
      { id: "T1595", name: "Active Scanning", description: "Probing infrastructure via scanning to gather information before targeting." },
      { id: "T1592", name: "Gather Victim Host Information", description: "Gathering information about target hosts, such as administrative data, hardware, software, and configuration." },
      { id: "T1589", name: "Gather Victim Identity Information", description: "Gathering information about victim identities including employee names, email addresses, and credentials." },
      { id: "T1590", name: "Gather Victim Network Information", description: "Gathering information about the victim's networks, including domain, topology, and network addresses." },
      { id: "T1591", name: "Gather Victim Org Information", description: "Gathering information about the victim's organization, including names of business units, relationships, and locations." },
      { id: "T1598", name: "Phishing for Information", description: "Sending phishing messages to elicit sensitive information useful for targeting." },
      { id: "T1597", name: "Search Closed Sources", description: "Searching closed sources like dark web, threat intel vendors, or private datasets for info about victims." },
      { id: "T1596", name: "Search Open Technical Databases", description: "Searching freely available technical databases like DNS records, WHOIS, and digital certificates." },
      { id: "T1593", name: "Search Open Websites/Domains", description: "Searching freely available websites, social media, and other online content for victim information." },
      { id: "T1594", name: "Search Victim-Owned Websites", description: "Searching websites owned by the target for information to use during targeting." },
    ],
  },
  {
    id: "TA0042",
    name: "Resource Development",
    shortName: "Resources",
    description: "Establishing resources to support operations. This may include setting up infrastructure, accounts, or capabilities.",
    color: "#8b5cf6",
    icon: "🛠️",
    techniques: [
      { id: "T1583", name: "Acquire Infrastructure", description: "Buying, leasing, or renting infrastructure like domains, servers, and serverless resources." },
      { id: "T1586", name: "Compromise Accounts", description: "Compromising accounts with services that can be used during targeting." },
      { id: "T1584", name: "Compromise Infrastructure", description: "Compromising third-party infrastructure to use for targeting." },
      { id: "T1587", name: "Develop Capabilities", description: "Building capabilities that can be used during targeting." },
      { id: "T1585", name: "Establish Accounts", description: "Creating accounts with services that can be used during targeting." },
      { id: "T1588", name: "Obtain Capabilities", description: "Buying, stealing, or downloading capabilities for use during targeting." },
      { id: "T1608", name: "Stage Capabilities", description: "Uploading, installing, or otherwise setting up capabilities for use during targeting." },
    ],
  },
  {
    id: "TA0001",
    name: "Initial Access",
    shortName: "Access",
    description: "Techniques that use various entry vectors to gain their initial foothold within a network.",
    color: "#a855f7",
    icon: "🚪",
    techniques: [
      { id: "T1189", name: "Drive-by Compromise", description: "Gaining access through visiting a website during normal browsing." },
      { id: "T1190", name: "Exploit Public-Facing Application", description: "Taking advantage of weaknesses in Internet-facing programs." },
      { id: "T1133", name: "External Remote Services", description: "Leveraging remote services like VPNs, Citrix, or RDP for initial access." },
      { id: "T1200", name: "Hardware Additions", description: "Introducing malicious hardware, such as USB devices, into a system." },
      { id: "T1566", name: "Phishing", description: "Sending phishing messages to gain access to victim systems." },
      { id: "T1091", name: "Replication Through Removable Media", description: "Moving onto systems via media like USB drives." },
      { id: "T1195", name: "Supply Chain Compromise", description: "Manipulating products or product delivery mechanisms to compromise data or systems." },
      { id: "T1199", name: "Trusted Relationship", description: "Breaching an organization that has access to the intended victim." },
      { id: "T1078", name: "Valid Accounts", description: "Using existing accounts that may have been stolen or brute forced." },
    ],
  },
  {
    id: "TA0002",
    name: "Execution",
    shortName: "Execute",
    description: "Techniques that result in adversary-controlled code running on a local or remote system.",
    color: "#ec4899",
    icon: "⚡",
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", description: "Using command-line interfaces or script interpreters to execute commands." },
      { id: "T1203", name: "Exploitation for Client Execution", description: "Exploiting software vulnerabilities to execute code." },
      { id: "T1559", name: "Inter-Process Communication", description: "Abusing IPC mechanisms to execute code." },
      { id: "T1106", name: "Native API", description: "Interacting directly with the native OS API to execute behaviors." },
      { id: "T1053", name: "Scheduled Task/Job", description: "Abusing task scheduling functionality to execute malicious code." },
      { id: "T1129", name: "Shared Modules", description: "Executing malicious code by loading shared modules." },
      { id: "T1072", name: "Software Deployment Tools", description: "Gaining access to and using third-party software suites for execution." },
      { id: "T1569", name: "System Services", description: "Abusing system services to execute malicious payloads." },
      { id: "T1204", name: "User Execution", description: "Relying on user interaction to execute malicious code." },
      { id: "T1047", name: "Windows Management Instrumentation", description: "Abusing WMI to execute malicious commands." },
    ],
  },
  {
    id: "TA0003",
    name: "Persistence",
    shortName: "Persist",
    description: "Techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions.",
    color: "#f43f5e",
    icon: "📌",
    techniques: [
      { id: "T1098", name: "Account Manipulation", description: "Manipulating accounts to maintain access to credentials and permissions." },
      { id: "T1197", name: "BITS Jobs", description: "Abusing BITS jobs to persistently execute code." },
      { id: "T1547", name: "Boot or Logon Autostart Execution", description: "Using mechanisms that run at system boot or user logon." },
      { id: "T1037", name: "Boot or Logon Initialization Scripts", description: "Using scripts automatically executed at boot or logon." },
      { id: "T1176", name: "Browser Extensions", description: "Abusing browser extensions to establish persistent access." },
      { id: "T1136", name: "Create Account", description: "Creating accounts for persistent access." },
      { id: "T1574", name: "Hijack Execution Flow", description: "Executing own malicious payloads by hijacking the way operating systems run programs." },
      { id: "T1053", name: "Scheduled Task/Job", description: "Abusing task scheduling to schedule execution of malicious code at system startup." },
      { id: "T1505", name: "Server Software Component", description: "Abusing server software components to establish persistent access." },
      { id: "T1078", name: "Valid Accounts", description: "Using credentials for existing accounts for persistence." },
    ],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    shortName: "PrivEsc",
    description: "Techniques that adversaries use to gain higher-level permissions on a system or network.",
    color: "#ef4444",
    icon: "⬆️",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Control Mechanism", description: "Abusing elevation control mechanisms to gain higher privileges." },
      { id: "T1134", name: "Access Token Manipulation", description: "Manipulating access tokens to operate under a different user or system context." },
      { id: "T1547", name: "Boot or Logon Autostart Execution", description: "Gaining elevated privileges by changing autostart execution configurations." },
      { id: "T1068", name: "Exploitation for Privilege Escalation", description: "Exploiting software vulnerabilities to gain elevated privileges." },
      { id: "T1574", name: "Hijack Execution Flow", description: "Hijacking the way operating systems run programs to escalate privileges." },
      { id: "T1055", name: "Process Injection", description: "Injecting code into processes to evade defenses and elevate privileges." },
      { id: "T1053", name: "Scheduled Task/Job", description: "Executing scheduled tasks in the context of higher privileges." },
      { id: "T1078", name: "Valid Accounts", description: "Using legitimate administrator credentials that have been compromised." },
    ],
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    shortName: "Evasion",
    description: "Techniques that adversaries use to avoid detection throughout their compromise.",
    color: "#f59e0b",
    icon: "🥷",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Control Mechanism", description: "Bypassing elevation controls to gain higher privileges without triggering detection." },
      { id: "T1134", name: "Access Token Manipulation", description: "Manipulating access tokens to evade detection." },
      { id: "T1197", name: "BITS Jobs", description: "Using BITS to evade defenses while transferring files or executing tasks." },
      { id: "T1140", name: "Deobfuscate/Decode Files or Information", description: "Using obfuscation techniques to hide malicious content." },
      { id: "T1006", name: "Direct Volume Access", description: "Directly accessing a volume to bypass file access controls." },
      { id: "T1562", name: "Impair Defenses", description: "Disabling security tools or modifying configurations to avoid detection." },
      { id: "T1036", name: "Masquerading", description: "Manipulating features of artifacts to make them appear legitimate." },
      { id: "T1027", name: "Obfuscated Files or Information", description: "Encrypting, encoding, or otherwise obfuscating content to evade defenses." },
      { id: "T1055", name: "Process Injection", description: "Injecting code into processes to evade process-based defenses." },
      { id: "T1218", name: "System Binary Proxy Execution", description: "Bypassing defenses by proxying execution through trusted binaries." },
    ],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    shortName: "Creds",
    description: "Techniques for stealing credentials like account names and passwords.",
    color: "#eab308",
    icon: "🔑",
    techniques: [
      { id: "T1110", name: "Brute Force", description: "Using brute force techniques to crack passwords." },
      { id: "T1555", name: "Credentials from Password Stores", description: "Searching common locations where passwords are stored." },
      { id: "T1212", name: "Exploitation for Credential Access", description: "Exploiting software vulnerabilities to obtain credentials." },
      { id: "T1187", name: "Forced Authentication", description: "Forcing authentication protocols to capture credentials." },
      { id: "T1003", name: "OS Credential Dumping", description: "Dumping credentials from the operating system." },
      { id: "T1528", name: "Steal Application Access Token", description: "Stealing application access tokens to bypass authentication." },
      { id: "T1649", name: "Steal or Forge Authentication Certificates", description: "Stealing or forging certificates for authentication." },
      { id: "T1558", name: "Steal or Forge Kerberos Tickets", description: "Stealing or forging Kerberos tickets for authentication." },
      { id: "T1539", name: "Steal Web Session Cookie", description: "Stealing web session cookies to hijack authenticated sessions." },
      { id: "T1552", name: "Unsecured Credentials", description: "Searching for unsecured credentials in files or environment variables." },
    ],
  },
  {
    id: "TA0007",
    name: "Discovery",
    shortName: "Discover",
    description: "Techniques an adversary may use to gain knowledge about the system and internal network.",
    color: "#84cc16",
    icon: "🗺️",
    techniques: [
      { id: "T1087", name: "Account Discovery", description: "Getting a listing of accounts on a system or within an environment." },
      { id: "T1010", name: "Application Window Discovery", description: "Getting a listing of opened application windows." },
      { id: "T1217", name: "Browser Information Discovery", description: "Enumerating browser information like bookmarks, history, and saved passwords." },
      { id: "T1580", name: "Cloud Infrastructure Discovery", description: "Discovering cloud infrastructure resources." },
      { id: "T1538", name: "Cloud Service Dashboard", description: "Using cloud service dashboards to discover resources." },
      { id: "T1526", name: "Cloud Service Discovery", description: "Discovering cloud services available to the compromised account." },
      { id: "T1613", name: "Container and Resource Discovery", description: "Discovering containers and other resources." },
      { id: "T1482", name: "Domain Trust Discovery", description: "Enumerating domain trusts." },
      { id: "T1083", name: "File and Directory Discovery", description: "Enumerating files and directories." },
      { id: "T1046", name: "Network Service Discovery", description: "Getting a listing of services running on remote hosts." },
    ],
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    shortName: "Lateral",
    description: "Techniques that adversaries use to enter and control remote systems on a network.",
    color: "#22c55e",
    icon: "↔️",
    techniques: [
      { id: "T1210", name: "Exploitation of Remote Services", description: "Exploiting remote services to gain access to internal systems." },
      { id: "T1534", name: "Internal Spearphishing", description: "Spearphishing within an environment after gaining access." },
      { id: "T1570", name: "Lateral Tool Transfer", description: "Transferring tools between systems within a compromised environment." },
      { id: "T1563", name: "Remote Service Session Hijacking", description: "Hijacking legitimate user remote service sessions." },
      { id: "T1021", name: "Remote Services", description: "Using valid accounts to log into remote services." },
      { id: "T1091", name: "Replication Through Removable Media", description: "Moving laterally via removable media." },
      { id: "T1072", name: "Software Deployment Tools", description: "Using deployment tools to move laterally." },
      { id: "T1080", name: "Taint Shared Content", description: "Delivering payloads to other systems by adding content to shared storage locations." },
      { id: "T1550", name: "Use Alternate Authentication Material", description: "Using alternate authentication material like password hashes." },
    ],
  },
  {
    id: "TA0009",
    name: "Collection",
    shortName: "Collect",
    description: "Techniques adversaries may use to gather information relevant to their objectives.",
    color: "#14b8a6",
    icon: "📦",
    techniques: [
      { id: "T1557", name: "Adversary-in-the-Middle", description: "Positioning to intercept and relay communications between two parties." },
      { id: "T1560", name: "Archive Collected Data", description: "Compressing and/or encrypting data prior to exfiltration." },
      { id: "T1123", name: "Audio Capture", description: "Capturing audio recordings from victim systems." },
      { id: "T1119", name: "Automated Collection", description: "Using automated techniques to collect internal data." },
      { id: "T1185", name: "Browser Session Hijacking", description: "Taking advantage of valid browser sessions to collect data." },
      { id: "T1115", name: "Clipboard Data", description: "Collecting data stored in the clipboard." },
      { id: "T1530", name: "Data from Cloud Storage", description: "Accessing data from cloud storage objects." },
      { id: "T1213", name: "Data from Information Repositories", description: "Mining data from information repositories." },
      { id: "T1005", name: "Data from Local System", description: "Searching local system sources for data to exfiltrate." },
      { id: "T1039", name: "Data from Network Shared Drive", description: "Searching network shares for data to exfiltrate." },
    ],
  },
  {
    id: "TA0011",
    name: "Command and Control",
    shortName: "C2",
    description: "Techniques that adversaries may use to communicate with systems under their control within a victim network.",
    color: "#06b6d4",
    icon: "📡",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", description: "Communicating using application layer protocols to avoid detection." },
      { id: "T1132", name: "Data Encoding", description: "Encoding data to make C2 traffic more difficult to detect." },
      { id: "T1001", name: "Data Obfuscation", description: "Obfuscating C2 traffic to make detection more difficult." },
      { id: "T1568", name: "Dynamic Resolution", description: "Using dynamic resolution like domain generation algorithms for C2." },
      { id: "T1573", name: "Encrypted Channel", description: "Encrypting C2 communications." },
      { id: "T1008", name: "Fallback Channels", description: "Using fallback channels when primary C2 is unavailable." },
      { id: "T1105", name: "Ingress Tool Transfer", description: "Transferring tools or files from an external system." },
      { id: "T1104", name: "Multi-Stage Channels", description: "Using multiple stages to establish C2 channels." },
      { id: "T1095", name: "Non-Application Layer Protocol", description: "Using non-application layer protocols for C2." },
      { id: "T1571", name: "Non-Standard Port", description: "Using non-standard ports for C2 to bypass filtering." },
      { id: "T1572", name: "Protocol Tunneling", description: "Tunneling C2 traffic through legitimate protocols." },
      { id: "T1090", name: "Proxy", description: "Using proxy servers to direct C2 traffic." },
      { id: "T1219", name: "Remote Access Software", description: "Using legitimate remote access software for C2." },
      { id: "T1102", name: "Web Service", description: "Using legitimate web services for C2." },
    ],
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    shortName: "Exfil",
    description: "Techniques that adversaries may use to steal data from your network.",
    color: "#3b82f6",
    icon: "📤",
    techniques: [
      { id: "T1020", name: "Automated Exfiltration", description: "Using automated techniques to exfiltrate data." },
      { id: "T1030", name: "Data Transfer Size Limits", description: "Breaking data into chunks to avoid detection during exfiltration." },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", description: "Exfiltrating data using a protocol other than the existing C2 channel." },
      { id: "T1041", name: "Exfiltration Over C2 Channel", description: "Exfiltrating data over the existing C2 channel." },
      { id: "T1011", name: "Exfiltration Over Other Network Medium", description: "Exfiltrating data over different network mediums." },
      { id: "T1052", name: "Exfiltration Over Physical Medium", description: "Exfiltrating data via physical medium like USB drives." },
      { id: "T1567", name: "Exfiltration Over Web Service", description: "Exfiltrating data to external web services." },
      { id: "T1029", name: "Scheduled Transfer", description: "Scheduling data exfiltration to occur at certain times." },
      { id: "T1537", name: "Transfer Data to Cloud Account", description: "Exfiltrating data to cloud accounts they control." },
    ],
  },
  {
    id: "TA0040",
    name: "Impact",
    shortName: "Impact",
    description: "Techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes.",
    color: "#dc2626",
    icon: "💥",
    techniques: [
      { id: "T1531", name: "Account Access Removal", description: "Disrupting availability by denying access to accounts." },
      { id: "T1485", name: "Data Destruction", description: "Destroying data and files on targeted systems." },
      { id: "T1486", name: "Data Encrypted for Impact", description: "Encrypting data to render it inaccessible (ransomware)." },
      { id: "T1565", name: "Data Manipulation", description: "Manipulating data to impact integrity." },
      { id: "T1491", name: "Defacement", description: "Defacing internal or external surfaces for impact." },
      { id: "T1561", name: "Disk Wipe", description: "Wiping disk structures or content to interrupt availability." },
      { id: "T1499", name: "Endpoint Denial of Service", description: "Performing DoS targeting an endpoint." },
      { id: "T1495", name: "Firmware Corruption", description: "Corrupting firmware to render devices inoperable." },
      { id: "T1490", name: "Inhibit System Recovery", description: "Deleting or removing backups and recovery capabilities." },
      { id: "T1498", name: "Network Denial of Service", description: "Performing DoS targeting networks." },
      { id: "T1496", name: "Resource Hijacking", description: "Hijacking system resources for cryptocurrency mining or spam." },
      { id: "T1489", name: "Service Stop", description: "Stopping or disabling services to render them unavailable." },
      { id: "T1529", name: "System Shutdown/Reboot", description: "Shutting down or rebooting systems to interrupt access." },
    ],
  },
];

export default function MitreAttackPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedTab, setSelectedTab] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");

  const filteredTechniques = useMemo(() => {
    if (!searchQuery.trim()) return tactics[selectedTab].techniques;
    const query = searchQuery.toLowerCase();
    return tactics[selectedTab].techniques.filter(
      (t) => t.name.toLowerCase().includes(query) || t.id.toLowerCase().includes(query) || t.description.toLowerCase().includes(query)
    );
  }, [selectedTab, searchQuery]);

  const pageContext = `MITRE ATT&CK Framework Guide - Comprehensive coverage of adversary tactics, techniques, and procedures (TTPs). Covers all MITRE ATT&CK tactics: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, and Impact. Each tactic includes specific techniques with IDs, descriptions, and real-world examples used by threat actors. Essential knowledge for threat intelligence, red team operations, and security analysis.`;

  return (
    <LearnPageLayout pageTitle="MITRE ATT&CK Framework" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
        <ArrowBackIcon />
      </IconButton>

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #dc2626, #f59e0b)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🎯 MITRE ATT&CK Framework
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
        </Typography>
      </Box>

      {/* Overview */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#f59e0b", 0.05)})` }}>
        <Grid container spacing={4}>
          <Grid item xs={12} md={8}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
              What is MITRE ATT&CK?
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              <strong>MITRE ATT&CK®</strong> (Adversarial Tactics, Techniques, and Common Knowledge) is a curated knowledge base and model for cyber adversary behavior. It catalogs the lifecycle of cyber attacks from initial access through data exfiltration, providing a common taxonomy for threat intelligence, detection, and defense.
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              Unlike the linear Kill Chain, ATT&CK is a <strong>matrix</strong> organized by <strong>Tactics</strong> (the "why") and <strong>Techniques</strong> (the "how"). Each technique includes real-world examples, detection strategies, and mitigation guidance.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="14 Tactics" sx={{ bgcolor: alpha("#dc2626", 0.1), color: "#dc2626", fontWeight: 600 }} />
              <Chip label="200+ Techniques" variant="outlined" />
              <Chip label="Enterprise, Mobile, ICS" variant="outlined" />
              <Chip label="Threat Intelligence" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 3, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Use Cases</Typography>
              {[
                { icon: "🔍", label: "Threat Intelligence - Map adversary behaviors" },
                { icon: "🛡️", label: "Detection - Build detection rules per technique" },
                { icon: "📊", label: "Gap Analysis - Identify coverage gaps" },
                { icon: "🎮", label: "Red Team - Plan realistic attack simulations" },
                { icon: "📋", label: "Reporting - Common language for incidents" },
              ].map((use, i) => (
                <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1.5 }}>
                  <Typography variant="h6">{use.icon}</Typography>
                  <Typography variant="body2">{use.label}</Typography>
                </Box>
              ))}
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Tactics Overview Cards */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        📋 14 Tactics Overview
      </Typography>
      <Box sx={{ display: "flex", overflowX: "auto", gap: 1.5, mb: 4, pb: 2 }}>
        {tactics.map((tactic, index) => (
          <Card
            key={tactic.id}
            onClick={() => setSelectedTab(index)}
            sx={{
              minWidth: 110,
              flexShrink: 0,
              cursor: "pointer",
              border: `2px solid ${selectedTab === index ? tactic.color : "transparent"}`,
              bgcolor: selectedTab === index ? alpha(tactic.color, 0.1) : "background.paper",
              transition: "all 0.2s",
              "&:hover": { bgcolor: alpha(tactic.color, 0.05), transform: "translateY(-2px)" },
            }}
          >
            <CardContent sx={{ textAlign: "center", p: 2, "&:last-child": { pb: 2 } }}>
              <Typography variant="h5" sx={{ mb: 0.5 }}>{tactic.icon}</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: tactic.color, display: "block" }}>
                {tactic.shortName}
              </Typography>
              <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.65rem" }}>
                {tactic.techniques.length} techniques
              </Typography>
            </CardContent>
          </Card>
        ))}
      </Box>

      {/* Tactic Detail */}
      <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden" }}>
        <Box sx={{ p: 4, bgcolor: alpha(tactics[selectedTab].color, 0.05), borderBottom: `3px solid ${tactics[selectedTab].color}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Typography variant="h3">{tactics[selectedTab].icon}</Typography>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                {tactics[selectedTab].name}
              </Typography>
              <Chip label={tactics[selectedTab].id} size="small" sx={{ mt: 0.5, bgcolor: alpha(tactics[selectedTab].color, 0.1), color: tactics[selectedTab].color }} />
            </Box>
          </Box>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.7, mb: 2 }}>
            {tactics[selectedTab].description}
          </Typography>
          <Link
            href={`https://attack.mitre.org/tactics/${tactics[selectedTab].id}/`}
            target="_blank"
            rel="noopener"
            sx={{ display: "inline-flex", alignItems: "center", gap: 0.5, fontSize: "0.875rem" }}
          >
            View on MITRE ATT&CK <LaunchIcon fontSize="small" />
          </Link>
        </Box>

        {/* Search */}
        <Box sx={{ p: 3, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <TextField
            fullWidth
            size="small"
            placeholder="Search techniques..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
            }}
            sx={{ maxWidth: 400 }}
          />
        </Box>

        {/* Techniques */}
        <Box sx={{ p: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
            {filteredTechniques.length} Techniques
          </Typography>
          {filteredTechniques.length === 0 ? (
            <Alert severity="info">No techniques match your search.</Alert>
          ) : (
            <Grid container spacing={2}>
              {filteredTechniques.map((technique) => (
                <Grid item xs={12} md={6} key={technique.id}>
                  <Paper
                    sx={{
                      p: 2,
                      height: "100%",
                      border: `1px solid ${alpha(tactics[selectedTab].color, 0.15)}`,
                      transition: "all 0.2s",
                      "&:hover": { borderColor: tactics[selectedTab].color, bgcolor: alpha(tactics[selectedTab].color, 0.02) },
                    }}
                  >
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                        {technique.name}
                      </Typography>
                      <Link
                        href={`https://attack.mitre.org/techniques/${technique.id}/`}
                        target="_blank"
                        rel="noopener"
                        sx={{ display: "flex", alignItems: "center" }}
                      >
                        <Chip
                          label={technique.id}
                          size="small"
                          clickable
                          sx={{ fontSize: "0.7rem", bgcolor: alpha(tactics[selectedTab].color, 0.1), color: tactics[selectedTab].color }}
                        />
                      </Link>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                      {technique.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          )}
        </Box>
      </Paper>

      {/* Resources */}
      <Paper sx={{ p: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          🔗 Resources
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: "MITRE ATT&CK Navigator", url: "https://mitre-attack.github.io/attack-navigator/", desc: "Interactive tool for visualizing and annotating ATT&CK matrices." },
            { title: "ATT&CK Website", url: "https://attack.mitre.org/", desc: "Official MITRE ATT&CK knowledge base with all tactics, techniques, and groups." },
            { title: "D3FEND", url: "https://d3fend.mitre.org/", desc: "Knowledge graph of defensive countermeasures mapped to ATT&CK." },
            { title: "Atomic Red Team", url: "https://atomicredteam.io/", desc: "Library of simple tests mapped to ATT&CK techniques." },
          ].map((resource) => (
            <Grid item xs={12} md={6} key={resource.title}>
              <Link href={resource.url} target="_blank" rel="noopener" underline="none">
                <Box
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    bgcolor: alpha(theme.palette.primary.main, 0.05),
                    border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
                    transition: "all 0.2s",
                    "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "primary.main" }}>
                      {resource.title}
                    </Typography>
                    <LaunchIcon fontSize="small" color="primary" />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {resource.desc}
                  </Typography>
                </Box>
              </Link>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
